"""Tag Remediation Lambda — auto-tag KMS keys detected by Wiz.

Receives Wiz webhook payloads via API Gateway when an untagged KMS key is
detected. Looks up the account's dp:* tags from the Tag Lookup API and
applies them to the KMS key.

Flow:
  Wiz webhook → API Gateway (API key auth) → this Lambda
    1. Extract KMS key ARN + account ID from Wiz payload
    2. GET {TAG_LOOKUP_URL}/accounts/{account_id} → account dp:* tags
    3. Check if key already has the tags (idempotent)
    4. Apply missing tags via kms:TagResource
    5. SNS notification + CloudWatch metric
"""

import json
import logging
import os
import urllib.request
import urllib.error

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

TAG_LOOKUP_URL = os.environ.get("TAG_LOOKUP_URL", "")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
METRICS_NAMESPACE = "DataPerimeter/Remediation"

# The dp:* tags we expect on every KMS key
REQUIRED_TAGS = ["dp:data-zone", "dp:environment", "dp:project"]


def _get_clients():
    """Create AWS service clients (separated for testability)."""
    return {
        "kms": boto3.client("kms"),
        "sns": boto3.client("sns"),
        "cloudwatch": boto3.client("cloudwatch"),
    }


def parse_webhook(event):
    """Extract KMS key ARNs and account IDs from Wiz webhook payload.

    Wiz sends the webhook via API Gateway, so the payload is in the
    'body' field (JSON string). The Wiz payload contains entities from
    the graphSearch query results.

    Returns a list of dicts: [{"key_arn": "...", "account_id": "..."}]
    """
    body = event.get("body", "{}")
    if isinstance(body, str):
        body = json.loads(body)

    targets = []
    entities = body.get("entities", body.get("data", {}).get("entities", []))

    for entity in entities:
        arn = entity.get("arn", "")
        account_id = entity.get("accountId", "")

        if arn and account_id and ":key/" in arn:
            targets.append({"key_arn": arn, "account_id": account_id})

    return targets


def lookup_account_tags(account_id):
    """Call the Tag Lookup API to get dp:* tags for an account.

    Returns a dict of tag key → value, filtered to REQUIRED_TAGS only.
    e.g. {"dp:data-zone": "finance", "dp:environment": "prod", "dp:project": "reporting"}
    """
    url = f"{TAG_LOOKUP_URL}/accounts/{account_id}"
    logger.info("Looking up tags for account %s: %s", account_id, url)

    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", "application/json")

    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    all_tags = data.get("tags", {})

    # Filter to only the dp:* tags we care about
    dp_tags = {k: v for k, v in all_tags.items() if k in REQUIRED_TAGS}

    if not dp_tags:
        logger.warning("No dp:* tags found for account %s", account_id)

    return dp_tags


def get_existing_tags(clients, key_arn):
    """Get current tags on a KMS key, filtered to REQUIRED_TAGS."""
    resp = clients["kms"].list_resource_tags(KeyId=key_arn)
    tags = {t["TagKey"]: t["TagValue"] for t in resp.get("Tags", [])}
    return {k: v for k, v in tags.items() if k in REQUIRED_TAGS}


def remediate_key(clients, key_arn, account_id):
    """Look up account tags and apply missing ones to the KMS key.

    Returns a dict describing what happened:
      {"key_arn": ..., "action": "tagged"|"skipped"|"error", "tags_applied": {...}}
    """
    result = {"key_arn": key_arn, "account_id": account_id}

    try:
        # Get the tags this key should have (from account metadata)
        account_tags = lookup_account_tags(account_id)
        if not account_tags:
            result["action"] = "error"
            result["reason"] = "no dp:* tags found for account"
            return result

        # Check what the key already has
        existing = get_existing_tags(clients, key_arn)

        # Find what's missing
        missing = {k: v for k, v in account_tags.items() if k not in existing}

        if not missing:
            logger.info("Key %s already has all required tags — skipping", key_arn)
            result["action"] = "skipped"
            result["tags_applied"] = {}
            return result

        # Apply missing tags
        clients["kms"].tag_resource(
            KeyId=key_arn,
            Tags=[{"TagKey": k, "TagValue": v} for k, v in missing.items()],
        )
        logger.info("Tagged key %s with %s", key_arn, missing)

        result["action"] = "tagged"
        result["tags_applied"] = missing
        return result

    except Exception as e:
        logger.error("Failed to remediate key %s: %s", key_arn, e)
        result["action"] = "error"
        result["reason"] = str(e)
        return result


def publish_metrics(clients, results):
    """Publish remediation metrics to CloudWatch."""
    tagged = sum(1 for r in results if r["action"] == "tagged")
    skipped = sum(1 for r in results if r["action"] == "skipped")
    errors = sum(1 for r in results if r["action"] == "error")

    clients["cloudwatch"].put_metric_data(
        Namespace=METRICS_NAMESPACE,
        MetricData=[
            {"MetricName": "KeysRemediated", "Value": tagged, "Unit": "Count"},
            {"MetricName": "KeysSkipped", "Value": skipped, "Unit": "Count"},
            {"MetricName": "KeysErrored", "Value": errors, "Unit": "Count"},
        ],
    )


def send_notification(clients, results):
    """Send SNS notification for remediated keys."""
    if not SNS_TOPIC_ARN:
        return

    tagged = [r for r in results if r["action"] == "tagged"]
    errors = [r for r in results if r["action"] == "error"]

    if not tagged and not errors:
        return

    lines = ["KMS Tag Remediation Report", "=" * 30, ""]

    if tagged:
        lines.append(f"Keys tagged: {len(tagged)}")
        for r in tagged:
            lines.append(f"  - {r['key_arn']} (account {r['account_id']})")
            lines.append(f"    Tags applied: {r['tags_applied']}")
        lines.append("")

    if errors:
        lines.append(f"Errors: {len(errors)}")
        for r in errors:
            lines.append(f"  - {r['key_arn']}: {r.get('reason', 'unknown')}")

    subject = f"[Data Perimeter] {len(tagged)} keys tagged, {len(errors)} errors"

    clients["sns"].publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject[:100],
        Message="\n".join(lines),
    )


def handler(event, context):
    """Lambda entry point — receives Wiz webhook via API Gateway."""
    logger.info("Tag remediation invoked")

    clients = _get_clients()
    targets = parse_webhook(event)

    if not targets:
        logger.info("No KMS key targets found in webhook payload")
        return {"statusCode": 200, "body": json.dumps({"remediated": 0})}

    logger.info("Processing %d KMS key(s)", len(targets))
    results = []
    for target in targets:
        result = remediate_key(clients, target["key_arn"], target["account_id"])
        results.append(result)

    publish_metrics(clients, results)
    send_notification(clients, results)

    tagged_count = sum(1 for r in results if r["action"] == "tagged")
    return {
        "statusCode": 200,
        "body": json.dumps({
            "remediated": tagged_count,
            "total": len(results),
            "results": results,
        }),
    }
