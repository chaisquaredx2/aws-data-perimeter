"""ExceptionExpiryEnforcer Lambda — Layer 5.

Scheduled via EventBridge to discover dp:exception:* tags on KMS keys and IAM
principals, send approaching-expiry notifications, and remove expired tags.

Tag removal is the enforcement mechanism: policies use a Null condition on
dp:exception:id, so removing the tag immediately reactivates the deny.
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

GRACE_PERIOD_HOURS = int(os.environ.get("GRACE_PERIOD_HOURS", "0"))
NOTIFICATION_THRESHOLDS = json.loads(
    os.environ.get("NOTIFICATION_THRESHOLDS", "[30,14,7,1]")
)
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
AUDIT_TABLE = os.environ.get("AUDIT_TABLE", "")
ENFORCE_REMOVAL = os.environ.get("ENFORCE_REMOVAL", "true").lower() == "true"

# Exception tag keys that are actively checked by policies
ACTIVE_EXCEPTION_TAGS = [
    "dp:exception:id",
    "dp:exception:expiry",
    "dp:exception:justification",
    "dp:exception:approver",
]

# Audit breadcrumb tags left after revocation
BREADCRUMB_TAGS = {"dp:exception:revoked-at", "dp:exception:revoked-id"}


def _get_clients():
    """Create AWS service clients (separated for testability)."""
    return {
        "tagging": boto3.client("resourcegroupstaggingapi"),
        "iam": boto3.client("iam"),
        "kms": boto3.client("kms"),
        "sns": boto3.client("sns"),
        "dynamodb": boto3.resource("dynamodb"),
        "cloudwatch": boto3.client("cloudwatch"),
    }


def handler(event, context):
    """Scheduled entry point: discover, notify, enforce."""
    clients = _get_clients()
    now = datetime.now(timezone.utc)
    grace_cutoff = now - timedelta(hours=GRACE_PERIOD_HOURS)

    exceptions = discover_exceptions(clients)

    metrics = {"active": 0, "expiring_soon": 0, "expired": 0, "revoked": 0}

    for exc in exceptions:
        expiry_date = parse_expiry(exc["tags"].get("dp:exception:expiry"))
        if expiry_date is None:
            logger.warning(
                "Unparseable expiry on %s: %s",
                exc["arn"],
                exc["tags"].get("dp:exception:expiry"),
            )
            continue

        days_until_expiry = (expiry_date - now).days

        if days_until_expiry > max(NOTIFICATION_THRESHOLDS):
            metrics["active"] += 1
            continue

        if days_until_expiry > 0:
            metrics["expiring_soon"] += 1
            if days_until_expiry in NOTIFICATION_THRESHOLDS:
                send_expiry_warning(clients, exc, days_until_expiry)
            continue

        # Expired
        metrics["expired"] += 1

        if expiry_date <= grace_cutoff:
            if ENFORCE_REMOVAL:
                revoke_exception(clients, exc, now)
                metrics["revoked"] += 1
                logger.info("Revoked exception on %s", exc["arn"])
            else:
                logger.info("Dry-run: would revoke exception on %s", exc["arn"])

    publish_metrics(clients, metrics)

    logger.info("Run complete: %s", metrics)
    return {"statusCode": 200, "summary": metrics}


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def discover_exceptions(clients):
    """Find all KMS keys and IAM principals with dp:exception:expiry tags."""
    exceptions = []

    # KMS keys + other resources via Resource Groups Tagging API
    paginator = clients["tagging"].get_paginator("get_resources")
    for page in paginator.paginate(
        TagFilters=[{"Key": "dp:exception:expiry"}],
    ):
        for resource in page["ResourceTagMappingList"]:
            tags = {t["Key"]: t["Value"] for t in resource["Tags"]}
            exceptions.append(
                {"arn": resource["ResourceARN"], "type": "resource", "tags": tags}
            )

    # IAM roles
    roles_paginator = clients["iam"].get_paginator("list_roles")
    for page in roles_paginator.paginate():
        for role in page["Roles"]:
            role_tags = {t["Key"]: t["Value"] for t in role.get("Tags", [])}
            if "dp:exception:expiry" in role_tags:
                exceptions.append(
                    {"arn": role["Arn"], "type": "iam_role", "tags": role_tags}
                )

    # IAM users
    users_paginator = clients["iam"].get_paginator("list_users")
    for page in users_paginator.paginate():
        for user in page["Users"]:
            user_tags = {t["Key"]: t["Value"] for t in user.get("Tags", [])}
            if "dp:exception:expiry" in user_tags:
                exceptions.append(
                    {"arn": user["Arn"], "type": "iam_user", "tags": user_tags}
                )

    return exceptions


# ---------------------------------------------------------------------------
# Expiry parsing
# ---------------------------------------------------------------------------


def parse_expiry(value):
    """Parse ISO-8601 date or date-time string to aware datetime."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def revoke_exception(clients, exc, now):
    """Remove active exception tags and leave audit breadcrumbs."""
    exception_id = exc["tags"].get("dp:exception:id", "UNKNOWN")

    # Breadcrumb BEFORE removal
    apply_tags(
        clients,
        exc,
        {
            "dp:exception:revoked-at": now.isoformat(),
            "dp:exception:revoked-id": exception_id,
        },
    )

    # Remove active exception tags
    keys_to_remove = [
        k
        for k in exc["tags"]
        if k.startswith("dp:exception:") and k not in BREADCRUMB_TAGS
    ]
    remove_tags(clients, exc, keys_to_remove)

    # Audit record
    if AUDIT_TABLE:
        write_audit_record(clients, exc, exception_id, now, action="REVOKED")

    # Notification
    if SNS_TOPIC_ARN:
        send_revocation_notice(clients, exc, exception_id)


# ---------------------------------------------------------------------------
# Tag operations
# ---------------------------------------------------------------------------


def apply_tags(clients, exc, tags_dict):
    """Apply tags to a resource or IAM principal."""
    if exc["type"] == "iam_role":
        role_name = exc["arn"].split("/")[-1]
        clients["iam"].tag_role(
            RoleName=role_name,
            Tags=[{"Key": k, "Value": v} for k, v in tags_dict.items()],
        )
    elif exc["type"] == "iam_user":
        user_name = exc["arn"].split("/")[-1]
        clients["iam"].tag_user(
            UserName=user_name,
            Tags=[{"Key": k, "Value": v} for k, v in tags_dict.items()],
        )
    else:
        clients["tagging"].tag_resources(
            ResourceARNList=[exc["arn"]], Tags=tags_dict
        )


def remove_tags(clients, exc, tag_keys):
    """Remove tags from a resource or IAM principal."""
    if not tag_keys:
        return
    if exc["type"] == "iam_role":
        role_name = exc["arn"].split("/")[-1]
        clients["iam"].untag_role(RoleName=role_name, TagKeys=tag_keys)
    elif exc["type"] == "iam_user":
        user_name = exc["arn"].split("/")[-1]
        clients["iam"].untag_user(UserName=user_name, TagKeys=tag_keys)
    else:
        clients["tagging"].untag_resources(
            ResourceARNList=[exc["arn"]], TagKeys=tag_keys
        )


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


def send_expiry_warning(clients, exc, days):
    """Publish approaching-expiry alert to SNS."""
    if not SNS_TOPIC_ARN:
        return
    clients["sns"].publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"Data Perimeter Exception Expiring in {days} day(s)",
        Message=json.dumps(
            {
                "event": "EXCEPTION_EXPIRING",
                "exception_id": exc["tags"].get("dp:exception:id"),
                "resource_arn": exc["arn"],
                "days_until_expiry": days,
                "expiry_date": exc["tags"].get("dp:exception:expiry"),
                "approver": exc["tags"].get("dp:exception:approver", "unknown"),
                "justification": exc["tags"].get("dp:exception:justification", ""),
            },
            indent=2,
        ),
    )


def send_revocation_notice(clients, exc, exception_id):
    """Publish revocation alert to SNS."""
    clients["sns"].publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"Data Perimeter Exception {exception_id} REVOKED",
        Message=json.dumps(
            {
                "event": "EXCEPTION_REVOKED",
                "exception_id": exception_id,
                "resource_arn": exc["arn"],
                "action": "Exception tags removed. Deny policies now active.",
            },
            indent=2,
        ),
    )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def write_audit_record(clients, exc, exception_id, now, action):
    """Write audit trail to DynamoDB."""
    table = clients["dynamodb"].Table(AUDIT_TABLE)
    table.put_item(
        Item={
            "exception_id": exception_id,
            "timestamp": now.isoformat(),
            "action": action,
            "resource_arn": exc["arn"],
            "resource_type": exc["type"],
            "original_tags": exc["tags"],
        }
    )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def publish_metrics(clients, metrics):
    """Publish exception lifecycle metrics to CloudWatch."""
    clients["cloudwatch"].put_metric_data(
        Namespace="DataPerimeter/Exceptions",
        MetricData=[
            {"MetricName": k, "Value": v, "Unit": "Count"}
            for k, v in metrics.items()
        ],
    )
