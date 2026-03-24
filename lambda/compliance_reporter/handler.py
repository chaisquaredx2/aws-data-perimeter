"""ComplianceReporter Lambda — Observability Layer.

Scheduled via EventBridge to query IAM Access Analyzer findings, categorize
them (unresolved vs exception-covered), and publish compliance metrics to
CloudWatch. Optionally sends SNS alerts when unresolved findings exist.
"""

import json
import logging
import os

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

ANALYZER_ARN = os.environ.get("ANALYZER_ARN", "")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
METRICS_NAMESPACE = "DataPerimeter/Compliance"


def _get_clients():
    """Create AWS service clients (separated for testability)."""
    return {
        "accessanalyzer": boto3.client("accessanalyzer"),
        "cloudwatch": boto3.client("cloudwatch"),
        "sns": boto3.client("sns"),
    }


def list_active_findings(clients):
    """Retrieve all ACTIVE Access Analyzer findings with pagination."""
    aa = clients["accessanalyzer"]
    findings = []

    paginator = aa.get_paginator("list_findings_v2")
    pages = paginator.paginate(
        analyzerArn=ANALYZER_ARN,
        filter={"status": {"eq": ["ACTIVE"]}},
    )

    for page in pages:
        findings.extend(page.get("findings", []))

    logger.info("Found %d active findings", len(findings))
    return findings


def categorize_findings(findings):
    """Split findings into unresolved and exception-covered.

    A finding is exception-covered if the resource has a dp:exception:id tag
    (these should normally be auto-archived by the analyzer archive rule, but
    we check here as a safety net).
    """
    unresolved = []
    exception_covered = []

    for finding in findings:
        # Access Analyzer v2 findings include resource tags in the finding
        resource_tags = {}
        if "resource" in finding:
            resource_tags = finding["resource"].get("tags", {})

        if "dp:exception:id" in resource_tags:
            exception_covered.append(finding)
        else:
            unresolved.append(finding)

    # Count by resource type
    by_type = {}
    for finding in unresolved:
        rtype = finding.get("resourceType", "Unknown")
        by_type[rtype] = by_type.get(rtype, 0) + 1

    return {
        "total": len(findings),
        "unresolved": len(unresolved),
        "exception_covered": len(exception_covered),
        "unresolved_by_type": by_type,
        "unresolved_findings": unresolved,
    }


def publish_metrics(clients, report):
    """Publish compliance metrics to CloudWatch."""
    cw = clients["cloudwatch"]

    metric_data = [
        {
            "MetricName": "ExternalAccessFindings",
            "Value": report["total"],
            "Unit": "Count",
        },
        {
            "MetricName": "UnresolvedFindings",
            "Value": report["unresolved"],
            "Unit": "Count",
        },
        {
            "MetricName": "ExceptionCoveredFindings",
            "Value": report["exception_covered"],
            "Unit": "Count",
        },
    ]

    # Per-resource-type breakdown
    for rtype, count in report["unresolved_by_type"].items():
        metric_data.append({
            "MetricName": "UnresolvedFindings",
            "Dimensions": [{"Name": "ResourceType", "Value": rtype}],
            "Value": count,
            "Unit": "Count",
        })

    cw.put_metric_data(Namespace=METRICS_NAMESPACE, MetricData=metric_data)
    logger.info(
        "Published metrics: total=%d unresolved=%d exception_covered=%d",
        report["total"],
        report["unresolved"],
        report["exception_covered"],
    )


def send_alert(clients, report):
    """Send SNS alert if there are unresolved findings."""
    if not SNS_TOPIC_ARN or report["unresolved"] == 0:
        return

    type_breakdown = "\n".join(
        f"  - {rtype}: {count}"
        for rtype, count in report["unresolved_by_type"].items()
    )

    message = (
        f"Data Perimeter Compliance Alert\n"
        f"================================\n\n"
        f"Unresolved external access findings: {report['unresolved']}\n"
        f"Exception-covered findings: {report['exception_covered']}\n"
        f"Total active findings: {report['total']}\n\n"
        f"Breakdown by resource type:\n{type_breakdown}\n\n"
        f"Review findings in IAM Access Analyzer console."
    )

    clients["sns"].publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[Data Perimeter] {report['unresolved']} unresolved findings",
        Message=message,
    )
    logger.info("Sent SNS alert for %d unresolved findings", report["unresolved"])


def handler(event, context):
    """Lambda entry point."""
    logger.info("ComplianceReporter invoked: %s", json.dumps(event))

    clients = _get_clients()

    findings = list_active_findings(clients)
    report = categorize_findings(findings)
    publish_metrics(clients, report)
    send_alert(clients, report)

    return {
        "total": report["total"],
        "unresolved": report["unresolved"],
        "exception_covered": report["exception_covered"],
    }
