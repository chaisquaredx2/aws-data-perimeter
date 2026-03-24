"""Tests for the ComplianceReporter Lambda handler."""

import importlib
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add the Lambda source directory to sys.path so we can import handler.
# We must insert at position 0 so this takes priority over the exception
# enforcer's handler module which may already be on sys.path.
_LAMBDA_DIR = str(Path(__file__).parent.parent / "lambda" / "compliance_reporter")


@pytest.fixture(autouse=True)
def _env_setup(monkeypatch):
    monkeypatch.setenv("ANALYZER_ARN", "arn:aws:access-analyzer:us-east-1:111122223333:analyzer/test")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:111122223333:alerts")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")


@pytest.fixture
def handler_module():
    # Temporarily put compliance_reporter's directory first on sys.path
    # and force-reload to pick up the correct handler module.
    sys.path.insert(0, _LAMBDA_DIR)
    try:
        if "handler" in sys.modules:
            del sys.modules["handler"]
        import handler as mod

        importlib.reload(mod)
        return mod
    finally:
        sys.path.remove(_LAMBDA_DIR)


def _make_clients():
    """Create a dict of mock AWS clients."""
    aa = MagicMock()
    cloudwatch = MagicMock()
    sns = MagicMock()

    # Default: no findings
    paginator = MagicMock()
    paginator.paginate.return_value = [{"findings": []}]
    aa.get_paginator.return_value = paginator

    return {
        "accessanalyzer": aa,
        "cloudwatch": cloudwatch,
        "sns": sns,
    }


def _make_finding(resource_type="AWS::S3::Bucket", has_exception_tag=False):
    """Create a mock Access Analyzer finding."""
    finding = {
        "id": "finding-123",
        "resourceType": resource_type,
        "resource": {
            "arn": f"arn:aws:s3:::test-bucket",
            "tags": {},
        },
        "status": "ACTIVE",
    }
    if has_exception_tag:
        finding["resource"]["tags"]["dp:exception:id"] = "EXC-2026-0001"
    return finding


class TestListActiveFindings:
    def test_no_findings(self, handler_module):
        clients = _make_clients()
        findings = handler_module.list_active_findings(clients)
        assert findings == []

    def test_single_page(self, handler_module):
        clients = _make_clients()
        finding = _make_finding()
        paginator = clients["accessanalyzer"].get_paginator.return_value
        paginator.paginate.return_value = [{"findings": [finding]}]

        findings = handler_module.list_active_findings(clients)
        assert len(findings) == 1
        assert findings[0]["resourceType"] == "AWS::S3::Bucket"

    def test_multiple_pages(self, handler_module):
        clients = _make_clients()
        f1 = _make_finding("AWS::S3::Bucket")
        f2 = _make_finding("AWS::KMS::Key")
        f3 = _make_finding("AWS::SQS::Queue")
        paginator = clients["accessanalyzer"].get_paginator.return_value
        paginator.paginate.return_value = [
            {"findings": [f1, f2]},
            {"findings": [f3]},
        ]

        findings = handler_module.list_active_findings(clients)
        assert len(findings) == 3


class TestCategorizeFindings:
    def test_empty(self, handler_module):
        report = handler_module.categorize_findings([])
        assert report["total"] == 0
        assert report["unresolved"] == 0
        assert report["exception_covered"] == 0

    def test_all_unresolved(self, handler_module):
        findings = [_make_finding("AWS::S3::Bucket"), _make_finding("AWS::KMS::Key")]
        report = handler_module.categorize_findings(findings)
        assert report["total"] == 2
        assert report["unresolved"] == 2
        assert report["exception_covered"] == 0
        assert report["unresolved_by_type"] == {
            "AWS::S3::Bucket": 1,
            "AWS::KMS::Key": 1,
        }

    def test_exception_covered(self, handler_module):
        findings = [
            _make_finding("AWS::S3::Bucket", has_exception_tag=False),
            _make_finding("AWS::S3::Bucket", has_exception_tag=True),
        ]
        report = handler_module.categorize_findings(findings)
        assert report["total"] == 2
        assert report["unresolved"] == 1
        assert report["exception_covered"] == 1

    def test_all_exception_covered(self, handler_module):
        findings = [
            _make_finding("AWS::S3::Bucket", has_exception_tag=True),
            _make_finding("AWS::KMS::Key", has_exception_tag=True),
        ]
        report = handler_module.categorize_findings(findings)
        assert report["unresolved"] == 0
        assert report["exception_covered"] == 2
        assert report["unresolved_by_type"] == {}


class TestPublishMetrics:
    def test_publishes_correct_namespace(self, handler_module):
        clients = _make_clients()
        report = {
            "total": 5,
            "unresolved": 3,
            "exception_covered": 2,
            "unresolved_by_type": {"AWS::S3::Bucket": 2, "AWS::KMS::Key": 1},
        }

        handler_module.publish_metrics(clients, report)

        call = clients["cloudwatch"].put_metric_data.call_args
        assert call.kwargs["Namespace"] == "DataPerimeter/Compliance"

        metric_names = {m["MetricName"] for m in call.kwargs["MetricData"]}
        assert "ExternalAccessFindings" in metric_names
        assert "UnresolvedFindings" in metric_names
        assert "ExceptionCoveredFindings" in metric_names

    def test_includes_per_type_dimensions(self, handler_module):
        clients = _make_clients()
        report = {
            "total": 2,
            "unresolved": 2,
            "exception_covered": 0,
            "unresolved_by_type": {"AWS::S3::Bucket": 1, "AWS::KMS::Key": 1},
        }

        handler_module.publish_metrics(clients, report)

        call = clients["cloudwatch"].put_metric_data.call_args
        dimensioned = [
            m for m in call.kwargs["MetricData"] if "Dimensions" in m
        ]
        assert len(dimensioned) == 2
        dimension_values = {d["Dimensions"][0]["Value"] for d in dimensioned}
        assert dimension_values == {"AWS::S3::Bucket", "AWS::KMS::Key"}


class TestSendAlert:
    def test_sends_alert_on_unresolved(self, handler_module):
        clients = _make_clients()
        report = {
            "total": 3,
            "unresolved": 2,
            "exception_covered": 1,
            "unresolved_by_type": {"AWS::S3::Bucket": 2},
        }

        handler_module.send_alert(clients, report)

        clients["sns"].publish.assert_called_once()
        call = clients["sns"].publish.call_args
        assert "2 unresolved" in call.kwargs["Subject"]
        assert "AWS::S3::Bucket" in call.kwargs["Message"]

    def test_no_alert_when_all_resolved(self, handler_module):
        clients = _make_clients()
        report = {
            "total": 1,
            "unresolved": 0,
            "exception_covered": 1,
            "unresolved_by_type": {},
        }

        handler_module.send_alert(clients, report)

        clients["sns"].publish.assert_not_called()

    def test_no_alert_without_topic(self, handler_module, monkeypatch):
        monkeypatch.setenv("SNS_TOPIC_ARN", "")
        importlib.reload(handler_module)

        clients = _make_clients()
        report = {
            "total": 5,
            "unresolved": 5,
            "exception_covered": 0,
            "unresolved_by_type": {"AWS::S3::Bucket": 5},
        }

        handler_module.send_alert(clients, report)

        clients["sns"].publish.assert_not_called()


class TestHandler:
    def test_no_findings(self, handler_module):
        clients = _make_clients()

        with patch.object(handler_module, "_get_clients", return_value=clients):
            result = handler_module.handler({}, None)

        assert result["total"] == 0
        assert result["unresolved"] == 0
        clients["cloudwatch"].put_metric_data.assert_called_once()
        clients["sns"].publish.assert_not_called()

    def test_with_unresolved_findings(self, handler_module):
        clients = _make_clients()
        findings = [_make_finding("AWS::S3::Bucket"), _make_finding("AWS::KMS::Key")]
        paginator = clients["accessanalyzer"].get_paginator.return_value
        paginator.paginate.return_value = [{"findings": findings}]

        with patch.object(handler_module, "_get_clients", return_value=clients):
            result = handler_module.handler({}, None)

        assert result["total"] == 2
        assert result["unresolved"] == 2
        clients["cloudwatch"].put_metric_data.assert_called_once()
        clients["sns"].publish.assert_called_once()

    def test_mixed_findings(self, handler_module):
        clients = _make_clients()
        findings = [
            _make_finding("AWS::S3::Bucket", has_exception_tag=False),
            _make_finding("AWS::S3::Bucket", has_exception_tag=True),
            _make_finding("AWS::KMS::Key", has_exception_tag=True),
        ]
        paginator = clients["accessanalyzer"].get_paginator.return_value
        paginator.paginate.return_value = [{"findings": findings}]

        with patch.object(handler_module, "_get_clients", return_value=clients):
            result = handler_module.handler({}, None)

        assert result["total"] == 3
        assert result["unresolved"] == 1
        assert result["exception_covered"] == 2
