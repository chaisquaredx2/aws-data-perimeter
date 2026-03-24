"""Tests for the KMS Tag Remediation Lambda handler."""

import importlib
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_LAMBDA_DIR = str(Path(__file__).parent.parent / "lambda" / "tag_remediation")


@pytest.fixture(autouse=True)
def _env_setup(monkeypatch):
    monkeypatch.setenv("TAG_LOOKUP_URL", "https://api.example.com")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:111122223333:alerts")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")


@pytest.fixture
def handler_module():
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
    """Create mock AWS clients."""
    kms = MagicMock()
    sns = MagicMock()
    cloudwatch = MagicMock()

    # Default: key has no tags
    kms.list_resource_tags.return_value = {"Tags": []}

    return {"kms": kms, "sns": sns, "cloudwatch": cloudwatch}


def _make_apigw_event(entities):
    """Create an API Gateway proxy event with Wiz webhook payload."""
    return {
        "httpMethod": "POST",
        "body": json.dumps({"entities": entities}),
        "headers": {"x-api-key": "test-key"},
    }


def _make_entity(arn="arn:aws:kms:us-east-1:111122223333:key/abc-123", account_id="111122223333"):
    return {"arn": arn, "accountId": account_id, "type": "AWS::KMS::Key", "name": "test-key"}


class TestParseWebhook:
    def test_extracts_kms_key(self, handler_module):
        event = _make_apigw_event([_make_entity()])
        targets = handler_module.parse_webhook(event)
        assert len(targets) == 1
        assert targets[0]["key_arn"] == "arn:aws:kms:us-east-1:111122223333:key/abc-123"
        assert targets[0]["account_id"] == "111122223333"

    def test_multiple_keys(self, handler_module):
        entities = [
            _make_entity("arn:aws:kms:us-east-1:111122223333:key/key-1", "111122223333"),
            _make_entity("arn:aws:kms:us-east-1:111122223333:key/key-2", "111122223333"),
        ]
        event = _make_apigw_event(entities)
        targets = handler_module.parse_webhook(event)
        assert len(targets) == 2

    def test_ignores_non_kms_resources(self, handler_module):
        entities = [
            {"arn": "arn:aws:s3:::my-bucket", "accountId": "111122223333"},
            _make_entity(),
        ]
        event = _make_apigw_event(entities)
        targets = handler_module.parse_webhook(event)
        assert len(targets) == 1
        assert ":key/" in targets[0]["key_arn"]

    def test_empty_payload(self, handler_module):
        event = _make_apigw_event([])
        targets = handler_module.parse_webhook(event)
        assert targets == []

    def test_nested_data_format(self, handler_module):
        """Wiz may nest entities under data.entities."""
        event = {
            "body": json.dumps({"data": {"entities": [_make_entity()]}}),
        }
        targets = handler_module.parse_webhook(event)
        assert len(targets) == 1


class TestLookupAccountTags:
    def test_returns_dp_tags(self, handler_module):
        mock_response = json.dumps({
            "accountId": "111122223333",
            "tags": {
                "dp:data-zone": "finance",
                "dp:environment": "prod",
                "dp:project": "reporting",
                "Name": "Finance Prod",
                "CostCenter": "12345",
            },
        }).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_response
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            tags = handler_module.lookup_account_tags("111122223333")

        assert tags == {
            "dp:data-zone": "finance",
            "dp:environment": "prod",
            "dp:project": "reporting",
        }

    def test_filters_non_dp_tags(self, handler_module):
        mock_response = json.dumps({
            "accountId": "111122223333",
            "tags": {"Name": "Test", "CostCenter": "999"},
        }).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_response
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            tags = handler_module.lookup_account_tags("111122223333")

        assert tags == {}


class TestRemediateKey:
    def test_applies_missing_tags(self, handler_module):
        clients = _make_clients()

        account_tags = {
            "dp:data-zone": "finance",
            "dp:environment": "prod",
            "dp:project": "reporting",
        }

        with patch.object(handler_module, "lookup_account_tags", return_value=account_tags):
            result = handler_module.remediate_key(
                clients, "arn:aws:kms:us-east-1:111:key/abc", "111"
            )

        assert result["action"] == "tagged"
        assert result["tags_applied"] == account_tags
        clients["kms"].tag_resource.assert_called_once()

    def test_skips_already_tagged(self, handler_module):
        clients = _make_clients()
        clients["kms"].list_resource_tags.return_value = {
            "Tags": [
                {"TagKey": "dp:data-zone", "TagValue": "finance"},
                {"TagKey": "dp:environment", "TagValue": "prod"},
                {"TagKey": "dp:project", "TagValue": "reporting"},
            ]
        }

        account_tags = {
            "dp:data-zone": "finance",
            "dp:environment": "prod",
            "dp:project": "reporting",
        }

        with patch.object(handler_module, "lookup_account_tags", return_value=account_tags):
            result = handler_module.remediate_key(
                clients, "arn:aws:kms:us-east-1:111:key/abc", "111"
            )

        assert result["action"] == "skipped"
        clients["kms"].tag_resource.assert_not_called()

    def test_applies_only_missing_tags(self, handler_module):
        clients = _make_clients()
        clients["kms"].list_resource_tags.return_value = {
            "Tags": [
                {"TagKey": "dp:data-zone", "TagValue": "finance"},
            ]
        }

        account_tags = {
            "dp:data-zone": "finance",
            "dp:environment": "prod",
            "dp:project": "reporting",
        }

        with patch.object(handler_module, "lookup_account_tags", return_value=account_tags):
            result = handler_module.remediate_key(
                clients, "arn:aws:kms:us-east-1:111:key/abc", "111"
            )

        assert result["action"] == "tagged"
        assert "dp:data-zone" not in result["tags_applied"]
        assert result["tags_applied"]["dp:environment"] == "prod"
        assert result["tags_applied"]["dp:project"] == "reporting"

    def test_error_when_no_account_tags(self, handler_module):
        clients = _make_clients()

        with patch.object(handler_module, "lookup_account_tags", return_value={}):
            result = handler_module.remediate_key(
                clients, "arn:aws:kms:us-east-1:111:key/abc", "111"
            )

        assert result["action"] == "error"
        assert "no dp:* tags" in result["reason"]
        clients["kms"].tag_resource.assert_not_called()


class TestPublishMetrics:
    def test_publishes_counts(self, handler_module):
        clients = _make_clients()
        results = [
            {"action": "tagged", "key_arn": "a", "tags_applied": {}},
            {"action": "skipped", "key_arn": "b"},
            {"action": "error", "key_arn": "c", "reason": "fail"},
        ]

        handler_module.publish_metrics(clients, results)

        call = clients["cloudwatch"].put_metric_data.call_args
        assert call.kwargs["Namespace"] == "DataPerimeter/Remediation"
        metrics = {m["MetricName"]: m["Value"] for m in call.kwargs["MetricData"]}
        assert metrics["KeysRemediated"] == 1
        assert metrics["KeysSkipped"] == 1
        assert metrics["KeysErrored"] == 1


class TestSendNotification:
    def test_sends_on_tagged(self, handler_module):
        clients = _make_clients()
        results = [
            {"action": "tagged", "key_arn": "arn:aws:kms:us-east-1:111:key/abc",
             "account_id": "111", "tags_applied": {"dp:data-zone": "finance"}},
        ]

        handler_module.send_notification(clients, results)

        clients["sns"].publish.assert_called_once()
        call = clients["sns"].publish.call_args
        assert "1 keys tagged" in call.kwargs["Subject"]
        assert "finance" in call.kwargs["Message"]

    def test_no_notification_when_all_skipped(self, handler_module):
        clients = _make_clients()
        results = [{"action": "skipped", "key_arn": "a"}]

        handler_module.send_notification(clients, results)

        clients["sns"].publish.assert_not_called()


class TestHandler:
    def test_no_targets(self, handler_module):
        clients = _make_clients()
        event = _make_apigw_event([])

        with patch.object(handler_module, "_get_clients", return_value=clients):
            result = handler_module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["remediated"] == 0

    def test_full_remediation_flow(self, handler_module):
        clients = _make_clients()
        event = _make_apigw_event([_make_entity()])

        account_tags = {
            "dp:data-zone": "finance",
            "dp:environment": "prod",
            "dp:project": "reporting",
        }

        with patch.object(handler_module, "_get_clients", return_value=clients), \
             patch.object(handler_module, "lookup_account_tags", return_value=account_tags):
            result = handler_module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["remediated"] == 1
        clients["kms"].tag_resource.assert_called_once()
        clients["cloudwatch"].put_metric_data.assert_called_once()
        clients["sns"].publish.assert_called_once()
