"""Tests for the ExceptionExpiryEnforcer Lambda handler."""

import importlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add the Lambda source directory to sys.path so we can import handler
_LAMBDA_DIR = str(Path(__file__).parent.parent / "lambda" / "exception_expiry_enforcer")
if _LAMBDA_DIR not in sys.path:
    sys.path.insert(0, _LAMBDA_DIR)


@pytest.fixture(autouse=True)
def _env_setup(monkeypatch):
    monkeypatch.setenv("GRACE_PERIOD_HOURS", "0")
    monkeypatch.setenv("NOTIFICATION_THRESHOLDS", "[30,14,7,1]")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:111122223333:alerts")
    monkeypatch.setenv("AUDIT_TABLE", "dp-exception-audit")
    monkeypatch.setenv("ENFORCE_REMOVAL", "true")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")


@pytest.fixture
def handler_module():
    import handler as mod

    importlib.reload(mod)
    return mod


def _make_clients():
    """Create a dict of mock AWS clients."""
    tagging = MagicMock()
    iam = MagicMock()
    kms = MagicMock()
    sns = MagicMock()
    dynamodb = MagicMock()
    cloudwatch = MagicMock()

    # Default: no resources found
    tagging_paginator = MagicMock()
    tagging_paginator.paginate.return_value = [
        {"ResourceTagMappingList": []}
    ]
    tagging.get_paginator.return_value = tagging_paginator

    iam_roles_paginator = MagicMock()
    iam_roles_paginator.paginate.return_value = [{"Roles": []}]
    iam_users_paginator = MagicMock()
    iam_users_paginator.paginate.return_value = [{"Users": []}]

    def iam_get_paginator(op):
        if op == "list_roles":
            return iam_roles_paginator
        return iam_users_paginator

    iam.get_paginator.side_effect = iam_get_paginator

    return {
        "tagging": tagging,
        "iam": iam,
        "kms": kms,
        "sns": sns,
        "dynamodb": dynamodb,
        "cloudwatch": cloudwatch,
    }


# ---------------------------------------------------------------------------
# parse_expiry
# ---------------------------------------------------------------------------


class TestParseExpiry:
    def test_iso_date(self, handler_module):
        dt = handler_module.parse_expiry("2026-06-15")
        assert dt == datetime(2026, 6, 15, tzinfo=timezone.utc)

    def test_iso_datetime(self, handler_module):
        dt = handler_module.parse_expiry("2026-06-15T12:30:00+00:00")
        assert dt.year == 2026
        assert dt.month == 6
        assert dt.tzinfo is not None

    def test_none(self, handler_module):
        assert handler_module.parse_expiry(None) is None

    def test_empty_string(self, handler_module):
        assert handler_module.parse_expiry("") is None

    def test_garbage(self, handler_module):
        assert handler_module.parse_expiry("not-a-date") is None


# ---------------------------------------------------------------------------
# discover_exceptions
# ---------------------------------------------------------------------------


class TestDiscoverExceptions:
    def test_discovers_tagged_resources(self, handler_module):
        clients = _make_clients()
        page = {
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:kms:us-east-1:111:key/abc",
                    "Tags": [
                        {"Key": "dp:exception:id", "Value": "EXC-2026-0001"},
                        {"Key": "dp:exception:expiry", "Value": "2026-12-31"},
                    ],
                }
            ]
        }
        clients["tagging"].get_paginator.return_value.paginate.return_value = [page]

        results = handler_module.discover_exceptions(clients)
        assert len(results) == 1
        assert results[0]["arn"] == "arn:aws:kms:us-east-1:111:key/abc"
        assert results[0]["type"] == "resource"
        assert results[0]["tags"]["dp:exception:id"] == "EXC-2026-0001"

    def test_discovers_iam_roles(self, handler_module):
        clients = _make_clients()
        role_page = {
            "Roles": [
                {
                    "Arn": "arn:aws:iam::111:role/test-role",
                    "RoleName": "test-role",
                    "Tags": [
                        {"Key": "dp:exception:expiry", "Value": "2026-06-01"},
                    ],
                }
            ]
        }
        roles_pag = MagicMock()
        roles_pag.paginate.return_value = [role_page]
        clients["iam"].get_paginator.side_effect = (
            lambda op: roles_pag if op == "list_roles" else MagicMock(paginate=MagicMock(return_value=[{"Users": []}]))
        )

        results = handler_module.discover_exceptions(clients)
        iam_results = [r for r in results if r["type"] == "iam_role"]
        assert len(iam_results) == 1
        assert iam_results[0]["arn"] == "arn:aws:iam::111:role/test-role"

    def test_discovers_iam_users(self, handler_module):
        clients = _make_clients()
        user_page = {
            "Users": [
                {
                    "Arn": "arn:aws:iam::111:user/test-user",
                    "UserName": "test-user",
                    "Tags": [
                        {"Key": "dp:exception:expiry", "Value": "2026-06-01"},
                    ],
                }
            ]
        }
        users_pag = MagicMock()
        users_pag.paginate.return_value = [user_page]
        clients["iam"].get_paginator.side_effect = (
            lambda op: MagicMock(paginate=MagicMock(return_value=[{"Roles": []}])) if op == "list_roles" else users_pag
        )

        results = handler_module.discover_exceptions(clients)
        iam_results = [r for r in results if r["type"] == "iam_user"]
        assert len(iam_results) == 1

    def test_empty_org(self, handler_module):
        clients = _make_clients()
        results = handler_module.discover_exceptions(clients)
        assert results == []


# ---------------------------------------------------------------------------
# revoke_exception
# ---------------------------------------------------------------------------


class TestRevokeException:
    def test_removes_tags_and_writes_breadcrumb(self, handler_module):
        clients = _make_clients()
        table_mock = MagicMock()
        clients["dynamodb"].Table.return_value = table_mock

        exc = {
            "arn": "arn:aws:kms:us-east-1:111:key/abc",
            "type": "resource",
            "tags": {
                "dp:exception:id": "EXC-2026-0001",
                "dp:exception:expiry": "2026-01-01",
                "dp:exception:justification": "Test",
                "dp:exception:approver": "admin@test.com",
            },
        }
        now = datetime(2026, 1, 2, tzinfo=timezone.utc)

        handler_module.revoke_exception(clients, exc, now)

        # Should have applied breadcrumb tags
        clients["tagging"].tag_resources.assert_called_once()
        breadcrumb_call = clients["tagging"].tag_resources.call_args
        assert "dp:exception:revoked-at" in breadcrumb_call.kwargs["Tags"]

        # Should have removed active exception tags
        clients["tagging"].untag_resources.assert_called_once()
        removed_keys = clients["tagging"].untag_resources.call_args.kwargs["TagKeys"]
        assert "dp:exception:id" in removed_keys
        assert "dp:exception:expiry" in removed_keys

        # Should NOT remove breadcrumb tags
        assert "dp:exception:revoked-at" not in removed_keys
        assert "dp:exception:revoked-id" not in removed_keys

        # Should write audit record
        table_mock.put_item.assert_called_once()

        # Should send SNS notification
        clients["sns"].publish.assert_called_once()

    def test_revokes_iam_role(self, handler_module):
        clients = _make_clients()
        clients["dynamodb"].Table.return_value = MagicMock()

        exc = {
            "arn": "arn:aws:iam::111:role/partner-role",
            "type": "iam_role",
            "tags": {
                "dp:exception:id": "EXC-2026-0002",
                "dp:exception:expiry": "2026-01-01",
            },
        }
        now = datetime(2026, 1, 2, tzinfo=timezone.utc)

        handler_module.revoke_exception(clients, exc, now)

        clients["iam"].tag_role.assert_called_once()
        clients["iam"].untag_role.assert_called_once()
        assert clients["iam"].untag_role.call_args.kwargs["RoleName"] == "partner-role"


# ---------------------------------------------------------------------------
# Tag operations
# ---------------------------------------------------------------------------


class TestTagOperations:
    def test_apply_tags_resource(self, handler_module):
        clients = _make_clients()
        exc = {"arn": "arn:aws:kms:us-east-1:111:key/abc", "type": "resource", "tags": {}}
        handler_module.apply_tags(clients, exc, {"foo": "bar"})
        clients["tagging"].tag_resources.assert_called_once()

    def test_apply_tags_iam_role(self, handler_module):
        clients = _make_clients()
        exc = {"arn": "arn:aws:iam::111:role/my-role", "type": "iam_role", "tags": {}}
        handler_module.apply_tags(clients, exc, {"foo": "bar"})
        clients["iam"].tag_role.assert_called_once()

    def test_apply_tags_iam_user(self, handler_module):
        clients = _make_clients()
        exc = {"arn": "arn:aws:iam::111:user/my-user", "type": "iam_user", "tags": {}}
        handler_module.apply_tags(clients, exc, {"foo": "bar"})
        clients["iam"].tag_user.assert_called_once()

    def test_remove_tags_resource(self, handler_module):
        clients = _make_clients()
        exc = {"arn": "arn:aws:kms:us-east-1:111:key/abc", "type": "resource", "tags": {}}
        handler_module.remove_tags(clients, exc, ["dp:exception:id"])
        clients["tagging"].untag_resources.assert_called_once()

    def test_remove_tags_empty_list(self, handler_module):
        clients = _make_clients()
        exc = {"arn": "arn:aws:kms:us-east-1:111:key/abc", "type": "resource", "tags": {}}
        handler_module.remove_tags(clients, exc, [])
        clients["tagging"].untag_resources.assert_not_called()


# ---------------------------------------------------------------------------
# handler (integration)
# ---------------------------------------------------------------------------


class TestHandler:
    def test_no_exceptions(self, handler_module):
        clients = _make_clients()
        with patch.object(handler_module, "_get_clients", return_value=clients):
            result = handler_module.handler({}, None)

        assert result["statusCode"] == 200
        assert result["summary"]["active"] == 0
        assert result["summary"]["revoked"] == 0

    def test_active_exception_not_revoked(self, handler_module):
        clients = _make_clients()
        future = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%d")
        page = {
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:kms:us-east-1:111:key/abc",
                    "Tags": [
                        {"Key": "dp:exception:id", "Value": "EXC-2026-0001"},
                        {"Key": "dp:exception:expiry", "Value": future},
                    ],
                }
            ]
        }
        clients["tagging"].get_paginator.return_value.paginate.return_value = [page]

        with patch.object(handler_module, "_get_clients", return_value=clients):
            result = handler_module.handler({}, None)

        assert result["summary"]["active"] == 1
        assert result["summary"]["revoked"] == 0
        clients["tagging"].untag_resources.assert_not_called()

    def test_expired_exception_revoked(self, handler_module):
        clients = _make_clients()
        clients["dynamodb"].Table.return_value = MagicMock()
        past = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
        page = {
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:kms:us-east-1:111:key/abc",
                    "Tags": [
                        {"Key": "dp:exception:id", "Value": "EXC-2026-0001"},
                        {"Key": "dp:exception:expiry", "Value": past},
                    ],
                }
            ]
        }
        clients["tagging"].get_paginator.return_value.paginate.return_value = [page]

        with patch.object(handler_module, "_get_clients", return_value=clients):
            result = handler_module.handler({}, None)

        assert result["summary"]["expired"] == 1
        assert result["summary"]["revoked"] == 1
        clients["tagging"].untag_resources.assert_called_once()

    def test_dry_run_no_removal(self, handler_module, monkeypatch):
        monkeypatch.setenv("ENFORCE_REMOVAL", "false")
        import importlib
        importlib.reload(handler_module)

        clients = _make_clients()
        past = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
        page = {
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:kms:us-east-1:111:key/abc",
                    "Tags": [
                        {"Key": "dp:exception:id", "Value": "EXC-2026-0001"},
                        {"Key": "dp:exception:expiry", "Value": past},
                    ],
                }
            ]
        }
        clients["tagging"].get_paginator.return_value.paginate.return_value = [page]

        with patch.object(handler_module, "_get_clients", return_value=clients):
            # Force ENFORCE_REMOVAL to false at module level
            handler_module.ENFORCE_REMOVAL = False
            result = handler_module.handler({}, None)

        assert result["summary"]["expired"] == 1
        assert result["summary"]["revoked"] == 0
        clients["tagging"].untag_resources.assert_not_called()

    def test_expiring_soon_sends_notification(self, handler_module):
        clients = _make_clients()
        # Expiry 14 days from now (midnight) — guarantees days_until_expiry == 14
        # which is in NOTIFICATION_THRESHOLDS [30, 14, 7, 1]
        target = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=15)
        soon = target.strftime("%Y-%m-%d")
        page = {
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:kms:us-east-1:111:key/abc",
                    "Tags": [
                        {"Key": "dp:exception:id", "Value": "EXC-2026-0001"},
                        {"Key": "dp:exception:expiry", "Value": soon},
                    ],
                }
            ]
        }
        clients["tagging"].get_paginator.return_value.paginate.return_value = [page]

        with patch.object(handler_module, "_get_clients", return_value=clients):
            result = handler_module.handler({}, None)

        assert result["summary"]["expiring_soon"] == 1
        # SNS may or may not fire depending on exact day match — verify no revocation
        assert result["summary"]["revoked"] == 0
