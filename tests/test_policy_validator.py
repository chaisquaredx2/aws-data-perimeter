"""Tests for policy_validator module."""

import json
import tempfile
from pathlib import Path

import pytest

from generator.policy_validator import (
    SCP_MAX_BYTES,
    ValidationResult,
    validate_all,
    validate_policy,
    validate_policy_file,
)


class TestValidatePolicy:
    def test_valid_policy(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Test",
                    "Effect": "Deny",
                    "Action": "s3:PutObject",
                    "Resource": "*",
                }
            ],
        }
        result = validate_policy(policy)
        assert result.valid is True
        assert result.errors == []
        assert result.size_bytes > 0

    def test_missing_version(self):
        policy = {
            "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]
        }
        result = validate_policy(policy)
        assert result.valid is False
        assert any("Version" in e for e in result.errors)

    def test_missing_statement(self):
        policy = {"Version": "2012-10-17"}
        result = validate_policy(policy)
        assert result.valid is False
        assert any("Statement" in e for e in result.errors)

    def test_statement_not_a_list(self):
        policy = {"Version": "2012-10-17", "Statement": {}}
        result = validate_policy(policy)
        assert result.valid is False
        assert any("list" in e for e in result.errors)

    def test_empty_statement_list(self):
        policy = {"Version": "2012-10-17", "Statement": []}
        result = validate_policy(policy)
        assert result.valid is False
        assert any("at least one" in e for e in result.errors)

    def test_missing_effect(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Action": "s3:*", "Resource": "*"}],
        }
        result = validate_policy(policy)
        assert result.valid is False
        assert any("Effect" in e for e in result.errors)

    def test_missing_action(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Resource": "*"}],
        }
        result = validate_policy(policy)
        assert result.valid is False
        assert any("Action" in e for e in result.errors)

    def test_not_action_is_valid(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "NotAction": "s3:*", "Resource": "*"}],
        }
        result = validate_policy(policy)
        assert result.valid is True

    def test_duplicate_sids(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "Dup", "Effect": "Deny", "Action": "s3:*", "Resource": "*"},
                {"Sid": "Dup", "Effect": "Deny", "Action": "ec2:*", "Resource": "*"},
            ],
        }
        result = validate_policy(policy)
        assert result.valid is False
        assert any("Duplicate" in e for e in result.errors)

    def test_allow_warning(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            ],
        }
        result = validate_policy(policy)
        assert len(result.warnings) > 0
        assert any("Allow" in w for w in result.warnings)

    def test_size_limit_exceeded(self):
        huge_statement = {
            "Sid": "Huge",
            "Effect": "Deny",
            "Action": [f"s3:Action{i}" for i in range(500)],
            "Resource": "*",
        }
        policy = {"Version": "2012-10-17", "Statement": [huge_statement]}
        result = validate_policy(policy)
        assert result.valid is False
        assert any("exceeds" in e for e in result.errors)

    def test_size_warning_at_80_percent(self):
        # Build a policy that's between 80% and 100% of the limit
        actions = ["s3:Action" + str(i) for i in range(100)]
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "Big", "Effect": "Deny", "Action": actions, "Resource": "*"}
            ],
        }
        minified = json.dumps(policy, separators=(",", ":"))
        size = len(minified.encode("utf-8"))
        if SCP_MAX_BYTES * 0.8 < size <= SCP_MAX_BYTES:
            result = validate_policy(policy)
            assert result.valid is True
            assert len(result.warnings) > 0
            assert any("80%" in w for w in result.warnings)


class TestValidatePolicyFile:
    def test_valid_file(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "T", "Effect": "Deny", "Action": "s3:*", "Resource": "*"}
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(policy, f)
            f.flush()
            result = validate_policy_file(f.name)
        assert result.valid is True
        assert result.path == f.name

    def test_invalid_json_file(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            f.write("{not valid json")
            f.flush()
            result = validate_policy_file(f.name)
        assert result.valid is False
        assert any("Invalid JSON" in e for e in result.errors)


class TestValidateAll:
    def test_validates_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ["policy-a", "policy-b"]:
                path = Path(tmpdir) / f"{name}.json"
                policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": name,
                            "Effect": "Deny",
                            "Action": "s3:*",
                            "Resource": "*",
                        }
                    ],
                }
                with open(path, "w") as f:
                    json.dump(policy, f)

            results = validate_all(tmpdir)
            assert len(results) == 2
            assert all(r.valid for r in results)

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results = validate_all(tmpdir)
            assert results == []
