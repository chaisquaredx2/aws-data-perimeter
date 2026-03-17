"""Tests for policy_splitter module."""

import json

import pytest

from generator.policy_splitter import (
    SCP_MAX_BYTES,
    needs_splitting,
    split_all,
    split_policy,
)


def _make_policy(num_statements: int, action_pad: int = 1) -> dict:
    """Create a policy with N statements, each with action_pad actions."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": f"Stmt{i}",
                "Effect": "Deny",
                "Action": [f"s3:Action{j}" for j in range(action_pad)],
                "Resource": "*",
            }
            for i in range(num_statements)
        ],
    }


class TestNeedsSplitting:
    def test_small_policy(self):
        policy = _make_policy(1)
        assert needs_splitting(policy) is False

    def test_oversized_policy(self):
        policy = _make_policy(50, action_pad=10)
        size = len(json.dumps(policy, separators=(",", ":")).encode("utf-8"))
        assert size > SCP_MAX_BYTES
        assert needs_splitting(policy) is True


class TestSplitPolicy:
    def test_no_split_needed(self):
        policy = _make_policy(2)
        result = split_policy(policy, "test-policy")
        assert len(result) == 1
        assert result[0][0] == "test-policy"
        assert result[0][1] is policy

    def test_splits_oversized_policy(self):
        policy = _make_policy(50, action_pad=10)
        assert needs_splitting(policy)

        result = split_policy(policy, "big-policy")
        assert len(result) > 1

        # Each part fits within the limit
        for name, doc in result:
            size = len(json.dumps(doc, separators=(",", ":")).encode("utf-8"))
            assert size <= SCP_MAX_BYTES, f"{name} is {size} bytes"

        # Part names are correct
        for i, (name, _) in enumerate(result, 1):
            assert name == f"big-policy-part{i}"

        # All parts have valid structure
        for _, doc in result:
            assert doc["Version"] == "2012-10-17"
            assert len(doc["Statement"]) > 0

        # Total statements match original
        total = sum(len(doc["Statement"]) for _, doc in result)
        assert total == 50

    def test_preserves_statement_order(self):
        policy = _make_policy(50, action_pad=10)
        result = split_policy(policy, "ordered")

        all_sids = []
        for _, doc in result:
            all_sids.extend(s["Sid"] for s in doc["Statement"])

        expected = [f"Stmt{i}" for i in range(50)]
        assert all_sids == expected

    def test_single_oversized_statement_raises(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Huge",
                    "Effect": "Deny",
                    "Action": [f"s3:Action{i}" for i in range(500)],
                    "Resource": "*",
                }
            ],
        }
        with pytest.raises(ValueError, match="exceeds"):
            split_policy(policy, "impossible")


class TestSplitAll:
    def test_passes_through_small_policies(self):
        policies = {
            "small-a": _make_policy(1),
            "small-b": _make_policy(2),
        }
        result = split_all(policies)
        assert set(result.keys()) == {"small-a", "small-b"}

    def test_splits_only_oversized(self):
        policies = {
            "small": _make_policy(1),
            "big": _make_policy(50, action_pad=10),
        }
        result = split_all(policies)

        assert "small" in result
        big_keys = [k for k in result if k.startswith("big")]
        assert len(big_keys) > 1

    def test_all_results_under_limit(self):
        policies = {
            "a": _make_policy(1),
            "b": _make_policy(50, action_pad=10),
            "c": _make_policy(30, action_pad=8),
        }
        result = split_all(policies)

        for name, doc in result.items():
            size = len(json.dumps(doc, separators=(",", ":")).encode("utf-8"))
            assert size <= SCP_MAX_BYTES, f"{name} is {size} bytes"
