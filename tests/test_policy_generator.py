"""Tests for policy_generator module."""

import json
import tempfile
from pathlib import Path

import pytest

from generator.intent_parser import parse_intent
from generator.policy_generator import (
    ALL_POLICIES,
    POLICY_GENERATORS,
    generate_policies,
    write_policies,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_intent.yaml"


@pytest.fixture
def config():
    return parse_intent(FIXTURE_PATH)


@pytest.fixture
def policies(config):
    return generate_policies(config)


class TestGeneratePolicies:
    def test_returns_all_policies(self, policies):
        assert len(policies) == 6
        assert "scp-cmk-enforcement" in policies
        assert "scp-kms-abac" in policies
        assert "scp-org-boundary" in policies
        assert "rcp-identity-perimeter" in policies
        assert "scp-network-perimeter" in policies
        assert "scp-tag-governance" in policies

    def test_layer_filtering(self, config):
        subset = generate_policies(config, layers=["layer_1_cmk_enforcement", "layer_2_kms_abac"])
        assert len(subset) == 2
        assert "scp-cmk-enforcement" in subset
        assert "scp-kms-abac" in subset

    def test_all_policies_have_version(self, policies):
        for name, doc in policies.items():
            assert doc["Version"] == "2012-10-17", f"{name} missing Version"

    def test_all_policies_have_statements(self, policies):
        for name, doc in policies.items():
            assert isinstance(doc["Statement"], list), f"{name} Statement not a list"
            assert len(doc["Statement"]) > 0, f"{name} has no statements"

    def test_all_statements_are_deny(self, policies):
        for name, doc in policies.items():
            for stmt in doc["Statement"]:
                assert stmt["Effect"] == "Deny", (
                    f"{name}: {stmt.get('Sid')} has Effect={stmt['Effect']}"
                )

    def test_no_duplicate_sids(self, policies):
        for name, doc in policies.items():
            sids = [s["Sid"] for s in doc["Statement"] if "Sid" in s]
            assert len(sids) == len(set(sids)), f"{name} has duplicate Sids"

    def test_all_policies_under_size_limit(self, policies):
        for name, doc in policies.items():
            size = len(json.dumps(doc, separators=(",", ":")).encode("utf-8"))
            assert size <= 5120, f"{name} is {size} bytes (limit 5120)"


class TestCMKEnforcement:
    def test_statement_count(self, policies):
        stmts = policies["scp-cmk-enforcement"]["Statement"]
        assert len(stmts) == 8

    def test_covers_s3(self, policies):
        sids = [s["Sid"] for s in policies["scp-cmk-enforcement"]["Statement"]]
        assert "DenyS3WithoutCMK" in sids
        assert "DenyS3BucketWithoutDefaultCMK" in sids

    def test_covers_all_services(self, policies):
        sids = {s["Sid"] for s in policies["scp-cmk-enforcement"]["Statement"]}
        expected = {
            "DenyS3WithoutCMK",
            "DenyS3BucketWithoutDefaultCMK",
            "DenyDynamoDBWithoutCMK",
            "DenySQSWithoutCMK",
            "DenySNSWithoutCMK",
            "DenyEBSWithoutEncryption",
            "DenyRDSWithoutEncryption",
            "DenyKMSKeyWithoutClassificationTags",
        }
        assert sids == expected


class TestKMSABAC:
    def test_single_statement(self, policies):
        stmts = policies["scp-kms-abac"]["Statement"]
        assert len(stmts) == 1
        assert stmts[0]["Sid"] == "EnforceKMSABACTagMatch"

    def test_uses_policy_variables(self, policies):
        condition = policies["scp-kms-abac"]["Statement"][0]["Condition"]
        snei = condition["StringNotEqualsIfExists"]
        assert snei["aws:ResourceTag/dp:data-zone"] == "${aws:PrincipalTag/dp:data-zone}"
        assert snei["aws:ResourceTag/dp:environment"] == "${aws:PrincipalTag/dp:environment}"
        assert snei["aws:ResourceTag/dp:project"] == "${aws:PrincipalTag/dp:project}"

    def test_exception_bypass(self, policies):
        condition = policies["scp-kms-abac"]["Statement"][0]["Condition"]
        assert condition["Null"]["aws:PrincipalTag/dp:exception:id"] == "true"

    def test_kms_actions(self, policies):
        actions = policies["scp-kms-abac"]["Statement"][0]["Action"]
        assert "kms:Decrypt" in actions
        assert "kms:GenerateDataKey" in actions
        assert "kms:CreateGrant" in actions


class TestTagGovernance:
    def test_statement_count(self, policies):
        stmts = policies["scp-tag-governance"]["Statement"]
        assert len(stmts) == 4

    def test_protects_dp_tags(self, policies):
        stmt = policies["scp-tag-governance"]["Statement"][0]
        assert stmt["Sid"] == "ProtectDataPerimeterTags"
        tag_keys = stmt["Condition"]["ForAnyValue:StringLike"]["aws:TagKeys"]
        assert "dp:data-zone" in tag_keys
        assert "dp:exception:*" in tag_keys

    def test_requires_classification_tags_on_kms(self, policies):
        sids = [s["Sid"] for s in policies["scp-tag-governance"]["Statement"]]
        assert "RequireKMSKeyDataZoneTag" in sids
        assert "RequireKMSKeyEnvironmentTag" in sids
        assert "RequireKMSKeyProjectTag" in sids

    def test_allowed_mutator_from_config(self, config):
        policies = generate_policies(config)
        stmt = policies["scp-tag-governance"]["Statement"][0]
        mutator_values = stmt["Condition"]["StringNotEquals"]["aws:PrincipalTag/team"]
        assert "security-admin" in mutator_values


class TestOrgBoundary:
    def test_single_statement(self, policies):
        stmts = policies["scp-org-boundary"]["Statement"]
        assert len(stmts) == 1
        assert stmts[0]["Sid"] == "EnforceResourcePerimeterOrgBoundary"

    def test_checks_org_id(self, policies):
        condition = policies["scp-org-boundary"]["Statement"][0]["Condition"]
        assert condition["StringNotEquals"]["aws:ResourceOrgID"] == "o-testorg123"

    def test_covers_key_services(self, policies):
        actions = policies["scp-org-boundary"]["Statement"][0]["Action"]
        assert "s3:*" in actions
        assert "kms:*" in actions
        assert "sqs:*" in actions

    def test_excludes_aws_managed_resources(self, policies):
        condition = policies["scp-org-boundary"]["Statement"][0]["Condition"]
        arn_patterns = condition["ArnNotLikeIfExists"]["aws:ResourceArn"]
        assert "arn:aws:s3:::aws-*" in arn_patterns

    def test_excludes_service_linked_roles(self, policies):
        condition = policies["scp-org-boundary"]["Statement"][0]["Condition"]
        assert "arn:aws:iam::*:role/aws-service-role/*" in (
            condition["ArnNotLikeIfExists"]["aws:PrincipalArn"]
        )

    def test_exception_bypass(self, policies):
        condition = policies["scp-org-boundary"]["Statement"][0]["Condition"]
        assert condition["Null"]["aws:PrincipalTag/dp:exception:id"] == "true"


class TestIdentityPerimeter:
    def test_single_statement(self, policies):
        stmts = policies["rcp-identity-perimeter"]["Statement"]
        assert len(stmts) == 1
        assert stmts[0]["Sid"] == "EnforceIdentityPerimeterOrgBoundary"

    def test_is_rcp_format(self, policies):
        stmt = policies["rcp-identity-perimeter"]["Statement"][0]
        assert stmt["Principal"] == "*"
        assert stmt["Action"] == "*"

    def test_checks_org_id(self, policies):
        condition = policies["rcp-identity-perimeter"]["Statement"][0]["Condition"]
        assert condition["StringNotEqualsIfExists"]["aws:PrincipalOrgID"] == "o-testorg123"

    def test_includes_third_party_accounts(self, policies):
        condition = policies["rcp-identity-perimeter"]["Statement"][0]["Condition"]
        accounts = condition["StringNotEqualsIfExists"]["aws:PrincipalAccount"]
        assert "999888777666" in accounts

    def test_excludes_aws_services(self, policies):
        condition = policies["rcp-identity-perimeter"]["Statement"][0]["Condition"]
        assert condition["BoolIfExists"]["aws:PrincipalIsAWSService"] == "false"

    def test_exception_bypass(self, policies):
        condition = policies["rcp-identity-perimeter"]["Statement"][0]["Condition"]
        assert condition["Null"]["aws:ResourceTag/dp:exception:id"] == "true"

    def test_no_third_party_without_exceptions(self, config):
        config.identity_perimeter.exceptions = []
        policies = generate_policies(config, layers=["layer_3b_identity_perimeter"])
        condition = policies["rcp-identity-perimeter"]["Statement"][0]["Condition"]
        assert "aws:PrincipalAccount" not in condition["StringNotEqualsIfExists"]


class TestNetworkPerimeter:
    def test_single_statement(self, policies):
        stmts = policies["scp-network-perimeter"]["Statement"]
        assert len(stmts) == 1
        assert stmts[0]["Sid"] == "EnforceNetworkPerimeterExpectedNetworks"

    def test_checks_vpcs(self, policies):
        condition = policies["scp-network-perimeter"]["Statement"][0]["Condition"]
        vpcs = condition["StringNotEqualsIfExists"]["aws:SourceVpc"]
        assert "vpc-test111" in vpcs

    def test_checks_cidrs(self, policies):
        condition = policies["scp-network-perimeter"]["Statement"][0]["Condition"]
        cidrs = condition["NotIpAddressIfExists"]["aws:SourceIp"]
        assert "10.0.0.0/8" in cidrs

    def test_excludes_aws_service_calls(self, policies):
        condition = policies["scp-network-perimeter"]["Statement"][0]["Condition"]
        assert condition["BoolIfExists"]["aws:ViaAWSService"] == "false"

    def test_exception_bypass(self, policies):
        condition = policies["scp-network-perimeter"]["Statement"][0]["Condition"]
        assert condition["Null"]["aws:PrincipalTag/dp:exception:id"] == "true"

    def test_excludes_service_linked_roles(self, policies):
        condition = policies["scp-network-perimeter"]["Statement"][0]["Condition"]
        assert "arn:aws:iam::*:role/aws-service-role/*" in (
            condition["ArnNotLikeIfExists"]["aws:PrincipalArn"]
        )


class TestWritePolicies:
    def test_writes_json_files(self, policies):
        with tempfile.TemporaryDirectory() as tmpdir:
            written = write_policies(policies, tmpdir)
            assert len(written) == 6
            for path in written:
                assert path.exists()
                assert path.suffix == ".json"
                with open(path) as f:
                    doc = json.load(f)
                assert "Version" in doc
                assert "Statement" in doc

    def test_creates_output_directory(self, policies):
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = Path(tmpdir) / "nested" / "output"
            written = write_policies(policies, outdir)
            assert outdir.exists()
            assert len(written) == 6
