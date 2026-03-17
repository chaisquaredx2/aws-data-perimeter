"""Generate JSON policy documents from intent configuration."""

import json
from pathlib import Path

from generator.intent_parser import IntentConfig
from generator.templates import (
    cmk_enforcement,
    identity_perimeter,
    kms_abac,
    network_perimeter,
    org_boundary,
    tag_governance,
)

# Map policy names (from intent YAML ou_mapping.policies) to generator functions.
# Tuple format: (output_filename, generator_fn, policy_type)
# policy_type is "scp" or "rcp" — controls which Terraform module picks it up.
POLICY_GENERATORS = {
    "layer_1_cmk_enforcement": (
        "scp-cmk-enforcement",
        cmk_enforcement.generate,
    ),
    "layer_2_kms_abac": (
        "scp-kms-abac",
        kms_abac.generate,
    ),
    "layer_3a_org_boundary": (
        "scp-org-boundary",
        org_boundary.generate,
    ),
    "layer_3b_identity_perimeter": (
        "rcp-identity-perimeter",
        identity_perimeter.generate,
    ),
    "layer_4_network_perimeter": (
        "scp-network-perimeter",
        network_perimeter.generate,
    ),
    "layer_6_tag_governance": (
        "scp-tag-governance",
        tag_governance.generate,
    ),
}

# All policy layers to generate
ALL_POLICIES = [
    "layer_1_cmk_enforcement",
    "layer_2_kms_abac",
    "layer_3a_org_boundary",
    "layer_3b_identity_perimeter",
    "layer_4_network_perimeter",
    "layer_6_tag_governance",
]


def generate_policies(config: IntentConfig, layers: list[str] | None = None) -> dict[str, dict]:
    """Generate policy documents from intent config.

    Args:
        config: Parsed intent configuration.
        layers: Optional list of layer names to generate. Defaults to ALL_POLICIES.

    Returns a dict mapping filename (without .json) to policy document.
    """
    target_layers = layers if layers is not None else ALL_POLICIES
    policies = {}

    for policy_name in target_layers:
        if policy_name not in POLICY_GENERATORS:
            continue

        filename, generator_fn = POLICY_GENERATORS[policy_name]
        policy_doc = generator_fn(config)
        policies[filename] = policy_doc

    return policies


def write_policies(policies: dict[str, dict], output_dir: str | Path) -> list[Path]:
    """Write policy documents as JSON files to output directory.

    Returns list of written file paths.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    written = []
    for filename, policy_doc in policies.items():
        path = output_dir / f"{filename}.json"
        with open(path, "w") as f:
            json.dump(policy_doc, f, indent=2)
            f.write("\n")
        written.append(path)

    return written
