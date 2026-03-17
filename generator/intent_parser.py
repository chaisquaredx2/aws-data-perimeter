"""Parse data_perimeter_intent.yaml into structured configuration."""

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ThirdPartyException:
    type: str
    principal_accounts: list[str] = field(default_factory=list)
    principal_pattern: str | None = None
    resource_arns: list[str] = field(default_factory=list)
    justification: str = ""
    expiry: str | None = None
    permanent: bool = False


@dataclass
class PerimeterConfig:
    enabled: bool = True
    enforcement_mode: str = "enforced"
    default_action: str = "deny"
    exceptions: list[ThirdPartyException] = field(default_factory=list)


@dataclass
class AllowedExternalResources:
    type: str
    patterns: list[str] = field(default_factory=list)


@dataclass
class ResourcePerimeterConfig(PerimeterConfig):
    allowed_external_resources: list[AllowedExternalResources] = field(
        default_factory=list
    )

    @property
    def aws_managed_patterns(self) -> list[str]:
        patterns = []
        for group in self.allowed_external_resources:
            if group.type == "aws_managed":
                patterns.extend(group.patterns)
        return patterns


@dataclass
class NetworkConfig:
    corporate_cidrs: list[str] = field(default_factory=list)


@dataclass
class NetworkPerimeterConfig(PerimeterConfig):
    expected_networks: NetworkConfig = field(default_factory=NetworkConfig)
    allowed_vpcs: list[str] = field(default_factory=list)


@dataclass
class OUConfig:
    ou_id: str
    description: str = ""
    policies: list[str] = field(default_factory=list)
    enforcement_mode: str = "enforced"


@dataclass
class TagGovernance:
    protected_tag_patterns: list[str] = field(default_factory=list)
    allowed_mutator_tags: list[dict] = field(default_factory=list)


@dataclass
class IntentConfig:
    version: str = "1.0"
    org_id: str = ""
    org_name: str = ""
    ou_mapping: dict[str, OUConfig] = field(default_factory=dict)
    identity_perimeter: PerimeterConfig = field(default_factory=PerimeterConfig)
    resource_perimeter: ResourcePerimeterConfig = field(
        default_factory=ResourcePerimeterConfig
    )
    network_perimeter: NetworkPerimeterConfig = field(
        default_factory=NetworkPerimeterConfig
    )
    tag_governance: TagGovernance = field(default_factory=TagGovernance)


def parse_intent(path: str | Path) -> IntentConfig:
    """Parse intent YAML file into IntentConfig."""
    path = Path(path)
    with open(path) as f:
        raw = yaml.safe_load(f)

    config = IntentConfig(
        version=raw.get("version", "1.0"),
        org_id=raw.get("organization", {}).get("id", ""),
        org_name=raw.get("organization", {}).get("name", ""),
    )

    # Parse OU mapping
    for ou_name, ou_data in raw.get("ou_mapping", {}).items():
        config.ou_mapping[ou_name] = OUConfig(
            ou_id=ou_data.get("ou_id", ""),
            description=ou_data.get("description", ""),
            policies=ou_data.get("policies", []),
            enforcement_mode=ou_data.get("enforcement_mode", "enforced"),
        )

    perimeter_cfg = raw.get("perimeter_configuration", {})

    # Parse identity perimeter
    identity = perimeter_cfg.get("identity_perimeter", {})
    config.identity_perimeter = PerimeterConfig(
        enabled=identity.get("enabled", True),
        enforcement_mode=identity.get("enforcement_mode", "enforced"),
        default_action=identity.get("default_action", "deny"),
        exceptions=[
            ThirdPartyException(
                type=exc.get("type", ""),
                principal_accounts=exc.get("principal_accounts", []),
                principal_pattern=exc.get("principal_pattern"),
                resource_arns=exc.get("resource_arns", []),
                justification=exc.get("justification", ""),
                expiry=exc.get("expiry"),
                permanent=exc.get("permanent", False),
            )
            for exc in identity.get("exceptions", [])
        ],
    )

    # Parse resource perimeter
    resource = perimeter_cfg.get("resource_perimeter", {})
    config.resource_perimeter = ResourcePerimeterConfig(
        enabled=resource.get("enabled", True),
        enforcement_mode=resource.get("enforcement_mode", "enforced"),
        default_action=resource.get("default_action", "deny"),
        allowed_external_resources=[
            AllowedExternalResources(
                type=r.get("type", ""),
                patterns=r.get("patterns", []),
            )
            for r in resource.get("allowed_external_resources", [])
        ],
    )

    # Parse network perimeter
    network = perimeter_cfg.get("network_perimeter", {})
    expected = network.get("expected_networks", {})
    config.network_perimeter = NetworkPerimeterConfig(
        enabled=network.get("enabled", True),
        enforcement_mode=network.get("enforcement_mode", "enforced"),
        default_action=network.get("default_action", "deny"),
        expected_networks=NetworkConfig(
            corporate_cidrs=expected.get("corporate_cidrs", []),
        ),
        allowed_vpcs=expected.get("allowed_vpcs", []),
    )

    # Parse tag governance
    tag_gov = raw.get("tag_governance", {})
    config.tag_governance = TagGovernance(
        protected_tag_patterns=tag_gov.get("protected_tags", []),
        allowed_mutator_tags=tag_gov.get("tag_mutation_control", {}).get(
            "allowed_mutators", []
        ),
    )

    return config
