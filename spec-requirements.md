# Data Perimeter Implementation Specification
## ABAC-Driven SCP/RCP Model with Dynamic Exception Management

**Version:** 1.0
**Target Audience:** Cloud Security Architects, Platform Engineering Teams
**Classification:** Enterprise Architecture Specification

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [ABAC Tag Schema and Dynamic Value System](#abac-tag-schema-and-dynamic-value-system)
4. [Code Generation Specification](#code-generation-specification)
5. [Exception Management Framework](#exception-management-framework)
6. [External Access Patterns](#external-access-patterns)
7. [Visibility and Monitoring](#visibility-and-monitoring)
8. [Implementation Workflow](#implementation-workflow)
9. [Sample Code Templates](#sample-code-templates)

---

## Executive Summary

This specification defines an intent-driven, ABAC-based approach to implementing AWS data perimeter controls using Service Control Policies (SCPs) and Resource Control Policies (RCPs). The framework moves away from pipeline/OPA-based guardrails to leverage native AWS policy enforcement with dynamic tag-based controls, structured exception management, and integrated visibility through Wiz and AWS IAM Access Analyzer.

### Key Principles

1. **Intent-Driven Configuration**: Declare security intent in YAML/JSON schemas; generate policies automatically
2. **Attribute-Based Access Control (ABAC)**: Leverage principal and resource tags for dynamic, scalable authorization
3. **Exception-as-Code**: Manage exceptions through version-controlled, auditable specifications
4. **Defense-in-Depth**: Implement identity, resource, and network perimeters comprehensively
5. **Zero Trust Architecture**: Default deny with explicit, time-bound exceptions
6. **Observability-First**: Integrate Access Analyzer and Wiz for continuous validation

---

## Architecture Overview

### KMS-Centric Data Perimeter Model

> **Core insight:** Not all AWS resources support tags, but all sensitive data
> should be encrypted with Customer Managed Keys (CMKs). By enforcing ABAC at the
> KMS layer — and mandating CMK encryption on all resources — KMS becomes the
> universal choke point. If a principal can't decrypt the KMS key, they can't
> access the data, regardless of what resource-level permissions they have.

```
┌─────────────────────────────────────────────────────────────────┐
│                     AWS Organization Boundary                    │
│                                                                  │
│  Layer 1: Preventive SCPs (resource creation)                    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Deny resource creation without CMK encryption              │  │
│  │ Deny use of AWS-managed keys (aws/s3, aws/sqs, etc.)      │  │
│  │ Enforce KMS key tagging at creation                        │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Layer 2: KMS ABAC (data access — primary gate)                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ SCP on kms:Decrypt, kms:GenerateDataKey, kms:CreateGrant   │  │
│  │ ResourceTag/dp:data-zone == ${PrincipalTag/dp:data-zone}   │  │
│  │ Same for dp:environment, dp:project                        │  │
│  │ STATIC policy — only KMS key + principal tags change       │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Layer 3: Org-boundary SCPs/RCPs (metadata + identity)           │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Identity perimeter: only org principals → resources (RCP)  │  │
│  │ Resource perimeter: only org resources ← principals (SCP)  │  │
│  │ Org-level boundary only — no per-resource ABAC tags needed │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Layer 4: Network perimeter (SCP + RCP)                          │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Literal VPC/CIDR values — changes infrequently             │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Layer 5: Exception lifecycle (Lambda enforcer)                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ dp:exception:* tags on KMS keys (not individual resources) │  │
│  │ Lambda removes expired tags → deny reactivates             │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Why KMS as the Choke Point

```
Without KMS gate:                   With KMS gate:

  Tag S3 bucket     ✓               Tag KMS key (dp:data-zone=analytics)
  Tag SQS queue     ✓                   │
  Tag SNS topic     ✓                   ├── S3 bucket (CMK-encrypted)
  Tag DynamoDB      ✗ (limited)         ├── SQS queue (CMK-encrypted)
  Tag EBS volume    ✓                   ├── DynamoDB table (CMK-encrypted)
  Tag Kinesis       ✗                   ├── EBS volume (CMK-encrypted)
  Tag Redshift      ✓                   └── Kinesis stream (CMK-encrypted)
  ... hundreds of resources
                                     1 key per (zone, env, project) tuple
  Problem: inconsistent tag          All data access requires kms:Decrypt
  support, thousands of tags         → single ABAC enforcement point
```

### Policy Layer Summary

| Layer | Control Objective | Policy Type | ABAC Tags? | Changes When | Statements |
|-------|-------------------|-------------|------------|--------------|------------|
| 1. CMK Enforcement | All resources use CMK; deny non-CMK key usage | SCP | No | New services added | 15 |
| 2. KMS ABAC | Data access matches classification | SCP | Yes (KMS key + principal) | Never (static policy) | 1 |
| 3a. Org Boundary | Only org resources (metadata protection) | SCP | No | Third-party partnerships | 1 |
| 3b. Identity Perimeter | Only org principals | RCP | No | Third-party partnerships | 1 |
| 4. Network | Expected networks only | SCP | No | VPC/CIDR infra changes | 1 |
| 5. Exceptions | Time-bound overrides | Lambda | Yes (KMS key) | Auto-expires | — |
| 6. Tag Governance | Protect dp:* classification tags | SCP | No | Mutator team changes | 4 |

### Known Tradeoffs and Mitigations

| Tradeoff | Impact | Mitigation |
|----------|--------|------------|
| Metadata leakage (list/describe ops) | Object names, queue URLs visible without KMS | Layer 3 org-boundary SCP covers list/describe |
| Data key caching | Revocation eventually consistent (minutes-hours) | Accept for most cases; `kms:DisableKey` for emergencies |
| KMS grants bypass tag conditions | EBS, RDS create grants for async ops | SCP restricting `kms:CreateGrant` with ABAC conditions |
| Cross-service calls (`ViaAWSService`) | Service identity, not user's, in KMS call | Exclude `ViaAWSService=true`; trust upstream service auth |
| Presigned URLs | Creator's tags checked, not accessor's | Network perimeter + short URL expiry |
| Key-to-zone discipline | Shared keys break boundary | 1:1 key per (zone, env, project) enforced via IaC + tag governance |

---

## ABAC Tag Schema — KMS-Centric Model

### Core Tag Taxonomy

> **Design principle:** ABAC classification tags live on **KMS keys** and **IAM
> principals** only — not on individual resources (S3 buckets, SQS queues, etc.).
> Since all resources must be CMK-encrypted (enforced by Layer 1 SCPs), the KMS
> key is the universal choke point. This eliminates the problem of inconsistent
> tag support across AWS services and reduces tag management from thousands of
> resources to dozens of KMS keys.

#### 1. Perimeter Inclusion/Exclusion Tags

```yaml
perimeter_control_tags:
  # Network Perimeter
  - key: "dp:network:enforcement"
    values: ["enforced", "excluded", "monitoring"]
    scope: ["principal"]
    description: "Controls network perimeter applicability for this principal"

  # Identity Perimeter
  - key: "dp:identity:enforcement"
    values: ["enforced", "excluded", "monitoring"]
    scope: ["kms_key"]
    description: "Controls identity perimeter applicability for this KMS key"

  # Resource Perimeter
  - key: "dp:resource:enforcement"
    values: ["enforced", "excluded", "monitoring"]
    scope: ["principal"]
    description: "Controls resource perimeter applicability for this principal"

  # KMS ABAC Perimeter
  - key: "dp:kms:enforcement"
    values: ["enforced", "excluded", "monitoring"]
    scope: ["principal", "kms_key"]
    description: "Controls KMS ABAC enforcement — exclude principals or keys from tag matching"
```

#### 2. Shared Classification Tags (KMS Key + Principal Matching)

> **How it works:** IAM policy variables (`${aws:PrincipalTag/key}`) compare
> principal tag values against KMS key resource tags at runtime. The SCP targets
> KMS actions (`kms:Decrypt`, `kms:GenerateDataKey`, `kms:CreateGrant`). If
> the principal's classification tags don't match the KMS key's tags, the
> KMS operation is denied — and without KMS, the encrypted data is inaccessible.
>
> **Policies are static.** Onboarding a new team/zone/project = create a KMS key
> with matching tags + tag the IAM role. No policy redeployment.

```yaml
shared_classification_tags:
  # Primary ABAC dimension — zone-based access boundary
  - key: "dp:data-zone"
    description: >
      Logical access zone. Principals can only use KMS keys in their
      matching zone. Policy evaluates:
      aws:ResourceTag/dp:data-zone == ${aws:PrincipalTag/dp:data-zone}
    scope: ["principal", "kms_key"]
    examples: ["analytics", "payments", "shared-services", "partner-acme"]
    policy_variable: true

  # Environment boundary — prevents cross-environment access
  - key: "dp:environment"
    description: >
      Environment isolation boundary. Policy evaluates:
      aws:ResourceTag/dp:environment == ${aws:PrincipalTag/dp:environment}
    scope: ["principal", "kms_key"]
    values: ["production", "staging", "development", "sandbox"]
    policy_variable: true

  # Project/team boundary — fine-grained isolation
  - key: "dp:project"
    description: >
      Project-level access boundary for workload isolation. Policy evaluates:
      aws:ResourceTag/dp:project == ${aws:PrincipalTag/dp:project}
    scope: ["principal", "kms_key"]
    examples: ["data-lake", "ml-pipeline", "customer-portal"]
    policy_variable: true
```

#### KMS ABAC Policy Variable Matching — How It Works

```
  IAM Role (principal tags):          KMS Key (resource tags):
  ┌───────────────────────────┐      ┌───────────────────────────┐
  │ dp:data-zone = "analytics"│      │ dp:data-zone = "analytics"│
  │ dp:environment = "prod"   │      │ dp:environment = "prod"   │
  │ dp:project = "data-lake"  │      │ dp:project = "data-lake"  │
  └───────────────────────────┘      └───────────────────────────┘
              │                                    │
              ▼                                    ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  KMS ABAC SCP Condition (STATIC — never changes):            │
  │                                                              │
  │  "StringNotEqualsIfExists": {                                │
  │    "aws:ResourceTag/dp:data-zone":                           │
  │        "${aws:PrincipalTag/dp:data-zone}",                   │
  │    "aws:ResourceTag/dp:environment":                         │
  │        "${aws:PrincipalTag/dp:environment}",                 │
  │    "aws:ResourceTag/dp:project":                             │
  │        "${aws:PrincipalTag/dp:project}"                      │
  │  }                                                           │
  │                                                              │
  │  Action: ["kms:Decrypt", "kms:GenerateDataKey",              │
  │           "kms:GenerateDataKeyWithoutPlaintext",             │
  │           "kms:ReEncryptFrom", "kms:ReEncryptTo",            │
  │           "kms:CreateGrant"]                                 │
  │                                                              │
  │  → Tags match? KMS operation allowed → data accessible       │
  │  → Tags differ? DENY KMS → data encrypted, inaccessible     │
  │                                                              │
  │  Onboarding: tag KMS key + tag IAM role. Policy unchanged.   │
  └──────────────────────────────────────────────────────────────┘

  Data flow:
  ┌──────────┐     kms:Decrypt      ┌──────────┐     s3:GetObject    ┌──────────┐
  │ IAM Role │ ──────────────────── │ KMS Key  │ ◄───────────────── │ S3 Bucket│
  │ (tagged) │   ABAC check here    │ (tagged) │   encrypted with   │(no tags  │
  └──────────┘                      └──────────┘   this CMK          │ needed!) │
                                                                     └──────────┘
```

#### KMS Key-to-Zone Mapping Convention

```yaml
kms_key_strategy:
  description: >
    One KMS key per (data-zone, environment, project) tuple.
    Enforced via IaC templates and tag governance SCP.
    Keys are created in each region where resources exist.
  naming_convention: "alias/dp/{data-zone}/{environment}/{project}"
  examples:
    - alias: "alias/dp/analytics/production/data-lake"
      tags:
        dp:data-zone: "analytics"
        dp:environment: "production"
        dp:project: "data-lake"
    - alias: "alias/dp/payments/production/customer-portal"
      tags:
        dp:data-zone: "payments"
        dp:environment: "production"
        dp:project: "customer-portal"
    - alias: "alias/dp/shared-services/production/shared"
      tags:
        dp:data-zone: "shared-services"
        dp:environment: "production"
        dp:project: "shared"
  anti_pattern: >
    NEVER share a KMS key across data zones or environments.
    A key tagged analytics/production must ONLY encrypt analytics/production
    resources. Violating this breaks the entire ABAC boundary.
```

#### Network Perimeter — Literal Values (Exception to ABAC Pattern)

```yaml
network_perimeter_values:
  description: >
    Network perimeter cannot use policy variables because aws:SourceVpc and
    aws:SourceIp are request context keys, not tags on a taggable entity.
    VPC and CIDR lists are hardcoded in the network perimeter SCP and
    managed via the intent configuration. These values change infrequently
    (infrastructure-level) so policy redeployment is acceptable.
  managed_in: "data_perimeter_intent.yaml → network_perimeter section"
  update_frequency: "Low — only when VPCs or corporate CIDRs change"
```

#### 3. Exception Management Tags

```yaml
exception_tags:
  - key: "dp:exception:id"
    value_pattern: "EXC-{YYYY}-{####}"
    scope: ["principal", "kms_key"]
    required_with: ["dp:exception:expiry", "dp:exception:justification"]
    description: "Unique exception identifier"

  - key: "dp:exception:expiry"
    value_pattern: "{ISO-8601-date}"
    scope: ["principal", "kms_key"]
    description: "Exception expiration date — enforced by ExceptionExpiryEnforcer Lambda"

  - key: "dp:exception:justification"
    value_pattern: "{free-text}"
    scope: ["principal", "kms_key"]
    description: "Business justification for exception"

  - key: "dp:exception:approver"
    value_pattern: "{email-address}"
    scope: ["principal", "kms_key"]
    description: "Approver email for audit trail"
```

#### 4. Workload Classification Tags

```yaml
workload_tags:
  - key: "dp:data-classification"
    values: ["public", "internal", "confidential", "restricted"]
    scope: ["kms_key"]
    description: "Data sensitivity classification — applied to KMS keys"

  - key: "dp:compliance-scope"
    values: ["pci", "hipaa", "sox", "fedramp", "none"]
    scope: ["kms_key"]
    encoding: "pipe-delimited"  # e.g., "pci|sox|hipaa" (AWS tags are single-value)
    description: "Compliance frameworks requiring additional controls"
```

### Tag Hierarchy and Precedence

```
Priority (Highest to Lowest):
1. dp:exception:* tags (explicit exceptions — managed by ExceptionExpiryEnforcer Lambda)
2. dp:*:enforcement = "excluded" (explicit exclusions from specific perimeters)
3. KMS ABAC tag matching via policy variables
   (dp:data-zone, dp:environment, dp:project on KMS key vs. principal)
4. dp:data-classification on KMS key (classification-based controls)
5. Layer 1 CMK enforcement (baseline — all resources must use CMK)
6. Org boundary enforcement (Layer 3 — identity/resource perimeter)
```

---

## Tech Stack and Project Structure

### Technology Decisions

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Policy generator | Python 3.12 | Parses intent YAML, generates JSON policies, validates SCP size limits |
| Lambda functions | Python 3.12 | ExceptionExpiryEnforcer, compliance checker |
| Infrastructure | Terraform | SCPs, RCPs, KMS keys, Lambda, EventBridge, DynamoDB, SNS |
| Configuration | YAML | Intent schema (`data_perimeter_intent.yaml`) |
| Generated output | JSON | SCP/RCP policy documents |

### Repository Structure

```
aws-data-perimeter/
├── terraform/
│   ├── modules/
│   │   ├── scp-policies/              # SCP deployment (Layers 1-4)
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── rcp-policies/              # RCP deployment (Layer 3b)
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── kms-keys/                  # KMS key creation with classification tags
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── exception-enforcer/        # Lambda + EventBridge + DynamoDB + SNS
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   └── tag-governance/            # Tag governance SCP
│   │       ├── main.tf
│   │       ├── variables.tf
│   │       └── outputs.tf
│   ├── environments/
│   │   ├── production/
│   │   │   ├── main.tf               # Composes modules for prod
│   │   │   ├── terraform.tfvars
│   │   │   └── backend.tf
│   │   └── staging/
│   │       ├── main.tf
│   │       ├── terraform.tfvars
│   │       └── backend.tf
│   └── policies/                      # Generated JSON policy documents
│       ├── scp-cmk-enforcement.json   # Layer 1
│       ├── scp-kms-abac.json          # Layer 2
│       ├── scp-org-boundary.json      # Layer 3a
│       ├── rcp-identity-perimeter.json # Layer 3b
│       ├── scp-network-perimeter.json # Layer 4
│       └── scp-tag-governance.json    # Layer 6
│
├── generator/                         # Python policy generator
│   ├── __init__.py
│   ├── cli.py                         # CLI entry point
│   ├── intent_parser.py               # Parse data_perimeter_intent.yaml
│   ├── policy_generator.py            # Generate JSON policies from intent
│   ├── policy_validator.py            # Validate SCP size limits, JSON structure
│   ├── policy_splitter.py             # Split policies exceeding 5,120 byte limit
│   └── templates/                     # Jinja2 or string templates for policy structure
│       ├── kms_abac.py
│       ├── cmk_enforcement.py
│       ├── org_boundary.py
│       ├── network_perimeter.py
│       └── tag_governance.py
│
├── lambda/                            # Lambda function source
│   ├── exception_expiry_enforcer/
│   │   ├── handler.py                 # Main Lambda handler
│   │   ├── discovery.py               # Tag discovery (Resource Groups + IAM APIs)
│   │   ├── revocation.py              # Tag removal + audit breadcrumb
│   │   ├── notifications.py           # SNS alerts
│   │   └── requirements.txt
│   └── compliance_checker/
│       ├── handler.py
│       ├── access_analyzer.py
│       └── requirements.txt
│
├── config/
│   ├── data_perimeter_intent.yaml     # Primary intent configuration
│   └── exceptions/                    # Exception request YAMLs
│       └── EXC-2026-0042.yaml
│
├── tests/
│   ├── test_policy_generator.py
│   ├── test_policy_validator.py
│   ├── test_policy_splitter.py
│   ├── test_exception_enforcer.py
│   └── fixtures/
│       ├── sample_intent.yaml
│       └── expected_policies/
│
├── pyproject.toml                     # Python project config
└── Makefile                           # generate, validate, plan, apply
```

### Build and Deploy Workflow

```
make generate          # Python generator reads intent YAML → writes JSON policies to terraform/policies/
make validate          # Validate JSON policies (size limits, structure, no duplicate keys)
make plan              # terraform plan (shows what SCPs/RCPs will change)
make apply             # terraform apply (deploys to AWS Organizations)
```

```
┌──────────────────┐     ┌───────────────────┐     ┌──────────────────┐
│ config/          │     │ generator/        │     │ terraform/       │
│ intent.yaml      │────▶│ policy_generator  │────▶│ policies/*.json  │
│ exceptions/*.yaml│     │ policy_validator  │     │ modules/         │
└──────────────────┘     │ policy_splitter   │     │ environments/    │
                         └───────────────────┘     └────────┬─────────┘
                                                            │
                                                   terraform apply
                                                            │
                                                            ▼
                                                   ┌──────────────────┐
                                                   │ AWS Organization │
                                                   │ • SCPs on OUs    │
                                                   │ • RCPs on OUs    │
                                                   │ • Lambda         │
                                                   │ • EventBridge    │
                                                   │ • DynamoDB       │
                                                   │ • SNS            │
                                                   └──────────────────┘
```

---

## Code Generation Specification

### Intent Schema Format

```yaml
# data_perimeter_intent.yaml
version: "1.0"
organization:
  id: "o-abc123xyz"
  name: "Example Corp"

# OU-level policy attachment — SCPs/RCPs apply to entire OUs, not individual accounts.
# Canary OU is used for testing new policies before broader rollout.
ou_mapping:
  shared_services:
    ou_id: "ou-abc1-shared00"
    description: "Shared services accounts (security tooling, logging, networking, CI/CD)"
    policies:
      - layer_1_cmk_enforcement
      - layer_2_kms_abac
      - layer_3a_org_boundary
      - layer_3b_identity_perimeter
      - layer_4_network_perimeter
      - layer_6_tag_governance
    enforcement_mode: "enforced"
    notes: >
      Shared services principals may need dp:data-zone=shared-services to
      access KMS keys across zones (e.g., centralized logging, security scanning).
      Use dp:kms:enforcement=excluded for cross-zone service roles.

  business_unit:
    ou_id: "ou-abc1-bu000000"
    description: "Business unit workload accounts (internal applications, data processing)"
    policies:
      - layer_1_cmk_enforcement
      - layer_2_kms_abac
      - layer_3a_org_boundary
      - layer_3b_identity_perimeter
      - layer_4_network_perimeter
      - layer_6_tag_governance
    enforcement_mode: "enforced"
    notes: >
      Primary OU for ABAC enforcement. Each BU account's principals and KMS keys
      tagged with matching dp:data-zone, dp:environment, dp:project values.

  internet_facing:
    ou_id: "ou-abc1-inet0000"
    description: "Internet-facing accounts (public APIs, CDN origins, web apps)"
    policies:
      - layer_1_cmk_enforcement
      - layer_2_kms_abac
      - layer_3a_org_boundary
      - layer_3b_identity_perimeter
      - layer_4_network_perimeter
      - layer_6_tag_governance
    enforcement_mode: "enforced"
    notes: >
      Network perimeter has broader exceptions here — internet-facing workloads
      need inbound public access. Identity perimeter is critical to prevent
      external principal access to backend resources. KMS ABAC isolates
      internet-facing data zones from internal BU data zones.

  canary_testing:
    ou_id: "ou-abc1-canary00"
    description: "Canary testing OU — deploy and validate new policies here before broader rollout"
    policies:
      - layer_1_cmk_enforcement
      - layer_2_kms_abac
      - layer_3a_org_boundary
      - layer_3b_identity_perimeter
      - layer_4_network_perimeter
      - layer_6_tag_governance
    enforcement_mode: "enforced"
    notes: >
      All policy changes deploy to canary first. Contains test accounts that
      mirror production patterns. Validate no disruption before promoting
      to other OUs. Rollout order: canary → shared_services → business_unit → internet_facing.

perimeter_configuration:
  identity_perimeter:
    enabled: true
    enforcement_mode: "enforced"  # enforced | monitoring | disabled
    default_action: "deny"

    exceptions:
      - type: "third_party_integration"
        principal_accounts: ["123456789012", "234567890123"]
        resource_arns:
          - "arn:aws:s3:::partner-data-bucket/*"
        justification: "Partner data sharing agreement"
        expiry: "2027-12-31"
        approver: "ciso@example.com"

      - type: "service_role"
        principal_pattern: "role/AWSServiceRoleFor*"
        scope: "organization"
        justification: "AWS service-linked roles"
        permanent: true

  resource_perimeter:
    enabled: true
    enforcement_mode: "enforced"
    default_action: "deny"

    allowed_external_resources:
      # AWS-owned resources
      - type: "aws_managed"
        patterns:
          - "arn:aws:s3:::aws-*"
          - "arn:aws:s3:::amazon-*"
          - "arn:aws:s3:::jumpstart-cache-prod-*"
        justification: "AWS managed service resources"

      # Third-party integrations
      - type: "third_party"
        patterns:
          - "arn:aws:s3:::partner-vendor-bucket/*"
        allowed_principals:
          - tag: "dp:resource:external-integration"
            value: "vendor-xyz"
        justification: "Vendor data ingestion"
        expiry: "2027-06-30"

  network_perimeter:
    enabled: true
    enforcement_mode: "enforced"
    default_action: "deny"

    expected_networks:
      corporate_cidrs:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "203.0.113.0/24"  # Example public IP range

      vpc_configuration:
        enforce_vpc_endpoints: true
        allowed_vpcs:
          - source: "tag"
            tag_key: "dp:network:corporate-vpc"
            tag_value: "true"

      service_networks:
        allow_aws_service_networks: true
        service_patterns:
          - "cloudfront.amazonaws.com"
          - "s3.amazonaws.com"

tag_governance:
  required_tags:
    principals:
      - "dp:environment"
      - "dp:data-classification"
    resources:
      - "dp:data-classification"

  protected_tags:
    - "dp:exception:*"
    - "dp:*:enforcement"

  tag_mutation_control:
    allowed_mutators:
      - tag: "team"
        value: "security-admin"
      - tag: "team"
        value: "platform-engineering"
```

### Policy Generation Rules

#### Input Schema → SCP/RCP Translation

```python
# Pseudocode for policy generation — KMS-Centric Model
#
# Layered enforcement:
#   Layer 1: CMK enforcement SCPs — deny resource creation without CMK
#   Layer 2: KMS ABAC SCP — tag matching on KMS actions (STATIC policy)
#   Layer 3: Org-boundary SCPs/RCPs — metadata/identity protection (STATIC)
#   Layer 4: Network perimeter SCP — literal VPC/CIDR (semi-static)
#
# Only Layer 1 (new services) and Layer 4 (new VPCs) require redeployment.
# Layers 2 and 3 are fully static — onboarding = tagging only.

def generate_cmk_enforcement_scp(intent_config):
    """
    Layer 1: Prevent resource creation without CMK encryption, deny use of
    non-CMK KMS keys, and enforce CloudWatch Logs CMK association.

    This is the foundational prerequisite for the KMS-centric model.
    Without it, unencrypted resources or AWS-managed keys bypass ABAC entirely.

    15 statements covering: S3, DynamoDB, SQS, SNS, EBS, RDS, EFS,
    Secrets Manager, Kinesis, Redshift, CloudWatch Logs, non-CMK key usage
    denial, and KMS key classification tag requirements.

    Service-to-service edge cases:
    - aws:ViaAWSService bypass on S3 PutObject (ALB access logs, Redshift UNLOAD)
    - aws:ViaAWSService + SLR bypass on CloudWatch Logs CreateLogGroup (Lambda, ECS auto-create)
    - aws:ViaAWSService bypass on non-CMK key usage (services using aws/s3, aws/ebs keys)
    - SCPs don't apply to AWS service principals (CloudTrail, Config) — no bypass needed
    """
    # See generator/templates/cmk_enforcement.py for full implementation.
    # Key statements:
    #
    # DenyS3WithoutCMK            — s3:PutObject without aws:kms (ViaAWSService bypass)
    # DenyS3BucketWithoutDefaultCMK — s3:PutEncryptionConfiguration
    # DenyDynamoDBWithoutCMK       — CreateTable + UpdateTable + Restore* without CMK
    # DenySQSWithoutCMK            — sqs:CreateQueue without KmsMasterKeyId
    # DenySNSWithoutCMK            — sns:CreateTopic without KmsMasterKeyId
    # DenyEBSWithoutEncryption     — ec2:CreateVolume with Encrypted=false
    # DenyRDSWithoutEncryption     — CreateDBInstance + Cluster + ReadReplica
    # DenyEFSWithoutCMK            — elasticfilesystem:CreateFileSystem with Encrypted=false
    # DenySecretsManagerWithoutCMK — secretsmanager:CreateSecret without KmsKeyId
    # DenyKinesisWithoutCMK        — kinesis:CreateStream/UpdateStreamMode without KMS encryption
    # DenyRedshiftWithoutCMK       — redshift:CreateCluster/RestoreFromClusterSnapshot unencrypted
    # DenyCloudWatchLogsRemoveCMK  — Unconditional deny on logs:DisassociateKmsKey
    # DenyCloudWatchLogsCreateWithoutCMK — logs:CreateLogGroup gated by
    #                                dp:logs:cmk-automation tag (ViaAWSService + SLR bypass)
    # DenyNonCMKKeyUsage           — Deny KMS crypto ops on keys without dp:data-zone tag
    #                                (catches aws/s3, aws/ebs, etc.; ViaAWSService bypass)
    # DenyKMSKeyWithoutClassificationTags — kms:CreateKey without dp:data-zone tag
    ...


def generate_kms_abac_scp(intent_config):
    """
    Layer 2: KMS ABAC SCP — the primary data access gate.

    STATIC policy. Uses IAM policy variables to match principal tags against
    KMS key resource tags. If tags don't match, kms:Decrypt (and related
    actions) are denied — making the encrypted data inaccessible regardless
    of resource-level permissions.

    Tag KMS keys + IAM principals to manage access. Never redeploy this policy.
    """
    policy = {
        "Version": "2012-10-17",
        "Statement": []
    }

    kms_abac_deny = {
        "Sid": "EnforceKMSABACTagMatch",
        "Effect": "Deny",
        "Action": [
            "kms:Decrypt",
            "kms:GenerateDataKey",
            "kms:GenerateDataKeyWithoutPlaintext",
            "kms:GenerateDataKeyPair",
            "kms:GenerateDataKeyPairWithoutPlaintext",
            "kms:ReEncryptFrom",
            "kms:ReEncryptTo",
            "kms:CreateGrant"
        ],
        "Resource": "*",
        "Condition": {
            # ABAC tag matching — static policy variable references
            "StringNotEqualsIfExists": {
                "aws:ResourceTag/dp:data-zone": "${aws:PrincipalTag/dp:data-zone}",
                "aws:ResourceTag/dp:environment": "${aws:PrincipalTag/dp:environment}",
                "aws:ResourceTag/dp:project": "${aws:PrincipalTag/dp:project}",
                # Skip principals excluded from KMS ABAC
                "aws:PrincipalTag/dp:kms:enforcement": ["excluded", "monitoring"]
            },
            # Skip principals with active exceptions
            "Null": {
                "aws:PrincipalTag/dp:exception:id": "true"
            },
            # Allow AWS service-to-service KMS calls (e.g., S3 encrypting on PutObject)
            "BoolIfExists": {
                "aws:ViaAWSService": "false"
            },
            # Skip AWS service-linked roles
            "ArnNotLikeIfExists": {
                "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*"
            }
        }
    }

    policy["Statement"].append(kms_abac_deny)
    return policy


def generate_org_boundary_scp(intent_config):
    """
    Layer 3a: Org-boundary SCP for resource perimeter.

    Lightweight SCP that prevents principals from accessing resources outside
    the org (covers metadata/list operations that don't touch KMS).
    No ABAC tags needed — just org ID check.
    """
    policy = {
        "Version": "2012-10-17",
        "Statement": []
    }

    org_deny = {
        "Sid": "EnforceResourcePerimeterOrgBoundary",
        "Effect": "Deny",
        "Action": [
            "s3:*", "sqs:*", "sns:*", "kms:*",
            "lambda:*", "secretsmanager:*", "ssm:*"
        ],
        "Resource": "*",
        "Condition": {
            "StringNotEquals": {
                "aws:ResourceOrgID": intent_config.organization.id
            },
            "StringNotEqualsIfExists": {
                "aws:PrincipalTag/dp:resource:enforcement": ["excluded", "monitoring"]
            },
            "Null": {
                "aws:PrincipalTag/dp:exception:id": "true"
            },
            # Allow AWS service-to-service calls (S3 replication,
            # CloudFormation StackSets, Config delivery, etc.)
            "BoolIfExists": {
                "aws:ViaAWSService": "false"
            },
            # Allow AWS-managed resources (S3 buckets used by services)
            "ArnNotLikeIfExists": {
                "aws:ResourceArn": intent_config.resource_perimeter.aws_managed_patterns,
                "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*"
            }
        }
    }

    policy["Statement"].append(org_deny)
    return policy


def generate_identity_perimeter_rcp(intent_config):
    """
    Layer 3b: Identity perimeter RCP.

    Org-boundary check for resources. Third-party accounts use literal IDs
    (external principals can't be tagged). Exception tags on KMS keys signal
    approved external access.
    """
    policy = {
        "Version": "2012-10-17",
        "Statement": []
    }

    identity_deny = {
        "Sid": "EnforceIdentityPerimeterOrgBoundary",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "*",
        "Resource": "*",
        "Condition": {
            "StringNotEqualsIfExists": {
                "aws:PrincipalOrgID": intent_config.organization.id,
                "aws:ResourceTag/dp:identity:enforcement": ["excluded", "monitoring"]
            },
            "BoolIfExists": {
                "aws:PrincipalIsAWSService": "false"
            },
            # Exception tags on KMS keys (not individual resources)
            "Null": {
                "aws:ResourceTag/dp:exception:id": "true"
            }
        }
    }

    # Third-party accounts: literal IDs (can't tag external principals)
    if intent_config.identity_perimeter.exceptions:
        third_party_accounts = [
            exc.principal_accounts
            for exc in intent_config.identity_perimeter.exceptions
            if exc.type == "third_party_integration"
        ]
        if third_party_accounts:
            identity_deny["Condition"]["StringNotEqualsIfExists"][
                "aws:PrincipalAccount"
            ] = flatten(third_party_accounts)

    policy["Statement"].append(identity_deny)
    return policy


def generate_network_perimeter_scp(intent_config):
    """
    Layer 4: Network perimeter SCP.

    Literal VPC/CIDR values — the only semi-static policy. Network context
    (aws:SourceVpc, aws:SourceIp) is not taggable, so values are hardcoded.
    Changes infrequently (infrastructure-level).
    """
    policy = {
        "Version": "2012-10-17",
        "Statement": []
    }

    network_deny = {
        "Sid": "EnforceNetworkPerimeterExpectedNetworks",
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {
            "StringNotEqualsIfExists": {
                "aws:SourceVpc": extract_vpc_list(intent_config),
                "aws:PrincipalTag/dp:network:enforcement": ["excluded", "monitoring"]
            },
            "NotIpAddressIfExists": {
                "aws:SourceIp": intent_config.network_perimeter.expected_networks.corporate_cidrs
            },
            "BoolIfExists": {
                "aws:ViaAWSService": "false"
            },
            "Null": {
                "aws:PrincipalTag/dp:exception:id": "true"
            },
            "ArnNotLikeIfExists": {
                "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*"
            }
        }
    }

    policy["Statement"].append(network_deny)
    return policy
```

---

## Exception Management Framework

### Exception Lifecycle (KMS-Centric)

> **In the KMS-centric model, exception tags are applied to KMS keys or IAM
> principals — not individual resources.** A single KMS key exception covers
> all resources encrypted with that key. For outbound access (our principals
> accessing external resources), exception tags go on the IAM principal.

```
┌─────────────┐
│   Request   │
│  Exception  │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│   Validation    │──── Check: Business justification
│   & Approval    │──── Check: Security impact assessment
└──────┬──────────┘──── Check: Compliance requirements
       │
       ▼
┌─────────────────┐
│  Tag KMS Key    │──── Apply: dp:exception:id
│  or Principal   │──── Apply: dp:exception:expiry
└──────┬──────────┘──── Apply: dp:exception:justification
       │                Apply: dp:exception:approver
       ▼                (No policy regen needed — policies check tag presence)
┌─────────────────┐
│  Continuous     │──── Monitor exception usage
│  Monitoring     │──── Alert on expiry approaching
└──────┬──────────┘──── Audit access patterns
       │
       ▼
┌─────────────────┐
│   Exception     │──── Lambda auto-removes expired tags from KMS keys
│   Expiration    │──── Deny reactivates immediately (no policy regen)
└─────────────────┘──── Notify stakeholders
```

### Exception Request Schema

```yaml
# exception_request.yaml
exception_id: "EXC-2026-0042"
request_date: "2026-03-16"
requester: "john.doe@example.com"

exception_type: "third_party_access"  # third_party_access | service_exemption | temporary_override

scope:
  perimeter_types: ["identity", "kms"]
  # In KMS-centric model, exceptions target KMS keys (not individual resources)
  # or IAM principals (for outbound access)
  target_type: "kms_key"  # kms_key | principal
  target_identifiers:
    - "arn:aws:kms:us-east-1:111122223333:key/12345678-abcd-1234-efgh-123456789012"
  target_alias: "alias/dp/shared-services/production/partner-acme"
  encrypted_resources:  # Informational — all resources using this KMS key are covered
    - "arn:aws:s3:::sensitive-data-bucket"
    - "arn:aws:s3:::sensitive-data-bucket/*"

exception_details:
  allowed_external_principals:
    - account: "123456789012"
      description: "Partner Company A"
      actions: ["s3:GetObject", "s3:PutObject"]
      kms_actions: ["kms:Decrypt", "kms:GenerateDataKey"]

  duration:
    start_date: "2026-04-01"
    end_date: "2027-03-31"
    auto_renew: false

  justification: |
    Business partnership requires bi-directional data exchange for
    joint analytics project. SOW signed 2026-03-01, expires 2027-03-31.

  security_review:
    risk_rating: "medium"
    mitigating_controls:
      - "Dedicated KMS key for partner data (alias/dp/shared-services/production/partner-acme)"
      - "S3 bucket versioning enabled"
      - "CloudTrail logging all KMS and S3 access"
      - "GuardDuty monitoring anomalous access"
    reviewer: "security-team@example.com"
    approval_date: "2026-03-20"

  compliance_impact:
    frameworks_affected: ["SOC2", "ISO27001"]
    compensating_controls: "Enhanced logging and monitoring"
    compliance_approval: "compliance-team@example.com"

implementation:
  method: "kms_key_tag"  # kms_key_tag | principal_tag
  tags_to_apply:
    - key: "dp:exception:id"
      value: "EXC-2026-0042"
    - key: "dp:exception:expiry"
      value: "2027-03-31"
    - key: "dp:exception:justification"
      value: "Partner data sharing - SOW 2026-03-01"
    - key: "dp:exception:approver"
      value: "ciso@example.com"
  # Partner account ID (123456789012) is a literal value in the identity
  # perimeter RCP — external principals cannot be tagged. Additionally,
  # the KMS key policy must grant kms:Decrypt to the partner account.
  kms_key_policy_update:
    grant_to: "arn:aws:iam::123456789012:root"
    actions: ["kms:Decrypt", "kms:GenerateDataKey"]
    conditions:
      source_ip: ["203.0.113.0/24"]
```

### Automated Exception Management

```python
# exception_manager.py
class DataPerimeterExceptionManager:
    """
    Manages lifecycle of data perimeter exceptions.

    In the KMS-centric model, exception tags are applied to:
    - KMS keys (for inbound third-party access — covers all resources using that key)
    - IAM principals (for outbound access to external resources)
    NOT to individual resources (S3 buckets, SQS queues, etc.)
    """

    def __init__(self):
        self.kms_client = boto3.client("kms")
        self.iam_client = boto3.client("iam")

    def validate_exception_request(self, request):
        """
        Validate exception request against policy
        """
        validations = {
            "has_business_justification": len(request.justification) > 50,
            "has_security_review": request.security_review is not None,
            "has_expiry_date": request.duration.end_date is not None,
            "duration_within_limits": self._check_duration_limits(request),
            "risk_acceptable": request.security_review.risk_rating in ["low", "medium"],
            "compliance_approved": request.compliance_impact.compliance_approval is not None,
            "target_is_kms_or_principal": request.scope.target_type in ["kms_key", "principal"]
        }

        return all(validations.values()), validations

    def apply_exception_tags(self, request):
        """
        Apply exception tags to KMS keys or IAM principals.
        """
        tags = [
            {"Key": "dp:exception:id", "Value": request.exception_id},
            {"Key": "dp:exception:expiry", "Value": request.duration.end_date},
            {"Key": "dp:exception:justification", "Value": request.justification[:256]},
            {"Key": "dp:exception:approver", "Value": request.security_review.reviewer}
        ]

        for target in request.scope.target_identifiers:
            if request.scope.target_type == "kms_key":
                # Tag the KMS key — covers all resources encrypted with this key
                self.kms_client.tag_resource(
                    KeyId=target,
                    Tags=[{"TagKey": t["Key"], "TagValue": t["Value"]} for t in tags]
                )
            elif request.scope.target_type == "principal":
                # Tag the IAM role — for outbound access exceptions
                role_name = target.split("/")[-1]
                self.iam_client.tag_role(
                    RoleName=role_name,
                    Tags=tags
                )

        # If this is a third-party access exception, also update KMS key policy
        # to grant the partner account kms:Decrypt access
        if request.kms_key_policy_update:
            self._update_kms_key_policy(request)

    def monitor_exception_expiry(self):
        """
        Monitor and alert on approaching exception expiry
        """
        current_date = datetime.now()

        # Query all resources/principals with exception tags
        exceptions = self._get_all_exceptions()

        for exception in exceptions:
            expiry_date = datetime.fromisoformat(exception.tags["dp:exception:expiry"])
            days_until_expiry = (expiry_date - current_date).days

            if days_until_expiry <= 30:
                self._send_expiry_notification(exception, days_until_expiry)

            if days_until_expiry <= 0:
                self._revoke_exception(exception)

    def _revoke_exception(self, exception):
        """
        Remove exception tags. No policy regeneration needed — policies use
        Null condition on dp:exception:id, so tag removal immediately
        reactivates the deny. See ExceptionExpiryEnforcer Lambda for the
        scheduled enforcement implementation.
        """
        # Write audit breadcrumb before removal
        self._tag_resource(exception.resource_arn, [
            {"Key": "dp:exception:revoked-at", "Value": datetime.now().isoformat()},
            {"Key": "dp:exception:revoked-id", "Value": exception.tags["dp:exception:id"]}
        ])

        # Remove active exception tags (deny reactivates immediately)
        self._remove_exception_tags(exception.resource_arn)

        # Send notification
        self._send_revocation_notification(exception)
```

### Lambda-Based Exception Expiry Enforcer

> **Design Note:** AWS IAM policy conditions cannot reference tag values dynamically
> (e.g., `DateGreaterThanIfExists` against a tag-stored date). Exception expiry is
> therefore enforced **out-of-band** by a scheduled Lambda function. Policies only
> check for **tag presence** (`Null` condition on `dp:exception:id`). When Lambda
> removes exception tags from an expired resource/principal, the deny statement
> activates immediately on the next API call.

#### Architecture

```
EventBridge Rule (rate: 1 hour)
        │
        ▼
┌───────────────────────────────────┐
│   ExceptionExpiryEnforcer Lambda  │
├───────────────────────────────────┤
│  1. Discover all resources and    │
│     principals with dp:exception  │
│     tags (Resource Groups Tagging │
│     API + IAM tag queries)        │
│  2. Parse dp:exception:expiry     │
│  3. Send notifications for        │
│     approaching expiry            │
│  4. Remove tags on expired        │
│     exceptions (after grace       │
│     period)                       │
│  5. Write audit trail tags and    │
│     CloudWatch metrics            │
└──────────┬────────────────────────┘
           │
     ┌─────┼──────────┬─────────────┐
     ▼     ▼          ▼             ▼
  Remove  SNS       CloudWatch   DynamoDB
  Tags    Alerts    Metrics      Audit Log
```

#### Lambda Configuration

```yaml
# exception_expiry_enforcer.yaml
exception_expiry_enforcer:
  runtime: "python3.12"
  handler: "exception_expiry_enforcer.handler"
  timeout_seconds: 900  # 15 minutes max for large orgs
  memory_mb: 512

  schedule:
    rate: "rate(1 hour)"
    enabled: true

  configuration:
    # Grace period after expiry before tags are removed (hours)
    grace_period_hours: 0

    # Notification thresholds (days before expiry)
    notification_thresholds: [30, 14, 7, 1]

    # SNS topic for notifications
    notification_topic_arn: "arn:aws:sns:us-east-1:111122223333:exception-expiry-alerts"

    # DynamoDB table for audit trail
    audit_table_name: "DataPerimeterExceptionAudit"

    # Whether to actually remove tags (false = dry-run / report only)
    enforce_removal: true

  iam_permissions:
    - effect: "Allow"
      actions:
        - "tag:GetResources"           # Resource Groups Tagging API
        - "tag:GetTagKeys"
        - "tag:GetTagValues"
      resources: ["*"]

    - effect: "Allow"
      actions:
        - "iam:ListRoles"
        - "iam:ListRoleTags"
        - "iam:ListUsers"
        - "iam:ListUserTags"
        - "iam:UntagRole"
        - "iam:UntagUser"
        - "iam:TagRole"                # For dp:exception:revoked-at breadcrumb
        - "iam:TagUser"
      resources: ["*"]

    - effect: "Allow"
      actions:
        - "s3:GetBucketTagging"
        - "s3:PutBucketTagging"
        - "s3:DeleteBucketTagging"
        - "sqs:ListQueueTags"
        - "sqs:TagQueue"
        - "sqs:UntagQueue"
        - "kms:ListResourceTags"
        - "kms:TagResource"
        - "kms:UntagResource"
      resources: ["*"]

    - effect: "Allow"
      actions:
        - "sns:Publish"
      resources: ["arn:aws:sns:*:*:exception-expiry-alerts"]

    - effect: "Allow"
      actions:
        - "dynamodb:PutItem"
      resources: ["arn:aws:dynamodb:*:*:table/DataPerimeterExceptionAudit"]

    - effect: "Allow"
      actions:
        - "cloudwatch:PutMetricData"
      resources: ["*"]
```

#### Lambda Implementation

```python
# exception_expiry_enforcer.py
import boto3
import json
import os
from datetime import datetime, timezone, timedelta

GRACE_PERIOD_HOURS = int(os.environ.get("GRACE_PERIOD_HOURS", "0"))
NOTIFICATION_THRESHOLDS = json.loads(os.environ.get("NOTIFICATION_THRESHOLDS", "[30,14,7,1]"))
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
AUDIT_TABLE = os.environ["AUDIT_TABLE"]
ENFORCE_REMOVAL = os.environ.get("ENFORCE_REMOVAL", "true").lower() == "true"

tagging_client = boto3.client("resourcegroupstaggingapi")
iam_client = boto3.client("iam")
sns_client = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")
cloudwatch = boto3.client("cloudwatch")


def handler(event, context):
    """
    Scheduled handler: discover exceptions, enforce expiry, notify stakeholders.
    """
    now = datetime.now(timezone.utc)
    grace_cutoff = now - timedelta(hours=GRACE_PERIOD_HOURS)

    # Step 1: Discover all resources with dp:exception:expiry tag
    exceptions = discover_exceptions()

    metrics = {"active": 0, "expiring_soon": 0, "expired": 0, "revoked": 0}

    for exc in exceptions:
        expiry_date = parse_expiry(exc["tags"].get("dp:exception:expiry"))
        if expiry_date is None:
            continue

        days_until_expiry = (expiry_date - now).days

        if days_until_expiry > max(NOTIFICATION_THRESHOLDS):
            metrics["active"] += 1
            continue

        # Send approaching-expiry notifications
        if days_until_expiry > 0:
            metrics["expiring_soon"] += 1
            if days_until_expiry in NOTIFICATION_THRESHOLDS:
                send_expiry_warning(exc, days_until_expiry)
            continue

        # Exception is expired
        metrics["expired"] += 1

        if expiry_date <= grace_cutoff:
            # Past grace period — revoke
            if ENFORCE_REMOVAL:
                revoke_exception(exc, now)
                metrics["revoked"] += 1
            else:
                log_dry_run(exc)

    # Step 2: Publish CloudWatch metrics
    publish_metrics(metrics)

    return {
        "statusCode": 200,
        "summary": metrics
    }


def discover_exceptions():
    """
    Find all resources and IAM principals tagged with dp:exception:expiry.
    Uses Resource Groups Tagging API for resources, IAM API for principals.
    """
    exceptions = []

    # Discover tagged resources (S3, SQS, KMS, etc.)
    paginator = tagging_client.get_paginator("get_resources")
    for page in paginator.paginate(
        TagFilters=[{"Key": "dp:exception:expiry"}]
    ):
        for resource in page["ResourceTagMappingList"]:
            tags = {t["Key"]: t["Value"] for t in resource["Tags"]}
            exceptions.append({
                "arn": resource["ResourceARN"],
                "type": "resource",
                "tags": tags
            })

    # Discover tagged IAM roles
    roles_paginator = iam_client.get_paginator("list_roles")
    for page in roles_paginator.paginate():
        for role in page["Roles"]:
            role_tags = {t["Key"]: t["Value"] for t in role.get("Tags", [])}
            if "dp:exception:expiry" in role_tags:
                exceptions.append({
                    "arn": role["Arn"],
                    "type": "iam_role",
                    "tags": role_tags
                })

    # Discover tagged IAM users
    users_paginator = iam_client.get_paginator("list_users")
    for page in users_paginator.paginate():
        for user in page["Users"]:
            user_tags = {t["Key"]: t["Value"] for t in user.get("Tags", [])}
            if "dp:exception:expiry" in user_tags:
                exceptions.append({
                    "arn": user["Arn"],
                    "type": "iam_user",
                    "tags": user_tags
                })

    return exceptions


def parse_expiry(value):
    """Parse ISO-8601 date string to datetime."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def revoke_exception(exc, now):
    """
    Remove dp:exception:* tags and leave an audit breadcrumb.
    Tag removal is what deactivates the exception — policies check Null condition
    on dp:exception:id, so removing the tag immediately re-enables the deny.
    """
    exception_id = exc["tags"].get("dp:exception:id", "UNKNOWN")

    # Write audit breadcrumb BEFORE removing tags
    breadcrumb_tags = {
        "dp:exception:revoked-at": now.isoformat(),
        "dp:exception:revoked-id": exception_id
    }
    apply_tags(exc, breadcrumb_tags)

    # Remove all active exception tags
    exception_tag_keys = [k for k in exc["tags"] if k.startswith("dp:exception:") and k not in breadcrumb_tags]
    remove_tags(exc, exception_tag_keys)

    # Write audit record to DynamoDB
    write_audit_record(exc, exception_id, now, action="REVOKED")

    # Send revocation notification
    send_revocation_notice(exc, exception_id)


def apply_tags(exc, tags_dict):
    """Apply tags to a resource or IAM principal."""
    if exc["type"] == "iam_role":
        role_name = exc["arn"].split("/")[-1]
        iam_client.tag_role(
            RoleName=role_name,
            Tags=[{"Key": k, "Value": v} for k, v in tags_dict.items()]
        )
    elif exc["type"] == "iam_user":
        user_name = exc["arn"].split("/")[-1]
        iam_client.tag_user(
            UserName=user_name,
            Tags=[{"Key": k, "Value": v} for k, v in tags_dict.items()]
        )
    else:
        tagging_client.tag_resources(
            ResourceARNList=[exc["arn"]],
            Tags=tags_dict
        )


def remove_tags(exc, tag_keys):
    """Remove tags from a resource or IAM principal."""
    if not tag_keys:
        return
    if exc["type"] == "iam_role":
        role_name = exc["arn"].split("/")[-1]
        iam_client.untag_role(RoleName=role_name, TagKeys=tag_keys)
    elif exc["type"] == "iam_user":
        user_name = exc["arn"].split("/")[-1]
        iam_client.untag_user(UserName=user_name, TagKeys=tag_keys)
    else:
        tagging_client.untag_resources(
            ResourceARNList=[exc["arn"]],
            TagKeys=tag_keys
        )


def send_expiry_warning(exc, days):
    """Send SNS notification for approaching exception expiry."""
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"Data Perimeter Exception Expiring in {days} day(s)",
        Message=json.dumps({
            "event": "EXCEPTION_EXPIRING",
            "exception_id": exc["tags"].get("dp:exception:id"),
            "resource_arn": exc["arn"],
            "days_until_expiry": days,
            "expiry_date": exc["tags"].get("dp:exception:expiry"),
            "approver": exc["tags"].get("dp:exception:approver", "unknown"),
            "justification": exc["tags"].get("dp:exception:justification", "")
        }, indent=2)
    )


def send_revocation_notice(exc, exception_id):
    """Send SNS notification that an exception was revoked."""
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"Data Perimeter Exception {exception_id} REVOKED",
        Message=json.dumps({
            "event": "EXCEPTION_REVOKED",
            "exception_id": exception_id,
            "resource_arn": exc["arn"],
            "action": "Exception tags removed. Deny policies now active."
        }, indent=2)
    )


def write_audit_record(exc, exception_id, now, action):
    """Write audit trail to DynamoDB."""
    table = dynamodb.Table(AUDIT_TABLE)
    table.put_item(Item={
        "exception_id": exception_id,
        "timestamp": now.isoformat(),
        "action": action,
        "resource_arn": exc["arn"],
        "resource_type": exc["type"],
        "original_tags": exc["tags"]
    })


def publish_metrics(metrics):
    """Publish exception lifecycle metrics to CloudWatch."""
    namespace = "DataPerimeter/Exceptions"
    cloudwatch.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": k, "Value": v, "Unit": "Count"}
            for k, v in metrics.items()
        ]
    )


def log_dry_run(exc):
    """Log what would be revoked in dry-run mode."""
    print(json.dumps({
        "dry_run": True,
        "would_revoke": exc["tags"].get("dp:exception:id"),
        "resource_arn": exc["arn"],
        "expiry_date": exc["tags"].get("dp:exception:expiry")
    }))
```

#### How Policies Interact with the Lambda

Policies use **tag presence only** — no date logic:

```
Policy Condition (SCP/RCP):             Lambda Enforcer:
┌─────────────────────────────┐        ┌───────────────────────────┐
│ "Null": {                   │        │ Runs every hour:          │
│   "dp:exception:id": "true" │◄───────│ If expired → remove tags  │
│ }                           │        │ dp:exception:id           │
│                             │        │ dp:exception:expiry       │
│ If tag MISSING → Deny       │        │ dp:exception:justification│
│ If tag PRESENT → Allow      │        │ dp:exception:approver     │
└─────────────────────────────┘        └───────────────────────────┘

Timeline:
  Exception granted     Exception expires       Tags removed
  ─────●───────────────────────●──────────────────●──────────
       │                       │                  │
       │  dp:exception:id      │  Grace period    │  Deny
       │  tag present          │  (configurable)  │  reactivates
       │  → Deny bypassed      │                  │
```

#### Audit Trail Schema (DynamoDB)

```yaml
# DynamoDB table: DataPerimeterExceptionAudit
table:
  name: "DataPerimeterExceptionAudit"
  partition_key: "exception_id"  # String
  sort_key: "timestamp"          # String (ISO-8601)

  attributes:
    - exception_id: "EXC-2026-0042"
    - timestamp: "2027-03-31T01:00:00+00:00"
    - action: "REVOKED"          # CREATED | RENEWED | REVOKED | EXPIRED_WARNING
    - resource_arn: "arn:aws:s3:::sensitive-data-bucket"
    - resource_type: "resource"
    - original_tags:             # Snapshot of tags at time of action
        dp:exception:id: "EXC-2026-0042"
        dp:exception:expiry: "2027-03-31"
        dp:exception:justification: "Partner data sharing"
        dp:exception:approver: "ciso@example.com"

  ttl:
    attribute: "ttl_epoch"
    retention_days: 365          # Keep audit records for 1 year
```

---

## External Access Patterns

### Handling Third-Party Access (KMS-Centric Model)

> **Key principle:** In the KMS-centric model, third-party access requires two
> things: (1) identity perimeter exception via literal account ID in RCP + exception
> tags on the KMS key, and (2) KMS key policy granting the third-party account
> `kms:Decrypt` access. The ABAC SCP doesn't apply to external principals (they
> don't have `dp:*` tags), so the KMS key policy + exception tags are the controls.

#### Scenario 1: Partner Needs Access to Specific S3 Bucket

```yaml
# Intent configuration
third_party_access:
  - partner_name: "Acme Analytics Corp"
    partner_account: "123456789012"

    access_pattern:
      type: "bidirectional_data_exchange"

      inbound:  # Partner accessing our resources
        resources:
          - "arn:aws:s3:::shared-analytics-data/*"
        kms_key: "alias/dp/shared-services/production/partner-acme"
        permissions:
          - "s3:GetObject"
          - "s3:ListBucket"
        conditions:
          source_ip_ranges: ["203.0.113.0/24"]  # Partner's IP range

      outbound:  # Our principals accessing partner resources
        allowed_principals_tag:
          key: "dp:resource:enforcement"
          value: "excluded"
        partner_resources:
          - "arn:aws:s3:::acme-analytics-bucket/*"
        permissions:
          - "s3:PutObject"

    kms_strategy:
      description: >
        Dedicated KMS key for partner data exchange. Tagged with
        dp:data-zone=shared-services so internal principals in that zone
        can also access. Exception tags on the key allow external access.
      key_alias: "alias/dp/shared-services/production/partner-acme"
      key_tags:
        dp:data-zone: "shared-services"
        dp:environment: "production"
        dp:project: "partner-acme"
        dp:exception:id: "EXC-2026-0042"
        dp:exception:expiry: "2027-03-31"
        dp:exception:approver: "ciso@example.com"
        dp:exception:justification: "Partner data sharing - SOW 2026-03-01"
      key_policy_grants:
        - principal: "arn:aws:iam::123456789012:root"
          actions: ["kms:Decrypt", "kms:GenerateDataKey"]
          conditions:
            source_ip: ["203.0.113.0/24"]

    monitoring:
      cloudtrail_insights: true
      guardduty_alerts: true
      access_analyzer_findings: true

    compliance:
      data_residency: "US"
      data_classification: "confidential"
```

#### Generated RCP for S3 Bucket

> Partner account `123456789012` is a literal value in the identity perimeter RCP.
> The KMS key's `dp:exception:id` tag signals approved external access — expiry
> enforced by ExceptionExpiryEnforcer Lambda.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceIdentityPerimeterWithPartnerException",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::shared-analytics-data",
        "arn:aws:s3:::shared-analytics-data/*"
      ],
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:PrincipalOrgID": "${MY_ORG_ID}",
          "aws:PrincipalAccount": ["123456789012"]
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        },
        "NotIpAddressIfExists": {
          "aws:SourceIp": ["203.0.113.0/24"]
        }
      }
    }
  ]
}
```

> **Note:** The partner also needs `kms:Decrypt` on the KMS key to read the
> encrypted data. This is granted via the KMS key policy (not the RCP). When the
> ExceptionExpiryEnforcer Lambda removes `dp:exception:*` tags from the KMS key
> on expiry, the key policy should also be reviewed/revoked.

#### Scenario 2: Service Role Accessing External Resources

> **Note:** External resources use external KMS keys we don't control. The
> service role needs to be excluded from the KMS ABAC check (via
> `dp:kms:enforcement=excluded`) and from the resource perimeter org boundary
> check. Exception tags on the principal enable this with time-bound expiry.

```yaml
# Intent configuration
service_integration:
  - service_name: "DataSync to Partner SFTP"
    our_service_role: "arn:aws:iam::111122223333:role/DataSyncServiceRole"

    exception_scope:
      perimeters: ["resource", "kms"]
      external_targets:
        - "arn:aws:transfer:us-east-1:123456789012:server/s-*"

    tagging_strategy:
      apply_to_role: true
      tags:
        # Exclude from resource perimeter org boundary
        - key: "dp:resource:enforcement"
          value: "excluded"
        # Exclude from KMS ABAC (external KMS keys have no dp:* tags)
        - key: "dp:kms:enforcement"
          value: "excluded"
        # Exception with expiry — managed by ExceptionExpiryEnforcer Lambda
        - key: "dp:exception:id"
          value: "EXC-2026-0015"
        - key: "dp:exception:expiry"
          value: "2027-03-31"
        - key: "dp:exception:justification"
          value: "AWS DataSync to partner SFTP for data migration"
        - key: "dp:exception:approver"
          value: "security-team@example.com"
```

---

## Visibility and Monitoring

### Integration with IAM Access Analyzer

#### Access Analyzer Configuration

```yaml
# access_analyzer_integration.yaml
access_analyzer:
  enabled: true

  analyzers:
    - name: "OrgDataPerimeterAnalyzer"
      type: "ORGANIZATION"

      findings_to_monitor:
        - external_access  # Resources accessible outside org
        - unused_access    # Overly permissive policies
        - external_principals  # External principals with access

      custom_archive_rules:
        - name: "ApprovedThirdPartyExceptions"
          filter:
            - criterion: "resource"
              contains: ["shared-analytics-data"]
            - criterion: "principal.AWS"
              eq: "123456789012"
            - criterion: "resourceTags/dp:exception:id"
              exists: true

      alerts:
        - trigger: "new_external_access_finding"
          severity: "HIGH"
          notification: "sns:arn:aws:sns:us-east-1:111122223333:security-alerts"

        - trigger: "exception_tag_missing"
          condition: "external_access AND NOT resourceTags/dp:exception:id"
          severity: "CRITICAL"
          notification: "sns:arn:aws:sns:us-east-1:111122223333:critical-alerts"
```

#### Automated Compliance Checking

```python
# access_analyzer_compliance.py
import boto3
from datetime import datetime

class DataPerimeterComplianceChecker:
    """
    Validate data perimeter compliance using Access Analyzer
    """

    def __init__(self):
        self.analyzer = boto3.client('accessanalyzer')

    def check_external_access_compliance(self, org_id):
        """
        Identify resources with external access lacking proper exceptions
        """
        findings = self.analyzer.list_findings(
            analyzerArn=f'arn:aws:access-analyzer:us-east-1:{org_id}:analyzer/OrgDataPerimeterAnalyzer',
            filter={
                'status': {'eq': ['ACTIVE']},
                'resourceType': {'eq': ['AWS::S3::Bucket', 'AWS::SQS::Queue', 'AWS::KMS::Key']}
            }
        )

        violations = []

        for finding in findings['findings']:
            # Check if external access has valid exception
            if not self._has_valid_exception(finding):
                violations.append({
                    'resource': finding['resource'],
                    'external_principal': finding['principal'],
                    'finding_id': finding['id'],
                    'severity': 'HIGH',
                    'remediation': 'Add exception tags or remove external access'
                })

        return violations

    def _has_valid_exception(self, finding):
        """
        Check if finding has valid exception tags
        """
        resource_arn = finding['resource']

        # Get resource tags
        tags = self._get_resource_tags(resource_arn)

        # Check for exception tags
        has_exception_id = 'dp:exception:id' in tags
        has_exception_expiry = 'dp:exception:expiry' in tags

        if not (has_exception_id and has_exception_expiry):
            return False

        # Check if exception is expired
        expiry_date = datetime.fromisoformat(tags['dp:exception:expiry'])
        if expiry_date < datetime.now():
            return False

        return True

    def generate_compliance_report(self):
        """
        Generate comprehensive compliance report
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'violations': {
                'identity_perimeter': self.check_identity_perimeter_violations(),
                'resource_perimeter': self.check_resource_perimeter_violations(),
                'network_perimeter': self.check_network_perimeter_violations()
            },
            'exceptions': {
                'active': self.count_active_exceptions(),
                'expiring_soon': self.count_expiring_exceptions(days=30),
                'expired': self.count_expired_exceptions()
            },
            'risk_score': self.calculate_risk_score()
        }

        return report
```

### Integration with Wiz

#### Wiz Query Templates

```graphql
# Wiz Query: Resources with External Access Without Exceptions
query DataPerimeterViolations {
  resources(
    where: {
      cloudPlatform: {equals: AWS}
      hasExternalAccess: {equals: true}
      NOT: {
        tags: {
          some: {
            key: {equals: "dp:exception:id"}
          }
        }
      }
    }
  ) {
    id
    name
    type
    externalAccess {
      principal
      permissions
      conditions
    }
    tags {
      key
      value
    }
    risk {
      score
      factors
    }
  }
}

# Wiz Query: Expired Exceptions Still in Use
query ExpiredExceptions {
  resources(
    where: {
      tags: {
        some: {
          key: {equals: "dp:exception:expiry"}
          value: {lt: "${CURRENT_DATE}"}
        }
      }
      hasExternalAccess: {equals: true}
    }
  ) {
    id
    name
    externalAccess {
      principal
      lastAccessTime
    }
    tags {
      key
      value
    }
  }
}

# Wiz Query: Network Perimeter Violations
query NetworkPerimeterViolations {
  resources(
    where: {
      cloudPlatform: {equals: AWS}
      hasPublicExposure: {equals: true}
      NOT: {
        OR: [
          {tags: {some: {key: {equals: "dp:network:enforcement"}, value: {equals: "excluded"}}}},
          {tags: {some: {key: {equals: "dp:exception:id"}}}}
        ]
      }
    }
  ) {
    id
    name
    type
    publicExposure {
      type
      ports
      cidrs
    }
  }
}
```

#### Wiz Integration Automation

```yaml
# wiz_integration.yaml
wiz_integration:
  enabled: true
  api_endpoint: "https://api.wiz.io/graphql"

  automated_queries:
    - name: "data_perimeter_violations"
      query_file: "data_perimeter_violations.graphql"
      schedule: "rate(1 hour)"

      actions:
        - type: "create_jira_ticket"
          condition: "violations.count > 0"
          priority: "high"

        - type: "send_slack_notification"
          channel: "#security-alerts"

        - type: "trigger_lambda"
          function: "arn:aws:lambda:us-east-1:111122223333:function:RemediatePerimeterViolation"

  compliance_dashboards:
    - name: "Data Perimeter Compliance Overview"
      widgets:
        - type: "metric"
          title: "Active Exceptions"
          query: "count_active_exceptions"

        - type: "metric"
          title: "Violations"
          query: "count_violations"
          threshold: 0

        - type: "table"
          title: "Top 10 Resources at Risk"
          query: "resources_highest_risk"

        - type: "trend"
          title: "Violations Over Time"
          query: "violations_trend"
          period: "30d"
```

### Continuous Monitoring Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     Data Perimeter Monitoring                     │
└──────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
        ┌────────────────────────────────────────────┐
        │         Data Collection Layer              │
        ├────────────────────────────────────────────┤
        │  • CloudTrail API Logs                     │
        │  • IAM Access Analyzer Findings            │
        │  • Wiz Security Graph                      │
        │  • AWS Config Compliance Data              │
        │  • Resource Tag Inventory                  │
        └────────────┬───────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────────────────────┐
        │         Analysis & Correlation             │
        ├────────────────────────────────────────────┤
        │  • Exception Expiry Tracking               │
        │  • Violation Detection                     │
        │  • Anomaly Detection (ML-based)            │
        │  • Compliance Scoring                      │
        └────────────┬───────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────────────────────┐
        │      Alerting & Remediation                │
        ├────────────────────────────────────────────┤
        │  • SNS/Email Alerts                        │
        │  • Slack/PagerDuty Integration             │
        │  • Jira Ticket Creation                    │
        │  • Automated Remediation (Lambda)          │
        └────────────┬───────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────────────────────┐
        │         Dashboards & Reporting             │
        ├────────────────────────────────────────────┤
        │  • CloudWatch Dashboards                   │
        │  • Wiz Security Posture Dashboard          │
        │  • QuickSight Executive Reports            │
        │  • Compliance Audit Reports                │
        └────────────────────────────────────────────┘
```

---

## Implementation Workflow

### Delivery Phase 1: MVP — Foundation (Layers 1 + 2 + 6)

> **Goal:** Enforce CMK encryption everywhere, enable KMS ABAC tag matching,
> and protect classification tags. This is the foundation everything else
> depends on.

```yaml
delivery_phase_1:
  layers:
    - layer_1_cmk_enforcement    # All resources must use CMK
    - layer_2_kms_abac           # KMS tag matching (primary data access gate)
    - layer_6_tag_governance     # Protect dp:* tags from unauthorized mutation

  build:
    - Python policy generator (cli.py, intent_parser.py, policy_generator.py)
    - Policy validator (SCP size limits, JSON structure)
    - Policy splitter (handle >5,120 byte policies)
    - Terraform modules: scp-policies, kms-keys, tag-governance
    - Terraform environments: canary first
    - Unit tests for generator + validator
    - data_perimeter_intent.yaml with OU mapping

  rollout:
    order: ["canary_testing", "shared_services", "business_unit", "internet_facing"]
    steps:
      - Deploy to canary OU in monitoring mode (dp:*:enforcement=monitoring)
      - Validate no disruption with test workloads
      - Switch canary to enforced
      - Roll out to shared_services, then business_unit, then internet_facing
      - Each OU starts in monitoring, then switches to enforced after validation

  deliverables:
    - generator/ — Python CLI that reads intent YAML and outputs JSON policies
    - terraform/modules/scp-policies/ — Layer 1 + Layer 2 SCPs
    - terraform/modules/kms-keys/ — KMS key creation with classification tags
    - terraform/modules/tag-governance/ — Layer 6 SCP
    - terraform/policies/*.json — Generated policy documents
    - tests/ — Unit tests
    - Makefile — generate, validate, plan, apply
```

### Delivery Phase 2: Exception Lifecycle (Layer 5)

> **Goal:** Automate exception expiry enforcement. Until this is built,
> expired exceptions must be manually cleaned up.

```yaml
delivery_phase_2:
  layers:
    - layer_5_exception_enforcer  # Lambda + EventBridge + DynamoDB + SNS

  build:
    - Lambda: exception_expiry_enforcer (discovery, revocation, notifications)
    - Terraform module: exception-enforcer (Lambda, EventBridge rule, DynamoDB audit table, SNS topic)
    - Exception request YAML schema + validation
    - Integration tests (mock AWS APIs)

  deliverables:
    - lambda/exception_expiry_enforcer/ — Lambda function source
    - terraform/modules/exception-enforcer/ — Infrastructure
    - config/exceptions/ — Exception request templates
```

### Delivery Phase 3: Org Boundary + Network Perimeter (Layers 3 + 4)

> **Goal:** Add metadata protection (list/describe ops) and network perimeter.
> These are defense-in-depth layers on top of the KMS ABAC foundation.

```yaml
delivery_phase_3:
  layers:
    - layer_3a_org_boundary        # SCP: only org resources
    - layer_3b_identity_perimeter  # RCP: only org principals
    - layer_4_network_perimeter    # SCP: expected VPCs/CIDRs

  build:
    - Generator templates for org boundary + network perimeter
    - Terraform module: rcp-policies
    - Network perimeter intent config (VPC/CIDR lists)
    - Internet-facing OU exception patterns

  deliverables:
    - terraform/modules/rcp-policies/ — Identity perimeter RCPs
    - Generator templates for Layers 3-4
    - Updated terraform/policies/ with all layers
```

### Operational Phase: Continuous Operation

```yaml
operational_phase:
  activities:
    - Weekly: Lambda reports on exception expiry (automated)
    - Monthly: Review Access Analyzer findings, compliance scoring
    - Quarterly: Policy refinement, KMS key audit, tag hygiene
    - On-demand: Exception requests via YAML → tag application → policy unchanged

  runbooks:
    - "New team onboarding" — create KMS key with tags, tag IAM roles, no policy change
    - "New partner integration" — exception request, KMS key policy grant, literal account ID in RCP
    - "Emergency access revocation" — kms:DisableKey for immediate effect
    - "Policy rollout" — canary → shared_services → business_unit → internet_facing
```

---

## Sample Code Templates

### Template 1: CMK Enforcement SCP (Layer 1 — Prerequisite)

> **Foundation policy (11 statements).** Without CMK enforcement, unencrypted
> resources or AWS-managed keys bypass the KMS ABAC gate entirely. Deploy this
> FIRST. Covers S3, DynamoDB, SQS, SNS, EBS, RDS, EFS, Secrets Manager,
> Kinesis, Redshift, CloudWatch Logs, and KMS key usage. Includes
> `aws:ViaAWSService` bypasses for AWS service-to-service calls (ALB access
> logs, S3 replication, Lambda auto-creating log groups, etc.) and
> service-linked role exclusions.
>
> See [generator/templates/cmk_enforcement.py](generator/templates/cmk_enforcement.py)
> for the canonical implementation. Generated output:
> [terraform/policies/scp-cmk-enforcement.json](terraform/policies/scp-cmk-enforcement.json)
> (3357 bytes, 66% of 5120 limit).

**Statement summary (15 statements):**

| Sid | Service | Condition Key | Notes |
|-----|---------|---------------|-------|
| DenyS3WithoutCMK | s3:PutObject | `s3:x-amz-server-side-encryption` ≠ aws:kms | + ViaAWSService bypass (ALB access logs) |
| DenyS3BucketWithoutDefaultCMK | s3:PutEncryptionConfiguration | `s3:x-amz-server-side-encryption` ≠ aws:kms | |
| DenyDynamoDBWithoutCMK | dynamodb:Create/Update/Restore* | `dynamodb:encryptionType` ≠ CUSTOMER_MANAGED_CMK | |
| DenySQSWithoutCMK | sqs:CreateQueue | `sqs:KmsMasterKeyId` is null | |
| DenySNSWithoutCMK | sns:CreateTopic | `sns:KmsMasterKeyId` is null | |
| DenyEBSWithoutEncryption | ec2:CreateVolume | `ec2:Encrypted` = false | |
| DenyRDSWithoutEncryption | rds:CreateDB*/ReadReplica | `rds:StorageEncrypted` = false | Boolean only — cannot distinguish CMK vs aws/rds |
| DenyEFSWithoutCMK | elasticfilesystem:CreateFileSystem | `elasticfilesystem:Encrypted` = false | |
| DenySecretsManagerWithoutCMK | secretsmanager:CreateSecret | `secretsmanager:KmsKeyId` is null | |
| DenyKinesisWithoutCMK | kinesis:CreateStream/UpdateStreamMode | `kinesis:EncryptionType` ≠ KMS | |
| DenyRedshiftWithoutCMK | redshift:CreateCluster/RestoreFromSnapshot | `redshift:Encrypted` = false | |
| DenyCloudWatchLogsRemoveCMK | logs:DisassociateKmsKey | Unconditional deny | No condition key for KMS at CreateLogGroup |
| DenyCloudWatchLogsCreateWithoutCMK | logs:CreateLogGroup | `dp:logs:cmk-automation` tag gate | + ViaAWSService + SLR bypass |
| DenyNonCMKKeyUsage | kms:Decrypt/Encrypt/GenerateDataKey/... | `aws:ResourceTag/dp:data-zone` is null | Catches aws/s3, aws/ebs managed keys |
| DenyKMSKeyWithoutClassificationTags | kms:CreateKey | `aws:RequestTag/dp:data-zone` is null | Moved to L6 tag governance as well |

### Template 2: KMS ABAC SCP (Layer 2 — Primary Data Access Gate)

> **Static policy — never redeploy.** Uses IAM policy variables to match
> principal tags against KMS key tags. If tags don't match, `kms:Decrypt` is
> denied and the encrypted data is inaccessible. Onboarding = tag KMS key +
> tag IAM role. No policy change needed.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceKMSABACTagMatch",
      "Effect": "Deny",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:GenerateDataKeyPair",
        "kms:GenerateDataKeyPairWithoutPlaintext",
        "kms:ReEncryptFrom",
        "kms:ReEncryptTo",
        "kms:CreateGrant"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:ResourceTag/dp:data-zone": "${aws:PrincipalTag/dp:data-zone}",
          "aws:ResourceTag/dp:environment": "${aws:PrincipalTag/dp:environment}",
          "aws:ResourceTag/dp:project": "${aws:PrincipalTag/dp:project}",
          "aws:PrincipalTag/dp:kms:enforcement": [
            "excluded",
            "monitoring"
          ]
        },
        "Null": {
          "aws:PrincipalTag/dp:exception:id": "true"
        },
        "BoolIfExists": {
          "aws:ViaAWSService": "false"
        },
        "ArnNotLikeIfExists": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*"
        }
      }
    }
  ]
}
```

### Template 3: Org-Boundary SCP (Layer 3a — Metadata Protection)

> **Static policy.** Prevents principals from accessing resources outside the
> org. Covers list/describe operations that don't touch KMS. No ABAC tags
> needed — org ID check only.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceResourcePerimeterOrgBoundary",
      "Effect": "Deny",
      "Action": [
        "s3:*",
        "sqs:*",
        "sns:*",
        "kms:*",
        "lambda:*",
        "secretsmanager:*",
        "ssm:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:ResourceOrgID": "${MY_ORG_ID}"
        },
        "StringNotEqualsIfExists": {
          "aws:PrincipalTag/dp:resource:enforcement": [
            "excluded",
            "monitoring"
          ]
        },
        "Null": {
          "aws:PrincipalTag/dp:exception:id": "true"
        },
        "BoolIfExists": {
          "aws:ViaAWSService": "false"
        },
        "ArnNotLikeIfExists": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*",
          "aws:ResourceArn": [
            "arn:aws:s3:::aws-*",
            "arn:aws:s3:::amazon-*",
            "arn:aws:s3:::jumpstart-cache-prod-*"
          ]
        }
      }
    }
  ]
}
```

### Template 4: Identity Perimeter RCP (Layer 3b — Org Boundary)

> **Static policy.** Third-party account IDs are the only literal values
> (external principals can't be tagged). Exception tags on KMS keys signal
> approved external access.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceIdentityPerimeterOrgBoundary",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:PrincipalOrgID": "${MY_ORG_ID}",
          "aws:ResourceTag/dp:identity:enforcement": [
            "excluded",
            "monitoring"
          ],
          "aws:PrincipalAccount": [
            "${APPROVED_THIRD_PARTY_ACCOUNT_1}",
            "${APPROVED_THIRD_PARTY_ACCOUNT_2}"
          ]
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        },
        "Null": {
          "aws:ResourceTag/dp:exception:id": "true"
        }
      }
    }
  ]
}
```

### Template 5: Network Perimeter SCP (Layer 4 — Literal VPC/CIDR)

> **Semi-static policy.** VPC IDs and CIDRs are literal values (network context
> is not taggable). These change infrequently (infra-level). `aws:ViaAWSService`
> is an exclusion condition on the Deny (SCPs cannot grant permissions).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceNetworkPerimeterExpectedNetworks",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:SourceVpc": [
            "vpc-aaa111",
            "vpc-bbb222",
            "vpc-ccc333"
          ],
          "aws:PrincipalTag/dp:network:enforcement": [
            "excluded",
            "monitoring"
          ]
        },
        "NotIpAddressIfExists": {
          "aws:SourceIp": [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "203.0.113.0/24"
          ]
        },
        "BoolIfExists": {
          "aws:ViaAWSService": "false"
        },
        "Null": {
          "aws:PrincipalTag/dp:exception:id": "true"
        },
        "ArnNotLikeIfExists": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*"
        }
      }
    }
  ]
}
```

### Template 6: Tag Governance SCP

> **Protects classification tags on KMS keys and IAM principals.** Only
> security-admin and platform-engineering teams can mutate dp:* tags.
> KMS key creation requires classification tags.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProtectDataPerimeterTags",
      "Effect": "Deny",
      "Action": [
        "kms:TagResource",
        "kms:UntagResource",
        "iam:TagRole",
        "iam:UntagRole",
        "iam:TagUser",
        "iam:UntagUser"
      ],
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringLike": {
          "aws:TagKeys": [
            "dp:exception:*",
            "dp:*:enforcement",
            "dp:data-zone",
            "dp:environment",
            "dp:project",
            "dp:data-classification",
            "dp:compliance-scope"
          ]
        },
        "StringNotEquals": {
          "aws:PrincipalTag/team": [
            "security-admin",
            "platform-engineering"
          ]
        },
        "ArnNotLikeIfExists": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*"
        }
      }
    },
    {
      "Sid": "RequireKMSKeyDataZoneTag",
      "Effect": "Deny",
      "Action": "kms:CreateKey",
      "Resource": "*",
      "Condition": {
        "Null": {
          "aws:RequestTag/dp:data-zone": "true"
        }
      }
    },
    {
      "Sid": "RequireKMSKeyEnvironmentTag",
      "Effect": "Deny",
      "Action": "kms:CreateKey",
      "Resource": "*",
      "Condition": {
        "Null": {
          "aws:RequestTag/dp:environment": "true"
        }
      }
    },
    {
      "Sid": "RequireKMSKeyProjectTag",
      "Effect": "Deny",
      "Action": "kms:CreateKey",
      "Resource": "*",
      "Condition": {
        "Null": {
          "aws:RequestTag/dp:project": "true"
        }
      }
    }
  ]
}
```

---

## Appendix: Reference Architecture Diagrams

### Complete Data Perimeter Policy Flow — KMS-Centric Model

```
┌─────────────────────────────────────────────────────────────────┐
│                  Intent Configuration (YAML)                     │
│  • Organization boundaries                                       │
│  • KMS key-to-zone mapping (alias/dp/{zone}/{env}/{project})     │
│  • Exception definitions                                         │
│  • VPC/CIDR lists (network perimeter only)                       │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Policy Generation Engine                        │
│  • Generate Layer 1: CMK enforcement SCPs                        │
│  • Generate Layer 2: KMS ABAC SCP (static — policy variables)    │
│  • Generate Layer 3: Org-boundary SCPs/RCPs                      │
│  • Generate Layer 4: Network perimeter SCP (literal VPC/CIDRs)   │
│  • Generate Layer 6: Tag governance SCP                          │
└────────────────────────┬────────────────────────────────────────┘
                         │
       ┌─────────────────┼─────────────────────────┐
       ▼                 ▼                         ▼
┌──────────────┐  ┌─────────────┐  ┌────────────────────────────┐
│ SCPs (L1-4)  │  │  RCPs (L3)  │  │ ExceptionExpiryEnforcer    │
│ • CMK enforce│  │ • Identity  │  │ Lambda (L5)                │
│ • KMS ABAC   │  │   perimeter │  │ • Scans dp:exception tags  │
│ • Org bound. │  │             │  │   on KMS keys + principals │
│ • Network    │  │             │  │ • Removes expired tags     │
│ • Tag govern.│  │             │  │ • Sends notifications      │
└──────┬───────┘  └──────┬──────┘  └────────────┬───────────────┘
       │                 │                      │
       └─────────────────┼──────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Runtime Enforcement                             │
│                                                                  │
│  Request: s3:GetObject on CMK-encrypted bucket                   │
│    1. Layer 1: Was bucket created with CMK? (preventive)         │
│    2. Layer 3: Is resource in org? (org boundary)                │
│    3. Layer 4: Is request from expected network? (VPC/CIDR)      │
│    4. Layer 2: Does principal's dp:data-zone match KMS key's     │
│       dp:data-zone? (KMS ABAC — this is the primary gate)       │
│    5. Layer 5: Does KMS key have dp:exception:id tag?            │
│       (exception still active? Lambda hasn't removed it yet?)    │
│    → All pass? ALLOW. Any fail? DENY.                            │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│               Monitoring & Compliance                            │
│  • Access Analyzer findings (→ compliance reporter Lambda)       │
│  • Wiz security graph analysis (→ tag remediation webhook)       │
│  • CloudTrail KMS deny events (Athena named queries)             │
│  • Exception lifecycle metrics (CloudWatch dashboard)            │
│  • DynamoDB audit trail for exception revocations                │
│  • Compliance metrics: DataPerimeter/Compliance namespace        │
│  • Remediation metrics: DataPerimeter/Remediation namespace      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│               Auto-Remediation                                   │
│                                                                  │
│  Wiz detects untagged KMS key                                    │
│    → Wiz Automation webhook POST                                 │
│    → API Gateway (API key auth)                                  │
│    → Tag Remediation Lambda                                      │
│      1. Extract KMS key ARN + account ID from Wiz payload        │
│      2. GET Tag Lookup API /accounts/{account_id} → dp:* tags    │
│      3. Apply missing dp:data-zone/environment/project to key    │
│      4. SNS notification + CloudWatch metric                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Conclusion

This specification defines a KMS-centric data perimeter framework for AWS using ABAC, SCP/RCP policies, and out-of-band exception management. Key benefits:

1. **KMS as universal choke point**: Tag KMS keys and IAM principals — not thousands of individual resources. All encrypted data access flows through KMS ABAC
2. **Static policies**: KMS ABAC SCP uses IAM policy variables (`${aws:PrincipalTag/...}`). Onboarding new teams/zones/projects = tag both sides. No policy redeployment
3. **Auditability**: All exceptions tracked with IDs, justifications, expiry dates on KMS keys. DynamoDB audit trail for revocations
4. **Automated lifecycle**: ExceptionExpiryEnforcer Lambda removes expired tags. Tag removal immediately reactivates deny — no policy regeneration needed
5. **Defense in depth**: Five layers (CMK enforcement → KMS ABAC → org boundary → network → exception lifecycle) with clear separation of concerns
6. **Visibility**: Deep integration with Access Analyzer, Wiz, CloudTrail KMS logs, and CloudWatch metrics

Implement this framework iteratively: Layer 1 (CMK enforcement) first, then Layer 2 (KMS ABAC in monitoring mode), then Layers 3-4, and finally Layer 5 (exception automation).
