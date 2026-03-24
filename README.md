# AWS Data Perimeter

A KMS-centric data perimeter framework for AWS. Instead of writing access rules on every S3 bucket, SQS queue, or DynamoDB table, this framework forces all sensitive data through CMK encryption and controls access at the KMS layer using tag-based policies (ABAC).

**Tag both sides, access flows. No policy redeployment needed.**

## How it works

All sensitive data must be encrypted with a Customer Managed Key (CMK). Each CMK is tagged with a data zone, environment, and project. IAM principals are tagged with the same dimensions. When a principal tries to decrypt data, AWS evaluates SCP conditions that compare the principal's tags against the KMS key's tags. If they don't match, access is denied.

This means onboarding a new team or granting cross-zone access is a tagging operation, not a policy change.

### The six enforcement layers

```
Request flow:
  Principal  ──>  Network check  ──>  Org boundary  ──>  CMK gate  ──>  KMS ABAC  ──>  Data
                       L4               L3a/L3b            L1              L2
```

| Layer | Policy | What it does |
|-------|--------|-------------|
| **L1** CMK Enforcement | SCP (15 statements) | Blocks resource creation without CMK encryption. Covers S3, DynamoDB, SQS, SNS, EBS, RDS, EFS, Secrets Manager, Kinesis, Redshift, CloudWatch Logs, and KMS managed key usage |
| **L2** KMS ABAC | SCP (static) | Denies `kms:Decrypt` unless principal tags match KMS key tags. This is the primary data access gate. Never needs redeployment |
| **L3a** Org Boundary | SCP | Prevents principals from touching resources outside your AWS Organization |
| **L3b** Identity Perimeter | RCP | Prevents external principals from accessing your resources (with approved third-party exceptions) |
| **L4** Network Perimeter | SCP | Restricts API calls to expected VPCs and CIDRs |
| **L5** Exception Lifecycle | Lambda | Scans `dp:exception:*` tags, sends expiry alerts, auto-removes expired exceptions |
| **L6** Tag Governance | SCP | Locks down who can modify `dp:*` classification tags on KMS keys and IAM principals |

### Why KMS-centric?

Traditional data perimeters require policies on every resource. This doesn't scale. With KMS-centric enforcement:

- **One CMK covers many resources** -- an S3 bucket, its DynamoDB metadata table, and its SQS notification queue can all share one CMK
- **Access is implicit** -- if your tags match the key's tags, you can decrypt. No bucket policies, no resource policies
- **Revocation is instant** -- disable a KMS key or remove an exception tag, and all resources using that key become inaccessible immediately

## Repository structure

```
config/
  data_perimeter_intent.yaml     # Your org config: org ID, VPCs, CIDRs, exceptions
  exceptions/                    # Exception request template and JSON schema

generator/                       # Python policy generator
  cli.py                         # CLI: generate and validate commands
  intent_parser.py               # Parses intent YAML into typed config
  policy_generator.py            # Orchestrates all 6 layer generators
  policy_validator.py            # Validates JSON size, structure, SCP rules
  policy_splitter.py             # Auto-splits policies exceeding 5120 byte limit
  templates/                     # One Python module per policy layer
    cmk_enforcement.py           # L1: 11 deny statements for CMK enforcement
    kms_abac.py                  # L2: ABAC tag-matching deny
    org_boundary.py              # L3a: org ID boundary check
    identity_perimeter.py        # L3b: RCP for external principal control
    network_perimeter.py         # L4: VPC/CIDR enforcement
    tag_governance.py            # L6: tag mutation protection

lambda/
  exception_expiry_enforcer/     # L5: Lambda that manages exception lifecycle
    handler.py
  compliance_reporter/           # Observability: Access Analyzer -> CloudWatch metrics
    handler.py
  tag_remediation/               # Remediation: Wiz webhook -> auto-tag KMS keys
    handler.py

terraform/
  policies/                      # Generated JSON policy files (git-tracked)
  modules/
    scp-policies/                # Attaches SCPs to OUs
    rcp-policies/                # Attaches RCPs to OUs
    kms-keys/                    # Creates tagged CMKs
    exception-enforcer/          # Lambda + EventBridge + DynamoDB audit table
    access-analyzer/             # IAM Access Analyzer + EventBridge -> SNS
    cloudwatch-dashboard/        # Single-pane-of-glass dashboard
    cloudtrail-athena/           # Pre-built Athena queries for CloudTrail
    compliance-reporter/         # Lambda: Access Analyzer findings -> metrics
    tag-remediation/             # API Gateway + Lambda: Wiz webhook -> KMS tagging
  environments/
    canary/                      # First deployment target

config/
  data_perimeter_intent.yaml     # Your org config
  exceptions/                    # Exception request template and schema
  wiz/                           # Wiz GraphQL query templates + webhook setup guide

tests/                           # 129 tests covering generators, Lambdas, and remediation
```

## Getting started

### Prerequisites

- Python 3.12+
- Terraform 1.5+
- AWS CLI configured with Organizations management account access

### Install

```bash
pip install -e ".[dev]"
```

### Configure your organization

Edit `config/data_perimeter_intent.yaml` with your actual values:

```yaml
organization:
  id: "o-your-org-id"
  name: "Your Company"

perimeter_configuration:
  network_perimeter:
    expected_networks:
      corporate_cidrs:
        - "10.0.0.0/8"
      allowed_vpcs:
        - "vpc-abc123"

  identity_perimeter:
    exceptions:
      - type: "third_party_integration"
        principal_accounts: ["999888777666"]
        justification: "Partner data sharing"
        expiry: "2027-12-31"
```

### Generate and deploy

```bash
# Generate policies from your intent config
make generate

# Validate generated JSON (size limits, structure, SCP rules)
make validate

# Run tests
make test

# Deploy to canary OU first
make plan    # review the Terraform plan
make apply   # deploy to canary
```

## Common tasks

### "I need to onboard a new team"

No policy changes required. Tag the KMS key and the IAM roles:

```bash
# Tag the KMS key with the team's data zone
aws kms tag-resource --key-id alias/dp/finance/prod/reporting \
  --tags TagKey=dp:data-zone,TagValue=finance \
         TagKey=dp:environment,TagValue=prod \
         TagKey=dp:project,TagValue=reporting

# Tag the team's IAM role with matching dimensions
aws iam tag-role --role-name FinanceAnalystRole \
  --tags Key=dp:data-zone,Value=finance \
         Key=dp:environment,Value=prod \
         Key=dp:project,Value=reporting
```

Tags match -> decryption allowed. No redeployment.

### "I need to add a new service to CMK enforcement"

1. Edit the relevant template in `generator/templates/`. For example, to add a new service to L1:

   ```python
   # generator/templates/cmk_enforcement.py
   statements.append({
       "Sid": "DenyNewServiceWithoutCMK",
       "Effect": "Deny",
       "Action": "newservice:CreateResource",
       "Resource": "*",
       "Condition": {
           # Use the service's encryption condition key
           "StringNotEqualsIfExists": {
               "newservice:EncryptionType": "CUSTOMER_MANAGED_CMK",
           },
       },
   })
   ```

2. Add tests in `tests/test_policy_generator.py`
3. Regenerate and validate:
   ```bash
   make generate
   make validate
   make test
   ```
4. Review the diff in `terraform/policies/` and deploy

### "I need to grant a third-party account temporary access"

1. Copy `config/exceptions/exception_template.yaml` and fill it in
2. Get security team approval
3. Apply the exception tags to the KMS key:
   ```bash
   aws kms tag-resource --key-id alias/dp/shared/prod/partner-data \
     --tags TagKey=dp:exception:id,TagValue=EXC-2026-0042 \
            TagKey=dp:exception:expiry,TagValue=2027-03-31 \
            TagKey=dp:exception:justification,TagValue="Partner data sharing per SOW-123"
   ```
4. Add the account ID to `identity_perimeter.exceptions` in the intent YAML
5. Regenerate the identity perimeter RCP:
   ```bash
   make generate
   ```
6. Deploy. The Lambda (L5) will auto-remove the exception tags when they expire.

### "I need to update network perimeters (new VPC or CIDR)"

1. Edit `config/data_perimeter_intent.yaml`:
   ```yaml
   network_perimeter:
     expected_networks:
       allowed_vpcs:
         - "vpc-abc123"
         - "vpc-new456"    # add the new VPC
   ```
2. Regenerate and deploy:
   ```bash
   make generate && make plan
   ```

### "A policy is too large (> 5120 bytes)"

The generator auto-splits oversized policies. If a single policy exceeds the SCP size limit, `policy_splitter.py` breaks it into numbered parts (`scp-cmk-enforcement-part1.json`, `scp-cmk-enforcement-part2.json`). Both parts get attached to the same OU by Terraform.

## Deployment strategy

Policies roll out in order: **canary -> shared_services -> business_unit -> internet_facing**

```
1. Generate policies          make generate
2. Validate                   make validate
3. Deploy to canary OU        make apply
4. Monitor for 24-48h         Check CloudTrail for unexpected denies
5. Promote to next OU         Create environment config, repeat
```

The exception enforcer Lambda starts in **dry-run mode** (`enforce_removal = false`) in canary. It logs what it would do without actually removing tags. Flip to `true` after validation.

## Testing

```bash
# Run all 129 tests
make test

# Run specific test class
python -m pytest tests/test_policy_generator.py::TestCMKEnforcement -v

# Run with coverage
python -m pytest tests/ --cov=generator --cov-report=term-missing
```

## Key design decisions

- **SCPs are Deny-only** -- they cannot grant permissions, only restrict. Every statement uses `Effect: Deny` with exclusion conditions (e.g., `StringNotEqualsIfExists`) to carve out allowed paths
- **`aws:ViaAWSService` bypasses** -- AWS services making calls on your behalf (ALB writing access logs, S3 replication, Lambda creating log groups) are excluded from deny rules to avoid breaking AWS-managed workflows
- **Service-linked role exclusions** -- AWS Organizations tag policies, Service Catalog, and other AWS services that use service-linked roles are excluded via `ArnNotLikeIfExists` on `arn:aws:iam::*:role/aws-service-role/*`
- **Exception tags live on KMS keys, not resources** -- one KMS key covers all resources encrypted with it. Revoking an exception = removing one tag, not updating dozens of resource policies
- **L2 (KMS ABAC) is static** -- uses IAM policy variables (`${aws:PrincipalTag/dp:data-zone}`) so it never needs redeployment. All access control changes happen through tagging
