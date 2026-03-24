# CLAUDE.md — Project Instructions for Claude Code

## Project Overview

KMS-centric AWS data perimeter framework. Python policy generator reads intent YAML, produces SCP/RCP JSON policies, deployed via Terraform. Six enforcement layers plus observability tooling.

## Documentation Requirements

After EVERY code change, you MUST update the following files if relevant:

### spec-requirements.md
- Update architecture diagrams or descriptions if structure changes
- Update API contracts if interfaces change
- Update data flow descriptions if logic changes
- Update technology decisions if new deps are added
- Update policy template JSON examples if policy logic changes
- Update pseudocode sections if generator logic changes
- Update the Policy Layer Summary table if layers are added/removed/modified

### README.md
- Keep setup/installation steps current
- Update usage examples if CLI args or APIs change
- Update environment variable documentation
- Update any feature lists
- Update the repository structure tree if files/directories are added or removed
- Update the "Common tasks" section if new workflows are introduced
- Update the "Key design decisions" section if architectural patterns change

## Build and Test Commands

```bash
make generate    # Generate policies from config/data_perimeter_intent.yaml
make validate    # Validate generated JSON (size, structure, SCP rules)
make test        # Run all tests (pytest)
make plan        # Generate + validate + terraform plan (canary)
make apply       # Generate + validate + terraform apply (canary)
make clean       # Remove generated policy JSON files
```

Run tests before committing:
```bash
python -m pytest tests/ -v
```

## Project Structure

- `generator/` — Python policy generator (cli, intent_parser, policy_generator, policy_validator, policy_splitter)
- `generator/templates/` — One Python module per policy layer (cmk_enforcement, kms_abac, org_boundary, identity_perimeter, network_perimeter, tag_governance)
- `lambda/exception_expiry_enforcer/` — L5 exception lifecycle Lambda
- `lambda/compliance_reporter/` — Observability Lambda (Access Analyzer -> CloudWatch metrics)
- `lambda/tag_remediation/` — Remediation Lambda (Wiz webhook -> auto-tag KMS keys via Tag Lookup API)
- `terraform/modules/` — Terraform modules (scp-policies, rcp-policies, kms-keys, exception-enforcer, access-analyzer, cloudwatch-dashboard, cloudtrail-athena, compliance-reporter, tag-remediation)
- `terraform/environments/canary/` — First deployment target
- `terraform/policies/` — Generated JSON policy files (git-tracked, do not hand-edit)
- `config/data_perimeter_intent.yaml` — Organization config (org ID, VPCs, CIDRs, exceptions)
- `config/exceptions/` — Exception request template and JSON schema
- `config/wiz/` — Wiz GraphQL query templates (docs only)
- `tests/` — pytest test suite

## Code Patterns

- **Policy templates** (`generator/templates/*.py`): Each exports a `generate(config) -> dict` function that returns a policy document. All statements use `Effect: Deny` with exclusion conditions.
- **Lambda handlers**: Use `_get_clients()` factory for boto3 clients (testability via mocking). Environment variables for config. Module-level constants parsed at import time.
- **Tests**: Use `importlib.reload` + `monkeypatch.setenv` for Lambda handler tests (env vars parsed at module level). Mock AWS clients via `_make_clients()` helper.
- **Terraform modules**: Follow `variables.tf` / `main.tf` / `outputs.tf` pattern. Use `count` with feature flag variables for optional modules.

## Key Constraints

- SCP size limit: 5,120 bytes max per policy. The splitter handles oversized policies automatically.
- All SCP statements must be `Effect: Deny` (SCPs cannot grant permissions).
- Include `aws:ViaAWSService: "false"` bypass on deny statements that could block AWS service-to-service calls (ALB -> S3, S3 replication, Lambda auto-creating log groups, etc.).
- Include `ArnNotLikeIfExists` on `arn:aws:iam::*:role/aws-service-role/*` for service-linked role exclusions where relevant.
- `terraform/policies/*.json` files are generated output — always regenerate via `make generate`, never hand-edit.
- Lambda source directories use `handler.py` as the entry point with `handler(event, context)` function.
