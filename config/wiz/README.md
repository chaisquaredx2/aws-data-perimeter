# Wiz Integration — Data Perimeter Queries

Reference GraphQL queries for monitoring data perimeter compliance via Wiz Security Graph. These are **not** deployed automatically — import them as saved queries in the Wiz console.

## Setup

1. **Wiz Connector**: Ensure your AWS Organization is connected to Wiz via a Wiz Connector with read access to IAM, S3, KMS, SQS, SNS, and resource tags.

2. **Import queries**: In Wiz Console > Security Graph > Saved Queries, create a new query for each `.graphql` file in this directory.

3. **Automations** (optional): In Wiz Console > Automations, create rules that trigger on query results:
   - `data_perimeter_violations.graphql` -> JIRA ticket (P2) + Slack channel
   - `expired_exceptions.graphql` -> JIRA ticket (P1) + Slack + PagerDuty
   - `network_perimeter_violations.graphql` -> Slack channel

4. **KMS tag remediation webhook** (optional): Auto-tag untagged KMS keys detected by Wiz.

   After deploying the `tag-remediation` Terraform module, configure a Wiz Automation:

   1. In Wiz Console > Automations, create a new Automation
   2. Trigger: use the `data_perimeter_violations.graphql` query filtered to `AWS::KMS::Key`
   3. Action: **Webhook**
   4. URL: the `api_gateway_url` output from the `tag-remediation` module
   5. Headers: `x-api-key: <value>` — retrieve with:
      ```bash
      aws apigateway get-api-key --api-key <api_key_id output> --include-value --query 'value' --output text
      ```
   6. Schedule: Hourly

   The Lambda will fetch the account's `dp:*` tags from the Tag Lookup API and apply them to the untagged KMS key automatically.

## Queries

| File | Purpose | Suggested schedule |
|------|---------|-------------------|
| `data_perimeter_violations.graphql` | Resources with external access lacking `dp:exception:id` tag | Hourly |
| `expired_exceptions.graphql` | Resources with expired exception dates still showing external access | Hourly |
| `network_perimeter_violations.graphql` | Resources with public exposure lacking enforcement tag or exception | Daily |

## Tag conventions

These queries rely on the data perimeter tag taxonomy:

- `dp:exception:id` — approved exception identifier
- `dp:exception:expiry` — ISO date when exception expires
- `dp:data-zone` — data classification zone
- `dp:*:enforcement` — per-layer enforcement mode (`excluded`, `monitoring`)
