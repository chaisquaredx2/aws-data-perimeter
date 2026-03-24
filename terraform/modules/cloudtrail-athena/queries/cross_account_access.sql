-- Cross-Account Access Patterns
--
-- Identifies API calls where the calling principal is in a different
-- account than the target resource. Helps detect unexpected cross-account
-- access that the org boundary SCP should be catching.

SELECT
    useridentity.accountid AS source_account,
    recipientaccountid AS target_account,
    eventsource,
    eventname,
    count(*) AS call_count,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM ${database}.cloudtrail_logs
WHERE recipientaccountid != useridentity.accountid
  AND errorcode IS NULL
  AND eventsource IN (
    's3.amazonaws.com',
    'kms.amazonaws.com',
    'sqs.amazonaws.com',
    'sns.amazonaws.com',
    'lambda.amazonaws.com',
    'secretsmanager.amazonaws.com'
  )
  AND date_partition >= date_format(current_date - interval '7' day, '%Y/%m/%d')
GROUP BY
    useridentity.accountid,
    recipientaccountid,
    eventsource,
    eventname
ORDER BY call_count DESC
LIMIT 500;
