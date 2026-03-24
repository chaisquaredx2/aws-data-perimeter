-- Exception Usage — Active Exception Tag Consumption
--
-- Finds successful API calls by principals that have dp:exception:id
-- in their session context. Helps identify which exceptions are actively
-- being used (and which can potentially be retired).

SELECT
    useridentity.arn AS principal_arn,
    useridentity.accountid AS account_id,
    eventsource,
    eventname,
    count(*) AS call_count,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM ${database}.cloudtrail_logs
WHERE errorcode IS NULL
  AND useridentity.principalid IS NOT NULL
  AND json_extract_scalar(
    json_format(cast(requestparameters AS json)),
    '$.tags'
  ) LIKE '%dp:exception:id%'
  AND date_partition >= date_format(current_date - interval '30' day, '%Y/%m/%d')
GROUP BY
    useridentity.arn,
    useridentity.accountid,
    eventsource,
    eventname
ORDER BY call_count DESC
LIMIT 500;
