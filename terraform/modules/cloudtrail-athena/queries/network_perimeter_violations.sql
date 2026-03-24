-- Network Perimeter Violations
--
-- Finds AccessDenied events caused by the network perimeter SCP,
-- grouped by source IP. Helps identify calls from unexpected networks.

SELECT
    sourceipaddress,
    useridentity.arn AS principal_arn,
    useridentity.accountid AS account_id,
    eventsource,
    eventname,
    count(*) AS deny_count,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM ${database}.cloudtrail_logs
WHERE errorcode = 'AccessDenied'
  AND errormessage LIKE '%EnforceNetworkPerimeterExpectedNetworks%'
  AND date_partition >= date_format(current_date - interval '7' day, '%Y/%m/%d')
GROUP BY
    sourceipaddress,
    useridentity.arn,
    useridentity.accountid,
    eventsource,
    eventname
ORDER BY deny_count DESC
LIMIT 500;
