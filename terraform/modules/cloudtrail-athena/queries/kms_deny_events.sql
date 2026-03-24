-- KMS Deny Events — Data Perimeter Policy Enforcement
--
-- Finds AccessDenied events on KMS operations caused by data perimeter
-- SCP statements. Use this to identify principals hitting policy denials
-- and validate that enforcement is working correctly.

SELECT
    eventtime,
    useridentity.arn AS principal_arn,
    useridentity.accountid AS account_id,
    eventname,
    requestparameters,
    errormessage,
    sourceipaddress,
    recipientaccountid
FROM ${database}.cloudtrail_logs
WHERE eventsource = 'kms.amazonaws.com'
  AND errorcode = 'AccessDenied'
  AND (
    errormessage LIKE '%EnforceKMSABACTagMatch%'
    OR errormessage LIKE '%DenyNonCMKKeyUsage%'
    OR errormessage LIKE '%DenyKMSKeyWithoutClassificationTags%'
  )
  AND date_partition >= date_format(current_date - interval '7' day, '%Y/%m/%d')
ORDER BY eventtime DESC
LIMIT 1000;
