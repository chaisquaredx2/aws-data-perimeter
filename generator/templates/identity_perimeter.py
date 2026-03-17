"""Layer 3b: Identity Perimeter RCP — restrict who can access org resources.

Org-boundary check applied to resources. Third-party accounts use literal IDs
(external principals can't be tagged). Exception tags on KMS keys signal
approved external access.

This is an RCP (Resource Control Policy), not an SCP.
"""


def generate(config) -> dict:
    """Generate Layer 3b identity perimeter RCP."""
    condition = {
        "StringNotEqualsIfExists": {
            "aws:PrincipalOrgID": config.org_id,
            "aws:ResourceTag/dp:identity:enforcement": [
                "excluded",
                "monitoring",
            ],
        },
        "BoolIfExists": {
            "aws:PrincipalIsAWSService": "false",
        },
        "Null": {
            "aws:ResourceTag/dp:exception:id": "true",
        },
    }

    # Third-party accounts: literal IDs (can't tag external principals)
    third_party_accounts = []
    for exc in config.identity_perimeter.exceptions:
        if exc.type == "third_party_integration":
            third_party_accounts.extend(exc.principal_accounts)

    if third_party_accounts:
        condition["StringNotEqualsIfExists"]["aws:PrincipalAccount"] = (
            third_party_accounts
        )

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnforceIdentityPerimeterOrgBoundary",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "*",
                "Resource": "*",
                "Condition": condition,
            }
        ],
    }
