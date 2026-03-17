"""Layer 4: Network Perimeter SCP — enforce expected network origins.

Literal VPC/CIDR values — the only semi-static policy. Network context
(aws:SourceVpc, aws:SourceIp) is not taggable, so values are hardcoded.
Changes infrequently (infrastructure-level).
"""


def generate(config) -> dict:
    """Generate Layer 4 network perimeter SCP."""
    vpc_list = config.network_perimeter.allowed_vpcs
    cidr_list = config.network_perimeter.expected_networks.corporate_cidrs

    condition = {
        "BoolIfExists": {
            "aws:ViaAWSService": "false",
        },
        "Null": {
            "aws:PrincipalTag/dp:exception:id": "true",
        },
        "StringNotEqualsIfExists": {
            "aws:PrincipalTag/dp:network:enforcement": [
                "excluded",
                "monitoring",
            ],
        },
        "ArnNotLikeIfExists": {
            "aws:PrincipalArn": "arn:aws:iam::*:role/aws-service-role/*",
        },
    }

    if vpc_list:
        condition["StringNotEqualsIfExists"]["aws:SourceVpc"] = vpc_list

    if cidr_list:
        condition["NotIpAddressIfExists"] = {
            "aws:SourceIp": cidr_list,
        }

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnforceNetworkPerimeterExpectedNetworks",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": condition,
            }
        ],
    }
