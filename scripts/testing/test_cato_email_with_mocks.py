#!/usr/bin/env python3
"""
Test script to run a NIST 800-53 cATO email with mock data
"""

import json
import os
from unittest.mock import MagicMock, patch

import boto3

from src.app import analyze_findings, generate_csv, send_email
from src.mapper_factory import MapperFactory

# Set environment variables needed for the function
os.environ["SENDER_EMAIL"] = "alexanderjyawn@gmail.com"
os.environ["RECIPIENT_EMAIL"] = "ajyawn27@gmail.com"
os.environ["BEDROCK_MODEL_ID"] = "anthropic.claude-3-sonnet-20240229-v1:0"

# Mock NIST 800-53 findings
mock_findings = [
    {
        "SchemaVersion": "2018-10-08",
        "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/abcdef-1234-5678-90ab-cdef12345678",
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "ProductName": "Security Hub",
        "CompanyName": "AWS",
        "Region": "us-east-1",
        "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/S3.1",
        "AwsAccountId": "123456789012",
        "Types": ["Software and Configuration Checks"],
        "FirstObservedAt": "2025-02-26T00:00:00Z",
        "LastObservedAt": "2025-02-26T01:00:00Z",
        "CreatedAt": "2025-02-26T00:00:00Z",
        "UpdatedAt": "2025-02-26T01:00:00Z",
        "Severity": {"Product": 70, "Label": "HIGH"},
        "Title": "S3.1 S3 buckets should have server-side encryption enabled",
        "Description": "This AWS control checks if S3 buckets have server-side encryption enabled.",
        "ProductFields": {
            "StandardsControlArn": "arn:aws:securityhub:us-east-1:123456789012:control/nist-800-53/v/5.0.0/SC-28",
            "RecommendationUrl": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-s3-1",
            "StandardsGuideArn": "arn:aws:securityhub:us-east-1:123456789012:standards/aws-foundational-security-best-practices/v/1.0.0",
            "RecordState": "ACTIVE",
            "WorkflowStatus": "NEW",
            "Compliance.Status": "FAILED",
        },
        "Resources": [
            {
                "Type": "AwsS3Bucket",
                "Id": "arn:aws:s3:::example-bucket-123",
                "Partition": "aws",
                "Region": "us-east-1",
                "Details": {
                    "AwsS3Bucket": {
                        "Name": "example-bucket-123",
                        "CreatedAt": "2023-01-01T00:00:00Z",
                    }
                },
            }
        ],
    },
    {
        "SchemaVersion": "2018-10-08",
        "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.4/finding/abcdef-1234-5678-90ab-cdef12345679",
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "ProductName": "Security Hub",
        "CompanyName": "AWS",
        "Region": "us-east-1",
        "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/IAM.4",
        "AwsAccountId": "123456789012",
        "Types": ["Software and Configuration Checks", "Policy"],
        "FirstObservedAt": "2025-02-26T00:00:00Z",
        "LastObservedAt": "2025-02-26T01:00:00Z",
        "CreatedAt": "2025-02-26T00:00:00Z",
        "UpdatedAt": "2025-02-26T01:00:00Z",
        "Severity": {"Product": 90, "Label": "CRITICAL"},
        "Title": "IAM.4 IAM root user access key should not exist",
        "Description": "This AWS control checks if the root user access key is available.",
        "ProductFields": {
            "StandardsControlArn": "arn:aws:securityhub:us-east-1:123456789012:control/nist-800-53/v/5.0.0/AC-6",
            "RecommendationUrl": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-iam-4",
            "StandardsGuideArn": "arn:aws:securityhub:us-east-1:123456789012:standards/aws-foundational-security-best-practices/v/1.0.0",
            "RecordState": "ACTIVE",
            "WorkflowStatus": "NEW",
            "Compliance.Status": "FAILED",
        },
        "Resources": [
            {
                "Type": "AwsIamUser",
                "Id": "AWS::::Account:123456789012",
                "Partition": "aws",
                "Region": "us-east-1",
            }
        ],
    },
    {
        "SchemaVersion": "2018-10-08",
        "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/CloudTrail.2/finding/abcdef-1234-5678-90ab-cdef12345680",
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "ProductName": "Security Hub",
        "CompanyName": "AWS",
        "Region": "us-east-1",
        "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/CloudTrail.2",
        "AwsAccountId": "123456789012",
        "Types": ["Software and Configuration Checks", "Unusual Behaviors"],
        "FirstObservedAt": "2025-02-26T00:00:00Z",
        "LastObservedAt": "2025-02-26T01:00:00Z",
        "CreatedAt": "2025-02-26T00:00:00Z",
        "UpdatedAt": "2025-02-26T01:00:00Z",
        "Severity": {"Product": 40, "Label": "MEDIUM"},
        "Title": "CloudTrail.2 CloudTrail should have encryption at-rest enabled",
        "Description": "This AWS control checks if AWS CloudTrail trails are encrypted at rest with AWS KMS keys.",
        "ProductFields": {
            "StandardsControlArn": "arn:aws:securityhub:us-east-1:123456789012:control/nist-800-53/v/5.0.0/SC-28",
            "RecommendationUrl": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-cloudtrail-2",
            "StandardsGuideArn": "arn:aws:securityhub:us-east-1:123456789012:standards/aws-foundational-security-best-practices/v/1.0.0",
            "RecordState": "ACTIVE",
            "WorkflowStatus": "NEW",
            "Compliance.Status": "FAILED",
        },
        "Resources": [
            {
                "Type": "AwsCloudTrailTrail",
                "Id": "arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events",
                "Partition": "aws",
                "Region": "us-east-1",
                "Details": {
                    "AwsCloudTrailTrail": {
                        "Name": "management-events",
                        "IsMultiRegionTrail": True,
                    }
                },
            }
        ],
    },
    {
        "SchemaVersion": "2018-10-08",
        "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.1/finding/abcdef-1234-5678-90ab-cdef12345681",
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "ProductName": "Security Hub",
        "CompanyName": "AWS",
        "Region": "us-east-1",
        "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/EC2.1",
        "AwsAccountId": "123456789012",
        "Types": ["Software and Configuration Checks"],
        "FirstObservedAt": "2025-02-26T00:00:00Z",
        "LastObservedAt": "2025-02-26T01:00:00Z",
        "CreatedAt": "2025-02-26T00:00:00Z",
        "UpdatedAt": "2025-02-26T01:00:00Z",
        "Severity": {"Product": 30, "Label": "LOW"},
        "Title": "EC2.1 EBS snapshots should not be publicly restorable",
        "Description": "This AWS control checks if Amazon EBS snapshots are not publicly restorable.",
        "ProductFields": {
            "StandardsControlArn": "arn:aws:securityhub:us-east-1:123456789012:control/nist-800-53/v/5.0.0/AC-3",
            "RecommendationUrl": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-ec2-1",
            "StandardsGuideArn": "arn:aws:securityhub:us-east-1:123456789012:standards/aws-foundational-security-best-practices/v/1.0.0",
            "RecordState": "ACTIVE",
            "WorkflowStatus": "NEW",
            "Compliance.Status": "FAILED",
        },
        "Resources": [
            {
                "Type": "AwsEc2Snapshot",
                "Id": "arn:aws:ec2:us-east-1:123456789012:snapshot/snap-123456789012",
                "Partition": "aws",
                "Region": "us-east-1",
            }
        ],
    },
]


def test_nist_email_with_mocks():
    """Generate and send a NIST 800-53 cATO email using mock data."""

    # Initialize mappers
    mappers = MapperFactory.get_all_mappers()

    # Set up the test framework mapping
    findings = {"NIST800-53": mock_findings}

    # Set up the mock analysis
    mock_analysis = """# NIST 800-53 Compliance Analysis

## Executive Summary

The AWS environment has several security findings that require immediate attention to maintain NIST 800-53 compliance. The findings include a critical issue with IAM root access keys, high-severity encryption concerns with S3 buckets, medium-severity issues with CloudTrail encryption, and low-severity concerns with EC2 snapshots.

## NIST 800-53 Impact

These findings directly impact the following NIST 800-53 control families:

1. Access Control (AC): The IAM root user access key finding violates least privilege principles (AC-6).
2. System and Information Integrity (SI): Multiple findings related to encryption and data protection.
3. Audit and Accountability (AU): Issues with CloudTrail configuration affect audit capabilities.

## Key Recommendations

1. Remove all IAM root user access keys immediately
2. Enable server-side encryption for all S3 buckets
3. Configure encryption for CloudTrail logs
4. Review EC2 snapshot permissions

## Auditor's Perspective

As a NIST 800-53 auditor with over 15 years of experience, I view the IAM root user access key finding as a significant concern that could result in a compliance failure. During a formal assessment, this would be flagged as a critical vulnerability requiring immediate remediation.

The encryption findings for S3 and CloudTrail represent fundamental security requirements under NIST 800-53 controls SC-28 (Protection of Information at Rest) and would need to be addressed within 30 days to maintain compliance.

I recommend prioritizing the critical finding immediately, followed by the high-severity issues within one week, and implementing a continuous monitoring solution to detect similar issues in the future. These actions would significantly improve your NIST 800-53 compliance posture."""

    mock_stats = {
        "NIST800-53": {
            "total": len(mock_findings),
            "critical": sum(
                1
                for f in mock_findings
                if f.get("Severity", {}).get("Label") == "CRITICAL"
            ),
            "high": sum(
                1 for f in mock_findings if f.get("Severity", {}).get("Label") == "HIGH"
            ),
            "medium": sum(
                1
                for f in mock_findings
                if f.get("Severity", {}).get("Label") == "MEDIUM"
            ),
            "low": sum(
                1 for f in mock_findings if f.get("Severity", {}).get("Label") == "LOW"
            ),
        }
    }

    analyses = {"NIST800-53": mock_analysis}

    # Set up boto3 client mocking to prevent actual email sending
    with patch.object(boto3, "client") as mock_boto3_client:
        mock_ses = MagicMock()
        mock_ses.send_raw_email.return_value = {"MessageId": "mock-message-id"}

        def mock_client(service_name, **kwargs):
            if service_name == "ses":
                return mock_ses
            else:
                return MagicMock()

        mock_boto3_client.side_effect = mock_client

        # Generate the email
        result = send_email(
            recipient_email=os.environ["RECIPIENT_EMAIL"],
            findings=findings,
            analyses=analyses,
            stats=mock_stats,
            mappers=mappers,
            selected_framework="NIST800-53",
            include_combined=False,
        )

        # Save the CSV to a file for inspection
        csv_data = generate_csv(findings, mappers, "NIST800-53")
        with open("nist_cato_findings.csv", "w") as f:
            f.write(csv_data)

        print(f"cATO Email {'sent successfully' if result else 'failed to send'}")
        print(f"NIST 800-53 cATO CSV saved to nist_cato_findings.csv")

        # Also save the mock data to view
        with open("nist_cato_mock_data.json", "w") as f:
            json.dump(
                {
                    "findings": mock_findings,
                    "analysis": mock_analysis,
                    "stats": mock_stats,
                },
                f,
                indent=2,
            )


if __name__ == "__main__":
    test_nist_email_with_mocks()
