"""
Test script to run the NIST 800-53 email functionality locally with mock data.
"""

import json
import os
import boto3
from unittest.mock import patch, MagicMock
from src.app import lambda_handler, send_email, analyze_findings, generate_csv
from src.mapper_factory import MapperFactory

# Set environment variables needed for the function
os.environ["SENDER_EMAIL"] = "your-verified-email@example.com"
os.environ["RECIPIENT_EMAIL"] = "your-verified-email@example.com"
os.environ["BEDROCK_MODEL_ID"] = "anthropic.claude-3-sonnet"  # Use your model of choice

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
            "Compliance.Status": "FAILED"
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
                        "CreatedAt": "2023-01-01T00:00:00Z"
                    }
                }
            }
        ]
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
            "Compliance.Status": "FAILED"
        },
        "Resources": [
            {
                "Type": "AwsIamUser",
                "Id": "AWS::::Account:123456789012",
                "Partition": "aws",
                "Region": "us-east-1"
            }
        ]
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
            "Compliance.Status": "FAILED"
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
                        "IsMultiRegionTrail": True
                    }
                }
            }
        ]
    }
]

# Create a NIST 800-53 specific event
event = {
    "framework": "NIST800-53",  # Specify NIST 800-53 framework
    "hours": 24,  # Look for findings from the last 24 hours
    "email": os.environ["RECIPIENT_EMAIL"],  # Use the same email for sending/receiving
    "generate_csv": True,  # Generate CSV files for findings
    "combined_analysis": False  # We only want NIST-specific analysis
}

def run_test_with_mocks():
    """Run test with mock data instead of actual SecurityHub API calls."""
    
    # Initialize mappers
    mappers = MapperFactory.get_all_mappers()
    
    # Mock the get_findings function to return our mock data
    with patch("src.app.get_findings", return_value={"NIST800-53": mock_findings}):
        # Mock the SES send_raw_email to prevent actual email sending
        with patch.object(boto3, "client") as mock_boto3_client:
            mock_ses = MagicMock()
            mock_bedrock = MagicMock()
            
            # Set up mock SES response
            mock_ses.send_raw_email.return_value = {"MessageId": "mock-message-id"}
            
            # Set up mock Bedrock response
            mock_bedrock_response = {
                "body": MagicMock()
            }
            mock_bedrock_response["body"].read.return_value = json.dumps({
                "content": [{"text": "This is a mock NIST 800-53 analysis generated for testing purposes."}]
            })
            mock_bedrock.invoke_model.return_value = mock_bedrock_response
            
            # Configure boto3.client to return our mocks
            def mock_client(service_name, **kwargs):
                if service_name == "ses":
                    return mock_ses
                elif service_name == "bedrock-runtime":
                    return mock_bedrock
                else:
                    return MagicMock()
            
            mock_boto3_client.side_effect = mock_client
            
            # Call the lambda function
            response = lambda_handler(event, None)
            
            # Print the response
            print(json.dumps(response, indent=2))
            
            # Save mock findings to a file for reference
            with open("nist_report.json", "w") as f:
                json.dump(mock_findings, f, indent=2)
            
            # Save the response to a file
            with open("nist_response.json", "w") as f:
                json.dump(response, f, indent=2)
            
            print("Test completed with mock data. Response saved to nist_response.json")
            print("Mock findings saved to nist_report.json")

if __name__ == "__main__":
    run_test_with_mocks()