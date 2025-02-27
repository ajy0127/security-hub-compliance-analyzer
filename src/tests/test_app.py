"""Tests for the main application."""

import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import ANY, MagicMock, patch

import boto3
import botocore.session
from botocore.stub import Stubber

# Import the functions from app.py
import app


class TestApp(unittest.TestCase):
    """Tests for the main application."""

    def setUp(self):
        """Set up test fixtures."""
        # Sample findings for testing
        self.sample_findings = [
            {
                "SchemaVersion": "2018-10-08",
                "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.1/finding/12345678-1234-1234-1234-123456789012",
                "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
                "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/IAM.1",
                "AwsAccountId": "123456789012",
                "Region": "us-east-1",
                "Types": [
                    "Software and Configuration Checks/Industry and Regulatory Standards"
                ],
                "FirstObservedAt": "2023-01-01T00:00:00.000Z",
                "LastObservedAt": "2023-01-01T00:00:00.000Z",
                "CreatedAt": "2023-01-01T00:00:00.000Z",
                "UpdatedAt": "2023-01-01T00:00:00.000Z",
                "Severity": {"Label": "MEDIUM", "Normalized": 40},
                "Title": "IAM root user access key should not exist",
                "Description": "This AWS control checks whether the root user access key is available.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Remove root access keys and create IAM users instead."
                    }
                },
                "ProductFields": {
                    "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                    "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0",
                    "ControlId": "IAM.1",
                    "RecommendationUrl": "https://docs.aws.amazon.com/console/securityhub/IAM.1/remediation",
                    "RelatedAWSResources:0/name": "securityhub-iam-root-access-key-check",
                    "RelatedAWSResources:0/type": "AWS::Config::ConfigRule",
                    "StandardsControlArn": "arn:aws:securityhub:us-east-1:123456789012:control/aws-foundational-security-best-practices/v/1.0.0/IAM.1",
                    "aws/securityhub/ProductName": "Security Hub",
                    "aws/securityhub/CompanyName": "AWS",
                    "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/securityhub/arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.1/finding/12345678-1234-1234-1234-123456789012",
                },
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": "AWS::::Account:123456789012",
                        "Partition": "aws",
                        "Region": "us-east-1",
                    }
                ],
                "Compliance": {"Status": "FAILED"},
                "WorkflowState": "NEW",
                "RecordState": "ACTIVE",
            }
        ]

        # Sample event for testing
        self.sample_event = {"email": "test@example.com", "hours": 24}

        # Sample test event for testing
        self.sample_test_event = {
            "test_email": True,
            "recipient_email": "test@example.com",
        }

    @patch("app.boto3.client")
    @patch("app.load_frameworks")
    def test_get_findings(self, mock_load_frameworks, mock_boto3_client):
        """Test retrieving findings from SecurityHub."""
        # Create a mock SecurityHub client
        mock_securityhub = MagicMock()
        mock_boto3_client.return_value = mock_securityhub

        # Configure the mock to return sample findings
        mock_securityhub.get_findings.return_value = {"Findings": self.sample_findings}

        # Mock the frameworks configuration
        mock_load_frameworks.return_value = [
            {
                "id": "SOC2",
                "name": "SOC 2",
                "arn": "arn:aws:securityhub:::standards/aws-soc2",
                "description": "SOC 2 Framework",
            }
        ]

        # Call the function with specific framework
        findings = app.get_findings(24, "SOC2")

        # Verify the function called SecurityHub with the correct parameters
        mock_securityhub.get_findings.assert_called_once()

        # Verify the function returned the expected findings
        self.assertEqual(findings, self.sample_findings)

    @patch("app.boto3.client")
    @patch("app.load_frameworks")
    def test_send_email(self, mock_load_frameworks, mock_boto3_client):
        """Test sending email with findings and analysis."""
        # Create a mock SES client
        mock_ses = MagicMock()
        mock_boto3_client.return_value = mock_ses

        # Configure the mock to return a successful response
        mock_ses.send_raw_email.return_value = {
            "MessageId": "12345678-1234-1234-1234-123456789012"
        }

        # Create a mock mapper dictionary
        mock_mappers = {"SOC2": MagicMock()}
        mock_mappers["SOC2"].map_finding.return_value = {
            "SOC2Controls": ["CC6.1", "CC7.2"]
        }
        mock_mappers["SOC2"].get_control_id_attribute.return_value = "SOC2Controls"

        # Sample analyses and stats
        analyses = {
            "SOC2": "Sample analysis text for SOC2",
            "combined": "Combined analysis",
        }
        stats = {
            "SOC2": {
                "total": 1,
                "by_severity": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 1,
                    "LOW": 0,
                    "INFORMATIONAL": 0,
                },
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 0,
            }
        }

        # Mock the frameworks configuration
        mock_load_frameworks.return_value = [
            {
                "id": "SOC2",
                "name": "SOC 2",
                "arn": "arn:aws:securityhub:::standards/aws-soc2",
                "description": "SOC 2 Framework",
            }
        ]

        # Set environment variables for testing
        os.environ["SENDER_EMAIL"] = "sender@example.com"

        # Create findings dict (new format)
        findings_dict = {"SOC2": self.sample_findings}

        # Call the function
        result = app.send_email(
            "test@example.com", findings_dict, analyses, stats, mock_mappers
        )

        # Verify the function called SES with the correct parameters
        mock_ses.send_raw_email.assert_called_once()

        # Verify the function returned the expected result
        self.assertTrue(result)

    @patch("app.boto3.client")
    def test_send_test_email(self, mock_boto3_client):
        """Test sending a test email."""
        # Create a mock SES client
        mock_ses = MagicMock()
        mock_boto3_client.return_value = mock_ses

        # Configure the mock to return a successful response
        mock_ses.send_raw_email.return_value = {
            "MessageId": "12345678-1234-1234-1234-123456789012"
        }

        # Set environment variables for testing
        os.environ["SENDER_EMAIL"] = "sender@example.com"

        # Call the function
        result = app.send_test_email("test@example.com")

        # Verify the function called SES with the correct parameters
        mock_ses.send_raw_email.assert_called_once()

        # Verify the function returned the expected result
        self.assertTrue(result)

    @patch("app.analyze_findings")
    @patch("app.get_findings")
    @patch("app.send_email")
    @patch("app.send_test_email")
    @patch("app.MapperFactory")
    @patch("app.load_frameworks")
    def test_lambda_handler_normal_operation(
        self,
        mock_load_frameworks,
        mock_mapper_factory,
        mock_send_test_email,
        mock_send_email,
        mock_get_findings,
        mock_analyze_findings,
    ):
        """Test lambda_handler with normal operation."""
        # Configure mocks
        mock_mappers = {"SOC2": MagicMock()}
        mock_mapper_factory.get_all_mappers.return_value = mock_mappers

        # Mock the frameworks configuration
        mock_load_frameworks.return_value = [
            {
                "id": "SOC2",
                "name": "SOC 2",
                "arn": "arn:aws:securityhub:::standards/aws-soc2",
                "description": "SOC 2 Framework",
            }
        ]

        # Configure get_findings to return mock findings (new dict format)
        findings_dict = {"SOC2": self.sample_findings}
        mock_get_findings.return_value = findings_dict

        # Configure analyze_findings to return mock analyses (new dict format) and stats
        mock_analyses = {"SOC2": "Sample analysis", "combined": "Combined analysis"}
        mock_stats = {
            "SOC2": {
                "total": 1,
                "by_severity": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 1,
                    "LOW": 0,
                    "INFORMATIONAL": 0,
                },
            }
        }
        mock_analyze_findings.return_value = (mock_analyses, mock_stats)

        mock_send_email.return_value = True

        # Call the function
        result = app.lambda_handler(self.sample_event, {})

        # Verify the function called the expected functions with the correct parameters
        mock_mapper_factory.get_all_mappers.assert_called_once()
        mock_get_findings.assert_called_once_with(24)
        mock_analyze_findings.assert_called_once_with(
            findings_dict, mock_mappers, None, ANY
        )
        mock_send_email.assert_called_once()
        mock_send_test_email.assert_not_called()

        # Verify the function returned the expected result
        self.assertEqual(
            result, {"statusCode": 200, "body": json.dumps("Email sent successfully")}
        )

    @patch("app.send_test_email")
    @patch("app.get_findings")
    def test_lambda_handler_test_email(self, mock_get_findings, mock_send_test_email):
        """Test lambda_handler with test email operation."""
        # Configure mocks
        mock_send_test_email.return_value = True

        # Call the function
        result = app.lambda_handler(self.sample_test_event, {})

        # Verify the function called the expected functions with the correct parameters
        mock_get_findings.assert_not_called()
        mock_send_test_email.assert_called_once_with("test@example.com")

        # Verify the function returned the expected result
        self.assertEqual(
            result,
            {"statusCode": 200, "body": json.dumps("Test email sent successfully")},
        )

    @patch("app.generate_csv")
    @patch("app.analyze_findings")
    @patch("app.get_findings")
    @patch("app.send_email")
    @patch("app.MapperFactory")
    @patch("app.load_frameworks")
    def test_lambda_handler_with_csv_generation(
        self,
        mock_load_frameworks,
        mock_mapper_factory,
        mock_send_email,
        mock_get_findings,
        mock_analyze_findings,
        mock_generate_csv,
    ):
        """Test lambda_handler with CSV generation."""
        # Configure mocks
        mock_mappers = {"SOC2": MagicMock()}
        mock_mapper_factory.get_all_mappers.return_value = mock_mappers

        # Mock the frameworks configuration
        mock_load_frameworks.return_value = [
            {
                "id": "SOC2",
                "name": "SOC 2",
                "arn": "arn:aws:securityhub:::standards/aws-soc2",
                "description": "SOC 2 Framework",
            }
        ]

        # Configure get_findings to return mock findings (new dict format)
        findings_dict = {"SOC2": self.sample_findings}
        mock_get_findings.return_value = findings_dict

        # Configure analyze_findings to return mock analyses (new dict format) and stats
        mock_analyses = {"SOC2": "Sample analysis", "combined": "Combined analysis"}
        mock_stats = {
            "SOC2": {
                "total": 1,
                "by_severity": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 1,
                    "LOW": 0,
                    "INFORMATIONAL": 0,
                },
            }
        }
        mock_analyze_findings.return_value = (mock_analyses, mock_stats)

        mock_send_email.return_value = True
        mock_generate_csv.return_value = {"SOC2": "/tmp/findings_soc2.csv"}

        # Call the function
        event_with_csv = self.sample_event.copy()
        event_with_csv["generate_csv"] = True
        result = app.lambda_handler(event_with_csv, {})

        # Verify the function called the expected functions with the correct parameters
        mock_mapper_factory.get_all_mappers.assert_called_once()
        mock_get_findings.assert_called_once_with(24)
        mock_analyze_findings.assert_called_once_with(
            findings_dict, mock_mappers, None, ANY
        )
        mock_generate_csv.assert_called_once_with(findings_dict, mock_mappers)
        mock_send_email.assert_called_once()

        # Verify the function returned the expected result
        self.assertEqual(
            result, {"statusCode": 200, "body": json.dumps("Email sent successfully")}
        )


if __name__ == "__main__":
    unittest.main()
