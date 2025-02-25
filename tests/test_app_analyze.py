"""Tests for the analyze_findings function in app.py."""

import io
import json
import os
import unittest
from datetime import datetime
from unittest.mock import MagicMock, mock_open, patch

import app


class TestAppAnalyze(unittest.TestCase):
    """Tests for the analyze_findings function."""

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
                    "ControlId": "IAM.1",
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

    @patch("app.boto3.client")
    def test_analyze_findings_with_bedrock(self, mock_boto3_client):
        """Test analyzing findings with Bedrock."""
        # Create a mock Bedrock client
        mock_bedrock = MagicMock()
        mock_boto3_client.return_value = mock_bedrock

        # Mock response body from Bedrock
        mock_response_body = io.BytesIO(
            json.dumps({"content": [{"text": "Sample analysis"}]}).encode("utf-8")
        )
        mock_response_body.close = MagicMock()

        # Configure the mock to return a successful response
        mock_bedrock.invoke_model.return_value = {"body": mock_response_body}

        # Create a mock SOC2Mapper
        mock_soc2_mapper = MagicMock()
        mock_soc2_mapper.map_finding.return_value = {"SOC2Controls": ["CC6.1", "CC7.2"]}

        # Call the function
        analysis, stats = app.analyze_findings(self.sample_findings, mock_soc2_mapper)

        # Verify the function called Bedrock
        mock_bedrock.invoke_model.assert_called_once()

        # Verify the function returned the expected analysis
        self.assertEqual(analysis, "Sample analysis")

        # Verify the statistics
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["medium"], 1)

    @patch("app.boto3.client")
    def test_analyze_findings_with_exception(self, mock_boto3_client):
        """Test analyzing findings with Bedrock exception."""
        # Create a mock Bedrock client
        mock_bedrock = MagicMock()
        mock_boto3_client.return_value = mock_bedrock

        # Configure the mock to raise an exception
        mock_bedrock.invoke_model.side_effect = Exception("Test exception")

        # Create a mock SOC2Mapper
        mock_soc2_mapper = MagicMock()
        mock_soc2_mapper.map_finding.return_value = {"SOC2Controls": ["CC6.1", "CC7.2"]}

        # Call the function
        analysis, stats = app.analyze_findings(self.sample_findings, mock_soc2_mapper)

        # Verify the function returned fallback analysis and correct stats
        self.assertIn("SecurityHub Findings Summary", analysis)
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["medium"], 1)

    def test_analyze_findings_no_findings(self):
        """Test analyzing findings with no findings."""
        # Create a mock SOC2Mapper
        mock_soc2_mapper = MagicMock()

        # Call the function with empty findings
        analysis, stats = app.analyze_findings([], mock_soc2_mapper)

        # Verify the function returned expected values
        self.assertEqual(analysis, "No findings to analyze.")
        self.assertEqual(stats, {})


if __name__ == "__main__":
    unittest.main()
