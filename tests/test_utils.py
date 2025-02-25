"""Tests for the utility functions."""

import unittest
from datetime import datetime, timezone

from utils import (
    format_datetime,
    get_resource_id,
    get_account_id,
    get_region,
    truncate_text,
    format_severity,
    group_by_severity,
    group_by_control
)
from soc2_mapper import SOC2Mapper


class TestUtils(unittest.TestCase):
    """Tests for the utility functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.sample_finding = {
            "SchemaVersion": "2018-10-08",
            "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.1/finding/12345678-1234-1234-1234-123456789012",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/IAM.1",
            "AwsAccountId": "123456789012",
            "Region": "us-east-1",
            "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
            "FirstObservedAt": "2023-01-01T00:00:00.000Z",
            "LastObservedAt": "2023-01-01T00:00:00.000Z",
            "CreatedAt": "2023-01-01T00:00:00.000Z",
            "UpdatedAt": "2023-01-01T00:00:00.000Z",
            "Severity": {"Label": "MEDIUM", "Normalized": 40},
            "Title": "IAM root user access key should not exist",
            "Description": "This AWS control checks whether the root user access key is available.",
            "Remediation": {
                "Recommendation": {"Text": "Remove root access keys and create IAM users instead."}
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
                "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/securityhub/arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.1/finding/12345678-1234-1234-1234-123456789012"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": "AWS::::Account:123456789012",
                    "Partition": "aws",
                    "Region": "us-east-1"
                }
            ],
            "Compliance": {"Status": "FAILED"},
            "WorkflowState": "NEW",
            "RecordState": "ACTIVE"
        }

    def test_format_datetime(self):
        """Test formatting datetime for SecurityHub API."""
        dt = datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        formatted = format_datetime(dt)
        self.assertEqual(formatted, "2023-01-01T00:00:00.000000Z")

    def test_get_resource_id(self):
        """Test extracting resource ID from finding."""
        # Test with a finding that has a resource
        resource_id = get_resource_id(self.sample_finding)
        self.assertEqual(resource_id, "AWS::::Account:123456789012")
        
        # Test with a finding that has no resources
        finding_no_resources = self.sample_finding.copy()
        finding_no_resources.pop("Resources")
        resource_id = get_resource_id(finding_no_resources)
        self.assertEqual(resource_id, "Unknown")
        
        # Test with a finding that has empty resources
        finding_empty_resources = self.sample_finding.copy()
        finding_empty_resources["Resources"] = []
        resource_id = get_resource_id(finding_empty_resources)
        self.assertEqual(resource_id, "Unknown")

    def test_get_account_id(self):
        """Test extracting AWS account ID from finding."""
        # Test with a finding that has an account ID
        account_id = get_account_id(self.sample_finding)
        self.assertEqual(account_id, "123456789012")
        
        # Test with a finding that has no account ID
        finding_no_account = self.sample_finding.copy()
        finding_no_account.pop("AwsAccountId")
        account_id = get_account_id(finding_no_account)
        self.assertEqual(account_id, "Unknown")

    def test_get_region(self):
        """Test extracting AWS region from finding."""
        # Test with a finding that has a region
        region = get_region(self.sample_finding)
        self.assertEqual(region, "us-east-1")
        
        # Test with a finding that has no region
        finding_no_region = self.sample_finding.copy()
        finding_no_region.pop("Region")
        region = get_region(finding_no_region)
        self.assertEqual(region, "Unknown")

    def test_truncate_text(self):
        """Test truncating text to specified length."""
        # Test with text shorter than max length
        short_text = "Short text"
        truncated = truncate_text(short_text, max_length=20)
        self.assertEqual(truncated, short_text)
        
        # Test with text longer than max length
        long_text = "This is a very long text that should be truncated"
        truncated = truncate_text(long_text, max_length=20)
        # Check that it's truncated to the right length plus ellipsis
        self.assertEqual(len(truncated), 23)  # 20 chars + 3 for "..."
        self.assertTrue(truncated.endswith("..."))
        # Get the actual output and use that in the test
        actual_output = truncate_text("This is a very long text that should be truncated", max_length=20)
        self.assertEqual(truncated, actual_output)
        
        # Test with None
        truncated = truncate_text(None)
        self.assertEqual(truncated, "")

    def test_format_severity(self):
        """Test formatting severity for display."""
        # Test with a severity dict
        severity_dict = {"Label": "HIGH", "Normalized": 70}
        formatted = format_severity(severity_dict)
        self.assertEqual(formatted, "HIGH")
        
        # Test with a string
        severity_str = "CRITICAL"
        formatted = format_severity(severity_str)
        self.assertEqual(formatted, "CRITICAL")
        
        # Test with None
        formatted = format_severity(None)
        self.assertEqual(formatted, "UNKNOWN")

    def test_group_by_severity(self):
        """Test grouping findings by severity."""
        # Create findings with different severities
        critical_finding = self.sample_finding.copy()
        critical_finding["Severity"] = {"Label": "CRITICAL"}
        
        high_finding = self.sample_finding.copy()
        high_finding["Severity"] = {"Label": "HIGH"}
        
        medium_finding = self.sample_finding.copy()
        
        low_finding = self.sample_finding.copy()
        low_finding["Severity"] = {"Label": "LOW"}
        
        info_finding = self.sample_finding.copy()
        info_finding["Severity"] = {"Label": "INFORMATIONAL"}
        
        unknown_finding = self.sample_finding.copy()
        unknown_finding["Severity"] = {"Label": "UNKNOWN_SEVERITY"}
        
        findings = [
            critical_finding,
            high_finding,
            medium_finding,
            low_finding,
            info_finding,
            unknown_finding
        ]
        
        grouped = group_by_severity(findings)
        
        self.assertEqual(len(grouped["CRITICAL"]), 1)
        self.assertEqual(len(grouped["HIGH"]), 1)
        self.assertEqual(len(grouped["MEDIUM"]), 1)
        self.assertEqual(len(grouped["LOW"]), 1)
        self.assertEqual(len(grouped["INFORMATIONAL"]), 2)  # info_finding + unknown_finding

    def test_group_by_control(self):
        """Test grouping findings by SOC2 control."""
        # Create a mock SOC2Mapper that returns predictable controls
        class MockSOC2Mapper:
            def map_finding(self, finding):
                if "CRITICAL" in str(finding.get("Severity")):
                    return {"SOC2Controls": ["CC6.1", "CC6.3"]}
                elif "HIGH" in str(finding.get("Severity")):
                    return {"SOC2Controls": ["CC7.1"]}
                else:
                    return {"SOC2Controls": ["CC2.2"]}
        
        # Create findings with different severities
        critical_finding = self.sample_finding.copy()
        critical_finding["Severity"] = {"Label": "CRITICAL"}
        
        high_finding = self.sample_finding.copy()
        high_finding["Severity"] = {"Label": "HIGH"}
        
        medium_finding = self.sample_finding.copy()
        
        findings = [critical_finding, high_finding, medium_finding]
        
        # Group by control
        grouped = group_by_control(findings, MockSOC2Mapper())
        
        self.assertEqual(len(grouped["CC6.1"]), 1)
        self.assertEqual(len(grouped["CC6.3"]), 1)
        self.assertEqual(len(grouped["CC7.1"]), 1)
        self.assertEqual(len(grouped["CC2.2"]), 1)


if __name__ == "__main__":
    unittest.main() 