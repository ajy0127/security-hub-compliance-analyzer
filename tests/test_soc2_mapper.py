"""Tests for the SOC2Mapper class."""

import json
import os
import unittest
from unittest.mock import patch, mock_open

from soc2_mapper import SOC2Mapper


class TestSOC2Mapper(unittest.TestCase):
    """Tests for the SOC2Mapper class."""

    def setUp(self):
        """Set up test fixtures."""
        self.sample_finding = {
            "SchemaVersion": "2018-10-08",
            "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.1/finding/12345678-1234-1234-1234-123456789012",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/IAM.1",
            "AwsAccountId": "123456789012",
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

        self.sample_mappings = {
            "type_mappings": {
                "Software and Configuration Checks/Industry and Regulatory Standards": ["CC1.3", "CC2.2", "CC2.3"]
            },
            "title_mappings": {
                "access key": ["CC6.1", "CC6.3"]
            },
            "control_descriptions": {
                "CC1.3": "Management has established procedures to evaluate and determine whether controls are operating effectively.",
                "CC2.2": "Information security policies include requirements for addressing security objectives.",
                "CC2.3": "Responsibility and accountability for designing, developing, implementing, operating, maintaining, and monitoring controls are assigned to individuals within the entity with appropriate skill levels and authority.",
                "CC6.1": "The entity implements logical access security software, infrastructure, and architectures for authentication and access to the system.",
                "CC6.3": "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles and responsibilities and considering the concepts of least privilege and segregation of duties."
            }
        }

    @patch("builtins.open", new_callable=mock_open, read_data=json.dumps({}))
    @patch("os.path.exists", return_value=True)
    def test_load_mappings_from_file(self, mock_exists, mock_file):
        """Test loading mappings from a file."""
        mapper = SOC2Mapper(mappings_file="fake_path.json")
        mock_exists.assert_called_once_with("fake_path.json")
        mock_file.assert_called_once_with("fake_path.json", "r")

    @patch("os.path.exists", return_value=False)
    def test_load_default_mappings_when_file_not_found(self, mock_exists):
        """Test loading default mappings when file is not found."""
        mapper = SOC2Mapper(mappings_file="nonexistent_file.json")
        mock_exists.assert_called_once_with("nonexistent_file.json")
        self.assertIsNotNone(mapper.mappings)
        self.assertIn("type_mappings", mapper.mappings)
        self.assertIn("title_mappings", mapper.mappings)
        self.assertIn("control_descriptions", mapper.mappings)

    @patch.object(SOC2Mapper, "_load_mappings")
    def test_map_finding(self, mock_load_mappings):
        """Test mapping a finding to SOC2 controls."""
        mock_load_mappings.return_value = self.sample_mappings
        mapper = SOC2Mapper()
        
        mapped_finding = mapper.map_finding(self.sample_finding)
        
        self.assertIsNotNone(mapped_finding)
        self.assertEqual(mapped_finding["Title"], "IAM root user access key should not exist")
        self.assertEqual(mapped_finding["Severity"], "MEDIUM")
        self.assertEqual(mapped_finding["Type"], "Software and Configuration Checks/Industry and Regulatory Standards")
        self.assertEqual(mapped_finding["ResourceId"], "AWS::::Account:123456789012")
        
        # Check that the finding was mapped to the correct controls
        self.assertIn("SOC2Controls", mapped_finding)
        self.assertIsInstance(mapped_finding["SOC2Controls"], list)
        
        # The finding should be mapped to controls from both type and title mappings
        expected_controls = ["CC1.3", "CC2.2", "CC2.3", "CC6.1", "CC6.3"]
        for control in expected_controls:
            self.assertIn(control, mapped_finding["SOC2Controls"])

    @patch.object(SOC2Mapper, "_load_mappings")
    def test_map_finding_with_no_matching_controls(self, mock_load_mappings):
        """Test mapping a finding with no matching controls."""
        # Create mappings with no matches for our sample finding
        empty_mappings = {
            "type_mappings": {
                "Some Other Type": ["CC1.3"]
            },
            "title_mappings": {
                "some other keyword": ["CC6.1"]
            },
            "control_descriptions": {}
        }
        mock_load_mappings.return_value = empty_mappings
        mapper = SOC2Mapper()
        
        # Modify the finding to have a type that doesn't match any mappings
        finding = self.sample_finding.copy()
        finding["Types"] = ["Some Unmapped Type"]
        finding["Title"] = "Some unmapped title"
        
        mapped_finding = mapper.map_finding(finding)
        
        # Should default to CC7.1
        self.assertIn("SOC2Controls", mapped_finding)
        self.assertIn("CC7.1", mapped_finding["SOC2Controls"])

    @patch.object(SOC2Mapper, "_load_mappings")
    def test_get_resource_id(self, mock_load_mappings):
        """Test extracting resource ID from finding."""
        mock_load_mappings.return_value = self.sample_mappings
        mapper = SOC2Mapper()
        
        # Test with a finding that has a resource
        resource_id = mapper._get_resource_id(self.sample_finding)
        self.assertEqual(resource_id, "AWS::::Account:123456789012")
        
        # Test with a finding that has no resources
        finding_no_resources = self.sample_finding.copy()
        finding_no_resources.pop("Resources")
        resource_id = mapper._get_resource_id(finding_no_resources)
        self.assertEqual(resource_id, "Unknown")
        
        # Test with a finding that has empty resources
        finding_empty_resources = self.sample_finding.copy()
        finding_empty_resources["Resources"] = []
        resource_id = mapper._get_resource_id(finding_empty_resources)
        self.assertEqual(resource_id, "Unknown")


if __name__ == "__main__":
    unittest.main() 