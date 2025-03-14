import unittest
import sys
import os
import json
from unittest.mock import patch, MagicMock

# Add the src directory to the path so we can import the modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.app import get_findings, analyze_findings, lambda_handler, get_nist_control_status, percentage


class TestAppFunctions(unittest.TestCase):
    """Unit tests for core app.py functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_findings = {
            "SOC2": [
                {
                    "Title": "Encryption missing on S3 bucket",
                    "Description": "S3 bucket is not using encryption",
                    "Severity": {"Label": "HIGH"},
                    "Types": ["Software and Configuration Checks"],
                    "Resources": [{"Id": "arn:aws:s3:::example-bucket"}]
                },
                {
                    "Title": "IAM user has excessive permissions",
                    "Description": "IAM user has overly permissive access",
                    "Severity": {"Label": "MEDIUM"},
                    "Types": ["Software and Configuration Checks"],
                    "Resources": [{"Id": "arn:aws:iam::123456789012:user/example-user"}]
                }
            ],
            "NIST800-53": [
                {
                    "Title": "Security group allows unrestricted access",
                    "Description": "A security group has a rule that allows unrestricted access",
                    "Severity": {"Label": "CRITICAL"},
                    "Types": ["Network Reachability"],
                    "Resources": [{"Id": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345"}]
                }
            ]
        }
        
        # Mock mappers for testing
        self.mock_soc2_mapper = MagicMock()
        self.mock_soc2_mapper.get_control_id_attribute.return_value = "SOC2Controls"
        self.mock_soc2_mapper.map_finding.side_effect = lambda finding: {
            "Title": finding.get("Title", ""),
            "Description": finding.get("Description", ""),
            "Severity": finding.get("Severity", {}).get("Label", "INFORMATIONAL"),
            "Type": " ".join(finding.get("Types", ["Unknown"])),
            "ResourceId": finding.get("Resources", [{}])[0].get("Id", "Unknown"),
            "SOC2Controls": ["CC6.1", "CC6.3"]
        }
        
        self.mock_nist_mapper = MagicMock()
        self.mock_nist_mapper.get_control_id_attribute.return_value = "NIST800-53Controls"
        self.mock_nist_mapper.map_finding.side_effect = lambda finding: {
            "Title": finding.get("Title", ""),
            "Description": finding.get("Description", ""),
            "Severity": finding.get("Severity", {}).get("Label", "INFORMATIONAL"),
            "Type": " ".join(finding.get("Types", ["Unknown"])),
            "ResourceId": finding.get("Resources", [{}])[0].get("Id", "Unknown"),
            "NIST800-53Controls": ["AC-3", "SC-7"]
        }
        
        self.mock_mappers = {
            "SOC2": self.mock_soc2_mapper,
            "NIST800-53": self.mock_nist_mapper
        }

    @patch('src.app.boto3.client')
    def test_get_findings(self, mock_boto_client):
        """Test get_findings function."""
        # Setup mock response
        mock_security_hub = MagicMock()
        mock_security_hub.get_findings.return_value = {
            "Findings": [
                {
                    "Title": "Encryption missing on S3 bucket",
                    "Description": "S3 bucket is not using encryption",
                    "Severity": {"Label": "HIGH"},
                    "Types": ["Software and Configuration Checks"],
                    "Resources": [{"Id": "arn:aws:s3:::example-bucket"}],
                    "ProductFields": {"StandardsArn": "arn:aws:securityhub:::ruleset/soc2/v/1.0.0"}
                }
            ]
        }
        mock_boto_client.return_value = mock_security_hub

        # Test with default parameters
        with patch('src.app.load_frameworks') as mock_load_frameworks:
            mock_load_frameworks.return_value = [
                {
                    "id": "SOC2",
                    "name": "SOC 2",
                    "description": "SOC 2 Security Framework",
                    "arn": "arn:aws:securityhub:::ruleset/soc2/v/1.0.0",
                }
            ]
            
            findings = get_findings(24)  # 24 hours
            
            # Verify boto3 client was called correctly
            mock_boto_client.assert_called_with("securityhub")
            
            # Verify get_findings called with correct filters
            call_args = mock_security_hub.get_findings.call_args[1]
            self.assertIn("Filters", call_args)
            self.assertIn("RecordState", call_args["Filters"])
            self.assertEqual(call_args["Filters"]["RecordState"][0]["Value"], "ACTIVE")
            
            # Verify findings were returned correctly
            self.assertIn("SOC2", findings)
            self.assertEqual(len(findings["SOC2"]), 1)

    def test_analyze_findings(self):
        """Test analyze_findings function."""
        # Test with mock findings and mappers
        analyses, stats = analyze_findings(self.mock_findings, self.mock_mappers)
        
        # Verify analyses contain expected frameworks
        self.assertIn("SOC2", analyses)
        self.assertIn("NIST800-53", analyses)
        
        # Verify stats contain expected data
        self.assertEqual(stats["SOC2"]["total"], 2)
        self.assertEqual(stats["NIST800-53"]["total"], 1)
        
        # Verify control mappings
        self.assertIn("by_control", stats["SOC2"])
        self.assertIn("CC6.1", stats["SOC2"]["by_control"])
        self.assertEqual(stats["SOC2"]["by_control"]["CC6.1"]["count"], 2)

    def test_percentage_calculation(self):
        """Test percentage calculation function."""
        self.assertEqual(percentage(10, 100), 10)
        self.assertEqual(percentage(0, 100), 0)
        self.assertEqual(percentage(100, 100), 100)
        self.assertEqual(percentage(33, 100), 33)
        self.assertEqual(percentage(75, 100), 75)
        # Test rounding
        self.assertEqual(percentage(33, 101), 33)  # 32.67 rounds to 33
        self.assertEqual(percentage(2, 3), 67)     # 66.67 rounds to 67
        # Test division by zero
        self.assertEqual(percentage(10, 0), 0)

    @patch('src.app.boto3.client')
    def test_get_nist_control_status(self, mock_boto_client):
        """Test get_nist_control_status function."""
        # Setup mock response
        mock_security_hub = MagicMock()
        mock_security_hub.get_enabled_standards.return_value = {
            "StandardsSubscriptions": [
                {
                    "StandardsArn": "arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0",
                    "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:123456789012:subscription/nist-800-53/v/5.0.0"
                }
            ]
        }
        mock_security_hub.describe_standards_controls.return_value = {
            "Controls": [
                {
                    "ControlId": "NIST.800-53.r5-AC-1",
                    "Title": "Access Control Policy and Procedures",
                    "Description": "The organization develops, documents, and disseminates...",
                    "ControlStatus": "ENABLED",
                    "ComplianceStatus": "PASSED",
                    "SeverityRating": "MEDIUM"
                },
                {
                    "ControlId": "NIST.800-53.r5-AC-2",
                    "Title": "Account Management",
                    "Description": "The organization manages information system accounts...",
                    "ControlStatus": "ENABLED",
                    "ComplianceStatus": "FAILED",
                    "SeverityRating": "HIGH"
                }
            ]
        }
        mock_boto_client.return_value = mock_security_hub

        # Call function
        control_status = get_nist_control_status()
        
        # Verify boto3 client was called correctly
        mock_boto_client.assert_called_with("securityhub")
        
        # Verify control status was returned correctly
        self.assertIn("AC-1", control_status)
        self.assertIn("AC-2", control_status)
        self.assertEqual(control_status["AC-1"]["status"], "PASSED")
        self.assertEqual(control_status["AC-2"]["status"], "FAILED")

    @patch('src.app.get_findings')
    @patch('src.app.MapperFactory.create_all_mappers')
    @patch('src.app.analyze_findings')
    @patch('src.app.send_email')
    def test_lambda_handler(self, mock_send_email, mock_analyze_findings, mock_create_mappers, mock_get_findings):
        """Test lambda_handler function."""
        # Setup mock responses
        mock_get_findings.return_value = self.mock_findings
        mock_create_mappers.return_value = self.mock_mappers
        mock_analyze_findings.return_value = (
            {"SOC2": "Analysis for SOC2", "NIST800-53": "Analysis for NIST800-53"},
            {"SOC2": {"total": 2}, "NIST800-53": {"total": 1}}
        )
        mock_send_email.return_value = True
        
        # Test with default parameters
        event = {
            "hours": 24,
            "framework_id": "SOC2",
            "email": "test@example.com"
        }
        context = {}
        
        response = lambda_handler(event, context)
        
        # Verify response
        self.assertEqual(response["statusCode"], 200)
        self.assertIn("message", response["body"])
        self.assertIn("output", response["body"])
        self.assertIn("stats", response["body"])
        
        # Verify function calls
        mock_get_findings.assert_called_with(24, "SOC2")
        mock_create_mappers.assert_called_once()
        mock_analyze_findings.assert_called_once()


if __name__ == '__main__':
    unittest.main()