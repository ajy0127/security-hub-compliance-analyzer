import unittest
import sys
import os
import json
from unittest.mock import patch, MagicMock

# Add the src directory to the path so we can import the modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.app import send_email, get_nist_control_status, send_test_email


class TestAWSServicesIntegration(unittest.TestCase):
    """Unit tests for AWS services integration functions."""

    def setUp(self):
        """Set up test fixtures."""
        # Set environment variables needed for tests
        os.environ["SENDER_EMAIL"] = "sender@example.com"
        
        # Sample findings for testing
        self.test_findings = {
            "SOC2": [
                {
                    "Title": "Encryption missing on S3 bucket",
                    "Description": "S3 bucket is not using encryption",
                    "Severity": {"Label": "HIGH"},
                    "Types": ["Software and Configuration Checks"],
                    "Resources": [{"Id": "arn:aws:s3:::example-bucket"}]
                }
            ]
        }
        
        # Sample analysis results
        self.test_analysis = {
            "SOC2": "Analysis for SOC2 Framework:\n\nTotal findings: 1\nFindings by severity:\n  HIGH: 1\n\nFindings by control:\n  CC6.1: 1 finding(s)\n  CC6.7: 1 finding(s)"
        }
        
        # Sample stats
        self.test_stats = {
            "SOC2": {
                "total": 1,
                "by_severity": {
                    "critical": 0,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "informational": 0
                },
                "by_control": {
                    "CC6.1": {
                        "count": 1,
                        "findings": [
                            {
                                "Title": "Encryption missing on S3 bucket",
                                "SOC2Controls": ["CC6.1", "CC6.7"]
                            }
                        ]
                    },
                    "CC6.7": {
                        "count": 1,
                        "findings": [
                            {
                                "Title": "Encryption missing on S3 bucket",
                                "SOC2Controls": ["CC6.1", "CC6.7"]
                            }
                        ]
                    }
                }
            }
        }
        
        # Sample mappers
        self.test_mappers = {
            "SOC2": MagicMock()
        }
        self.test_mappers["SOC2"].get_control_id_attribute.return_value = "SOC2Controls"

    @patch('src.app.boto3.client')
    def test_send_email(self, mock_boto_client):
        """Test send_email function."""
        # Setup mock
        mock_ses = MagicMock()
        mock_ses.send_raw_email.return_value = {"MessageId": "test-message-id"}
        mock_boto_client.return_value = mock_ses
        
        # Call function
        result = send_email(
            "recipient@example.com", 
            self.test_findings, 
            self.test_analysis, 
            self.test_stats, 
            self.test_mappers
        )
        
        # Verify boto3 client was called correctly
        mock_boto_client.assert_called_with("ses")
        
        # Verify SES send_raw_email was called
        mock_ses.send_raw_email.assert_called_once()
        call_args = mock_ses.send_raw_email.call_args[1]
        
        # Verify email parameters
        self.assertEqual(call_args["Source"], "sender@example.com")
        self.assertEqual(call_args["Destinations"], ["recipient@example.com"])
        self.assertIn("Data", call_args["RawMessage"])
        
        # Verify result
        self.assertTrue(result)

    @patch('src.app.boto3.client')
    def test_send_email_without_sender(self, mock_boto_client):
        """Test send_email function without sender email."""
        # Remove sender email environment variable
        del os.environ["SENDER_EMAIL"]
        
        # Call function
        result = send_email(
            "recipient@example.com", 
            self.test_findings, 
            self.test_analysis, 
            self.test_stats, 
            self.test_mappers
        )
        
        # Verify boto3 client was not called
        mock_boto_client.assert_not_called()
        
        # Verify result
        self.assertFalse(result)
        
        # Restore environment variable for other tests
        os.environ["SENDER_EMAIL"] = "sender@example.com"

    @patch('src.app.boto3.client')
    def test_send_email_without_recipient(self, mock_boto_client):
        """Test send_email function without recipient email."""
        # Call function with None recipient
        result = send_email(
            None, 
            self.test_findings, 
            self.test_analysis, 
            self.test_stats, 
            self.test_mappers
        )
        
        # Verify boto3 client was not called
        mock_boto_client.assert_not_called()
        
        # Verify result
        self.assertFalse(result)

    @patch('src.app.boto3.client')
    def test_send_email_with_error(self, mock_boto_client):
        """Test send_email function with SES error."""
        # Setup mock to raise exception
        mock_ses = MagicMock()
        mock_ses.send_raw_email.side_effect = Exception("Test SES error")
        mock_boto_client.return_value = mock_ses
        
        # Call function
        result = send_email(
            "recipient@example.com", 
            self.test_findings, 
            self.test_analysis, 
            self.test_stats, 
            self.test_mappers
        )
        
        # Verify boto3 client was called
        mock_boto_client.assert_called_with("ses")
        
        # Verify result
        self.assertFalse(result)

    @patch('src.app.boto3.client')
    def test_send_test_email(self, mock_boto_client):
        """Test send_test_email function."""
        # Setup mock
        mock_ses = MagicMock()
        mock_ses.send_raw_email.return_value = {"MessageId": "test-message-id"}
        mock_boto_client.return_value = mock_ses
        
        # Call function
        result = send_test_email("recipient@example.com")
        
        # Verify boto3 client was called correctly
        mock_boto_client.assert_called_with("ses")
        
        # Verify SES send_raw_email was called
        mock_ses.send_raw_email.assert_called_once()
        call_args = mock_ses.send_raw_email.call_args[1]
        
        # Verify email parameters
        self.assertEqual(call_args["Source"], "sender@example.com")
        self.assertEqual(call_args["Destinations"], ["recipient@example.com"])
        self.assertIn("Data", call_args["RawMessage"])
        
        # Verify result
        self.assertTrue(result)

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
                },
                {
                    "ControlId": "NIST.800-53.r5-AC-3",
                    "Title": "Access Enforcement",
                    "Description": "The system enforces approved authorizations...",
                    "ControlStatus": "DISABLED",
                    "SeverityRating": "HIGH"
                }
            ]
        }
        mock_boto_client.return_value = mock_security_hub
        
        # Call function
        control_status = get_nist_control_status()
        
        # Verify boto3 client was called correctly
        mock_boto_client.assert_called_with("securityhub")
        
        # Verify describe_standards_controls was called with correct parameters
        call_args = mock_security_hub.describe_standards_controls.call_args[1]
        self.assertEqual(
            call_args["StandardsSubscriptionArn"], 
            "arn:aws:securityhub:us-east-1:123456789012:subscription/nist-800-53/v/5.0.0"
        )
        
        # Verify control status was processed correctly
        self.assertIn("AC-1", control_status)
        self.assertIn("AC-2", control_status)
        self.assertIn("AC-3", control_status)
        
        # Verify specific control details
        self.assertEqual(control_status["AC-1"]["status"], "PASSED")
        self.assertEqual(control_status["AC-1"]["severity"], "MEDIUM")
        self.assertEqual(control_status["AC-1"]["disabled"], False)
        
        self.assertEqual(control_status["AC-2"]["status"], "FAILED")
        self.assertEqual(control_status["AC-2"]["severity"], "HIGH")
        self.assertEqual(control_status["AC-2"]["disabled"], False)
        
        self.assertEqual(control_status["AC-3"]["status"], "NOT_APPLICABLE")
        self.assertEqual(control_status["AC-3"]["severity"], "HIGH")
        self.assertEqual(control_status["AC-3"]["disabled"], True)

    @patch('src.app.boto3.client')
    def test_get_nist_control_status_no_standards(self, mock_boto_client):
        """Test get_nist_control_status when no NIST standard is enabled."""
        # Setup mock response with no NIST standard
        mock_security_hub = MagicMock()
        mock_security_hub.get_enabled_standards.return_value = {
            "StandardsSubscriptions": [
                {
                    "StandardsArn": "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.2.0",
                    "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.2.0"
                }
            ]
        }
        mock_boto_client.return_value = mock_security_hub
        
        # Call function
        control_status = get_nist_control_status()
        
        # Verify boto3 client was called
        mock_boto_client.assert_called_with("securityhub")
        
        # Verify we got an empty result
        self.assertEqual(control_status, {})


if __name__ == '__main__':
    unittest.main()