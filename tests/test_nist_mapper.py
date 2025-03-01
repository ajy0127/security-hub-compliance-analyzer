import unittest
import sys
import os

# Add the src directory to the path so we can import the modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.mapper_factory import NIST80053Mapper


class TestNIST80053Mapper(unittest.TestCase):
    """Unit tests for the NIST80053Mapper class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mapper = NIST80053Mapper()

    def test_map_finding_encryption(self):
        """Test mapping a finding related to encryption."""
        finding = {
            "Title": "Encryption missing on S3 bucket",
            "Description": "S3 bucket is not using encryption for data at rest",
            "Severity": {"Label": "HIGH"},
            "Types": ["Software and Configuration Checks"],
            "Resources": [{"Id": "arn:aws:s3:::example-bucket"}]
        }
        result = self.mapper.map_finding(finding)
        self.assertIn("SC-13", result["NIST800-53Controls"])
        self.assertIn("SC-28", result["NIST800-53Controls"])

    def test_map_finding_network(self):
        """Test mapping a finding related to network security."""
        finding = {
            "Title": "Security group allows unrestricted access",
            "Description": "A security group has a rule that allows unrestricted access",
            "Severity": {"Label": "CRITICAL"},
            "Types": ["Network Reachability"],
            "Resources": [{"Id": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345"}]
        }
        result = self.mapper.map_finding(finding)
        self.assertIn("SC-7", result["NIST800-53Controls"])
        self.assertIn("AC-4", result["NIST800-53Controls"])
        self.assertIn("AC-17", result["NIST800-53Controls"])

    def test_map_finding_default(self):
        """Test mapping a finding with no specific matches."""
        finding = {
            "Title": "Generic finding with no specific keywords",
            "Description": "This is a generic description",
            "Severity": {"Label": "LOW"},
            "Types": ["Unknown Type"],
            "Resources": [{"Id": "arn:aws:ec2::123456789012:instance/i-12345"}]
        }
        result = self.mapper.map_finding(finding)
        self.assertEqual(["SI-4"], result["NIST800-53Controls"])


if __name__ == '__main__':
    unittest.main()