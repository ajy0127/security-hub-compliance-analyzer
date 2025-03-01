import unittest
import sys
import os

# Add the src directory to the path so we can import the modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.soc2_mapper import SOC2Mapper


class TestSOC2Mapper(unittest.TestCase):
    """Unit tests for the SOC2Mapper class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mapper = SOC2Mapper()

    def test_map_finding_encryption(self):
        """Test mapping a finding related to encryption."""
        finding = {
            "Title": "Encryption missing on S3 bucket",
            "Description": "S3 bucket is not using encryption",
            "Severity": {"Label": "HIGH"},
            "Types": ["Software and Configuration Checks"],
            "Resources": [{"Id": "arn:aws:s3:::example-bucket"}]
        }
        result = self.mapper.map_finding(finding)
        self.assertIn("CC6.1", result["SOC2Controls"])
        self.assertIn("CC6.7", result["SOC2Controls"])

    def test_map_finding_access(self):
        """Test mapping a finding related to access."""
        finding = {
            "Title": "IAM user has excessive permissions",
            "Description": "IAM user has overly permissive access",
            "Severity": {"Label": "MEDIUM"},
            "Types": ["Software and Configuration Checks"],
            "Resources": [{"Id": "arn:aws:iam::123456789012:user/example-user"}]
        }
        result = self.mapper.map_finding(finding)
        self.assertIn("CC6.1", result["SOC2Controls"])
        self.assertIn("CC6.3", result["SOC2Controls"])

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
        self.assertIn("CC6.1", result["SOC2Controls"])

    def test_control_id_attribute(self):
        """Test the control_id_attribute method."""
        self.assertEqual("SOC2Controls", self.mapper.get_control_id_attribute())


if __name__ == '__main__':
    unittest.main()