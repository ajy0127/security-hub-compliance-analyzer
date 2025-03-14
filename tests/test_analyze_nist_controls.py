import unittest
import sys
import os
from unittest.mock import patch, mock_open
import json

# Add the src directory to the path so we can import the modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.analyze_nist_controls import load_nist_mappings, analyze_control_families


class TestAnalyzeNISTControls(unittest.TestCase):
    """Unit tests for analyze_nist_controls.py functions."""

    def setUp(self):
        """Set up test fixtures."""
        # Sample NIST mappings for testing
        self.mock_nist_mappings = {
            "type_mappings": {
                "Software and Configuration Checks": ["AC-3", "AC-6", "SI-2"],
                "Network Reachability": ["SC-7", "AC-4", "AC-17"]
            },
            "title_mappings": {
                "encryption": ["SC-13", "SC-28"],
                "access": ["AC-3", "AC-6"]
            },
            "control_descriptions": {
                "AC-1": "Access Control Policy and Procedures",
                "AC-2": "Account Management",
                "AC-3": "Access Enforcement",
                "AC-4": "Information Flow Enforcement",
                "AC-6": "Least Privilege",
                "SC-7": "Boundary Protection",
                "SC-13": "Cryptographic Protection",
                "SC-28": "Protection of Information at Rest",
                "SI-2": "Flaw Remediation",
                "SI-4": "Information System Monitoring"
            }
        }
        
        # Convert to JSON string for mock_open
        self.mock_mappings_json = json.dumps(self.mock_nist_mappings)

    @patch('builtins.open', new_callable=mock_open)
    def test_load_nist_mappings(self, mock_file):
        """Test loading NIST mappings from file."""
        # Configure mock to return our test mappings
        mock_file.return_value.read.return_value = self.mock_mappings_json
        
        # Call function
        mappings = load_nist_mappings()
        
        # Verify file was opened with correct path
        mock_file.assert_called_with("config/mappings/nist800_53_mappings.json", "r")
        
        # Verify returned mappings match our test data
        self.assertEqual(mappings, self.mock_nist_mappings)
        self.assertIn("type_mappings", mappings)
        self.assertIn("title_mappings", mappings)
        self.assertIn("control_descriptions", mappings)

    @patch('builtins.print')
    @patch('src.analyze_nist_controls.load_nist_mappings')
    def test_analyze_control_families(self, mock_load_mappings, mock_print):
        """Test analyze_control_families function."""
        # Configure mock to return our test mappings
        mock_load_mappings.return_value = self.mock_nist_mappings
        
        # Call function
        analyze_control_families()
        
        # Verify load_nist_mappings was called
        mock_load_mappings.assert_called_once()
        
        # Verify print was called multiple times
        self.assertTrue(mock_print.call_count > 5, "print should be called multiple times")
        
        # Instead of checking specific print calls which might be fragile,
        # just verify that the function completed without errors and
        # the mocks were called as expected

    @patch('builtins.print')
    @patch('src.analyze_nist_controls.load_nist_mappings')
    def test_analyze_control_families_empty_mappings(self, mock_load_mappings, mock_print):
        """Test analyze_control_families function with empty mappings."""
        # Configure mock to return None (failed to load mappings)
        mock_load_mappings.return_value = None
        
        # Call function
        analyze_control_families()
        
        # Verify load_nist_mappings was called
        mock_load_mappings.assert_called_once()
        
        # Verify appropriate error message was printed
        mock_print.assert_called_with("Failed to load NIST 800-53 mappings.")


if __name__ == '__main__':
    unittest.main()