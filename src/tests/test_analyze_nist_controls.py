import json
import os
from unittest.mock import mock_open, patch

import pytest

from analyze_nist_controls import analyze_control_families, load_nist_mappings


class TestAnalyzeNISTControls:
    @pytest.fixture
    def sample_mappings(self):
        return {
            "control_descriptions": {
                "AC-1": "Access Control Policy and Procedures",
                "AC-2": "Account Management",
                "AU-1": "Audit and Accountability Policy and Procedures",
                "CM-1": "Configuration Management Policy and Procedures",
                "SI-1": "System and Information Integrity Policy",
            }
        }

    def test_load_nist_mappings_success(self, sample_mappings):
        mock_file_content = json.dumps(sample_mappings)
        with patch("builtins.open", mock_open(read_data=mock_file_content)):
            result = load_nist_mappings()
            assert result == sample_mappings
            assert "control_descriptions" in result
            assert len(result["control_descriptions"]) == 5

    def test_load_nist_mappings_file_not_found(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = load_nist_mappings()
            assert result is None

    def test_load_nist_mappings_invalid_json(self):
        with patch("builtins.open", mock_open(read_data="invalid json")):
            result = load_nist_mappings()
            assert result is None

    def test_analyze_control_families_with_mappings(self, sample_mappings, capsys):
        with patch(
            "analyze_nist_controls.load_nist_mappings", return_value=sample_mappings
        ):
            analyze_control_families()
            captured = capsys.readouterr()
            output = captured.out

            # Verify key sections are present
            assert "NIST 800-53 Control Families Analysis" in output
            assert "Total Controls: 5" in output
            assert "Control Distribution by Family:" in output
            assert "Continuous ATO (cATO) Key Control Families:" in output

            # Verify control families are listed
            assert "AC - Access Control: 2 controls" in output
            assert "AU - Audit and Accountability: 1 controls" in output
            assert "CM - Configuration Management: 1 controls" in output
            assert "SI - System and Information Integrity: 1 controls" in output

    def test_analyze_control_families_no_mappings(self, capsys):
        with patch("analyze_nist_controls.load_nist_mappings", return_value=None):
            analyze_control_families()
            captured = capsys.readouterr()
            assert "Failed to load NIST 800-53 mappings." in captured.out

    def test_analyze_control_families_empty_mappings(self, capsys):
        with patch(
            "analyze_nist_controls.load_nist_mappings",
            return_value={"control_descriptions": {}},
        ):
            analyze_control_families()
            captured = capsys.readouterr()
            assert "Total Controls: 0" in captured.out
            assert "Control Families: 0" in captured.out
