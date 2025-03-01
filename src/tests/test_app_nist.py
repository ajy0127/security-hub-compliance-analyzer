import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from app import generate_nist_cato_report, get_nist_control_status


class TestAppNIST:
    @pytest.fixture
    def mock_securityhub(self):
        with patch("boto3.client") as mock_client:
            mock_sh = MagicMock()
            mock_client.return_value = mock_sh
            yield mock_sh

    @pytest.fixture
    def sample_standards_response(self):
        return {
            "StandardsSubscriptions": [
                {
                    "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
                    "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.2.0",
                },
                {
                    "StandardsArn": "arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0",
                    "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:123456789012:subscription/nist-800-53/v/5.0.0",
                },
            ]
        }

    @pytest.fixture
    def sample_controls_response(self):
        return {
            "Controls": [
                {
                    "ControlId": "NIST.800-53.r5-AC-1",
                    "Title": "Access Control Policy and Procedures",
                    "Description": "The organization develops and maintains access control policies.",
                    "ControlStatus": "ENABLED",
                    "ComplianceStatus": "PASSED",
                    "SeverityRating": "HIGH",
                    "DisabledReason": "",
                    "RelatedRequirements": ["SOC2 CC1.1"],
                },
                {
                    "ControlId": "NIST.800-53.r5-AC-2",
                    "Title": "Account Management",
                    "Description": "The organization manages system accounts.",
                    "ControlStatus": "ENABLED",
                    "ComplianceStatus": "FAILED",
                    "SeverityRating": "CRITICAL",
                    "DisabledReason": "",
                    "RelatedRequirements": ["SOC2 CC1.2"],
                },
                {
                    "ControlId": "NIST.800-53.r5-CM-1",
                    "Title": "Configuration Management Policy",
                    "Description": "The organization develops configuration management policies.",
                    "ControlStatus": "DISABLED",
                    "ComplianceStatus": "",
                    "SeverityRating": "MEDIUM",
                    "DisabledReason": "Not applicable for this environment",
                    "RelatedRequirements": [],
                },
            ]
        }

    def test_get_nist_control_status_success(
        self, mock_securityhub, sample_standards_response, sample_controls_response
    ):
        # Setup mock responses
        mock_securityhub.get_enabled_standards.return_value = sample_standards_response
        mock_securityhub.describe_standards_controls.return_value = (
            sample_controls_response
        )

        # Call the function
        result = get_nist_control_status()

        # Verify the results
        # Our implementation will now return ALL NIST controls (about 288+ controls)
        # rather than just the 3 in the sample data
        assert len(result) > 3  # We should have more than just the 3 test controls
        assert "AC-1" in result  # But we should still have our test controls
        assert "AC-2" in result
        assert "CM-1" in result

        # Verify specific control details
        ac1 = result["AC-1"]
        assert ac1["status"] == "PASSED"
        assert ac1["severity"] == "HIGH"
        assert not ac1["disabled"]

        ac2 = result["AC-2"]
        assert ac2["status"] == "FAILED"
        assert ac2["severity"] == "CRITICAL"
        assert not ac2["disabled"]

        cm1 = result["CM-1"]
        assert cm1["status"] == "NOT_APPLICABLE"
        assert cm1["severity"] == "MEDIUM"
        assert cm1["disabled"]

    def test_get_nist_control_status_no_nist_standard(self, mock_securityhub):
        # Setup mock response without NIST standard
        mock_securityhub.get_enabled_standards.return_value = {
            "StandardsSubscriptions": [
                {
                    "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
                    "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:123456789012:subscription/cis-aws-foundations-benchmark/v/1.2.0",
                }
            ]
        }

        # Call the function
        result = get_nist_control_status()

        # Verify empty result when NIST standard is not found
        assert result == {}

    def test_get_nist_control_status_api_error(self, mock_securityhub):
        # Setup mock to raise an exception
        mock_securityhub.get_enabled_standards.side_effect = Exception("API Error")

        # Call the function
        result = get_nist_control_status()

        # Verify empty result on error
        assert result == {}

    def test_generate_nist_cato_report(
        self, mock_securityhub, sample_standards_response, sample_controls_response
    ):
        # Setup mock responses
        mock_securityhub.get_enabled_standards.return_value = sample_standards_response
        mock_securityhub.describe_standards_controls.return_value = (
            sample_controls_response
        )

        # Call the function
        report_text, statistics, control_families = generate_nist_cato_report()

        # Verify report content
        assert isinstance(report_text, str)
        assert "# NIST 800-53 Control Status for cATO" in report_text
        assert "## Executive Summary" in report_text
        assert "## Control Family Status" in report_text

        # Verify statistics
        assert isinstance(statistics, dict)
        assert "total_controls" in statistics
        assert statistics["total_controls"] > 3  # We now have all NIST controls
        assert "passing_controls" in statistics
        assert statistics["passing_controls"] >= 1  # At minimum, the one from our test
        assert "failing_controls" in statistics
        assert statistics["failing_controls"] >= 1  # At minimum, the one from our test
        assert "not_applicable_controls" in statistics
        assert statistics["not_applicable_controls"] >= 1  # At minimum, the one from our test

        # Verify control families
        assert isinstance(control_families, dict)
        # Since we can have different numbers of controls based on initialization
        # Make the assertions more flexible
        assert "AC" in control_families  # Access Control family
        assert "CM" in control_families  # Configuration Management family
        assert len(control_families["AC"]["controls"]) >= 2  # Should have at least 2 AC controls
        assert len(control_families["CM"]["controls"]) >= 1  # Should have at least 1 CM control
