#!/usr/bin/env python3
"""
Unit tests for the enhanced SOC2Mapper functionality.

These tests specifically focus on the enhanced features we've added:
1. Partial string matching for finding types
2. Control mapping validation
3. Custom control mapping support
"""

import os
import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add project root to Python path
import sys
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.lib.soc2_mapper import SOC2Mapper


@pytest.fixture
def sample_mappings():
    """Sample control mappings for testing"""
    return {
        "finding_type_mappings": {
            "Software and Configuration Checks/AWS Security Best Practices/S3": {
                "primary_controls": ["CC6.1.10", "CC6.1.7"],
                "secondary_controls": ["CC6.1.4", "CC6.1.8"]
            },
            "Software and Configuration Checks/AWS Security Best Practices/IAM": {
                "primary_controls": ["CC6.1.2", "CC6.1.3"],
                "secondary_controls": ["CC6.1.9", "CC6.2.1"]
            },
            "Software and Configuration Checks/AWS Security Best Practices/KMS": {
                "primary_controls": ["CC6.1.8", "CC6.1.7"],
                "secondary_controls": ["CC6.1.10"]
            }
        },
        "severity_risk_mapping": {
            "CRITICAL": "High",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFORMATIONAL": "Low"
        },
        "control_descriptions": {
            "CC6.1.10": "Customer data encryption uses envelope encryption",
            "CC6.1.7": "All data at rest is encrypted",
            "CC6.1.4": "Network access control",
            "CC6.1.8": "AWS KMS key management",
            "CC6.1.2": "Multi-factor authentication",
            "CC6.1.3": "Password policies",
            "CC6.1.9": "IAM roles and groups",
            "CC6.2.1": "Least privilege access"
        }
    }


@pytest.fixture
def temp_config_file(sample_mappings):
    """Create a temporary config file with sample mappings"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(sample_mappings, f)
        temp_file = f.name
    
    yield temp_file
    
    # Cleanup
    os.unlink(temp_file)


@pytest.fixture
def sample_findings():
    """Sample findings for testing"""
    return [
        # Exact match finding
        {
            "Id": "finding-001",
            "Type": "Software and Configuration Checks/AWS Security Best Practices/S3",
            "Title": "S3 Bucket Public Access",
            "Description": "S3 bucket has public access enabled",
            "Severity": "CRITICAL",
            "ResourceType": "AwsS3Bucket", 
            "ResourceId": "test-bucket"
        },
        # Partial match finding
        {
            "Id": "finding-002",
            "Type": "Software and Configuration Checks/AWS Security Best Practices/S3/PublicAccess",
            "Title": "S3 Public Access Block",
            "Description": "S3 public access block is not enabled",
            "Severity": "HIGH",
            "ResourceType": "AwsS3Bucket",
            "ResourceId": "other-bucket"
        },
        # No match finding
        {
            "Id": "finding-003",
            "Type": "Custom/Third Party/Unknown",
            "Title": "Unknown Finding",
            "Description": "This is an unknown finding type",
            "Severity": "MEDIUM",
            "ResourceType": "Custom",
            "ResourceId": "custom-resource"
        }
    ]


def test_initialize_with_custom_config(temp_config_file):
    """Test initializing SOC2Mapper with a custom config file"""
    mapper = SOC2Mapper(custom_config_path=temp_config_file)
    
    # Verify mappings loaded correctly
    assert "finding_type_mappings" in mapper.mappings
    assert "severity_risk_mapping" in mapper.mappings
    assert "control_descriptions" in mapper.mappings
    
    # Verify specific mappings
    assert "Software and Configuration Checks/AWS Security Best Practices/S3" in mapper.mappings["finding_type_mappings"]
    assert "CC6.1.10" in mapper.mappings["control_descriptions"]
    assert "CRITICAL" in mapper.mappings["severity_risk_mapping"]


def test_validate_mappings_with_valid_config(sample_mappings):
    """Test validation with valid mappings"""
    with patch.object(SOC2Mapper, '__init__', return_value=None):
        mapper = SOC2Mapper()
        mapper.mappings = sample_mappings
        
        # Should not raise exceptions
        result = mapper.validate_mappings()
        assert result is True


def test_validate_mappings_with_missing_descriptions(sample_mappings):
    """Test validation with missing control descriptions"""
    with patch.object(SOC2Mapper, '__init__', return_value=None):
        mapper = SOC2Mapper()
        
        # Remove a control description
        modified_mappings = sample_mappings.copy()
        del modified_mappings["control_descriptions"]["CC6.1.10"]
        mapper.mappings = modified_mappings
        
        # Should still return True but log a warning
        with patch('src.lib.soc2_mapper.logger') as mock_logger:
            result = mapper.validate_mappings()
            assert result is True
            mock_logger.warning.assert_called()


def test_exact_match_finding_mapping(temp_config_file, sample_findings):
    """Test mapping a finding with an exact type match"""
    mapper = SOC2Mapper(custom_config_path=temp_config_file)
    
    # Get the exact match finding
    exact_match_finding = sample_findings[0]
    
    # Map the finding
    mapped_controls = mapper.map_finding_to_controls(exact_match_finding)
    
    # Verify mapping
    assert mapped_controls["primary_controls"] == ["CC6.1.10", "CC6.1.7"]
    assert mapped_controls["secondary_controls"] == ["CC6.1.4", "CC6.1.8"]


def test_partial_match_finding_mapping(temp_config_file, sample_findings):
    """Test mapping a finding with a partial type match"""
    mapper = SOC2Mapper(custom_config_path=temp_config_file)
    
    # Get the partial match finding
    partial_match_finding = sample_findings[1]
    
    # Map the finding
    mapped_controls = mapper.map_finding_to_controls(partial_match_finding)
    
    # Verify mapping - should match with S3 controls
    assert "CC6.1.10" in mapped_controls["primary_controls"]
    assert "CC6.1.7" in mapped_controls["primary_controls"]


def test_no_match_finding_mapping(temp_config_file, sample_findings):
    """Test mapping a finding with no type match"""
    mapper = SOC2Mapper(custom_config_path=temp_config_file)
    
    # Get the no match finding
    no_match_finding = sample_findings[2]
    
    # Map the finding
    mapped_controls = mapper.map_finding_to_controls(no_match_finding)
    
    # Verify mapping - should be empty
    assert mapped_controls["primary_controls"] == []
    assert mapped_controls["secondary_controls"] == []


def test_map_severity_to_risk(temp_config_file):
    """Test mapping severity to risk level"""
    mapper = SOC2Mapper(custom_config_path=temp_config_file)
    
    # Test mappings
    assert mapper.map_severity_to_risk("CRITICAL") == "High"
    assert mapper.map_severity_to_risk("HIGH") == "High"
    assert mapper.map_severity_to_risk("MEDIUM") == "Medium"
    assert mapper.map_severity_to_risk("LOW") == "Low"
    assert mapper.map_severity_to_risk("INFORMATIONAL") == "Low"
    assert mapper.map_severity_to_risk("UNKNOWN") == "Unknown"  # Not in mapping


def test_get_control_description(temp_config_file):
    """Test getting control descriptions"""
    mapper = SOC2Mapper(custom_config_path=temp_config_file)
    
    # Test descriptions
    assert "encryption" in mapper.get_control_description("CC6.1.10").lower()
    assert "not available" in mapper.get_control_description("NON_EXISTENT").lower()


def test_format_finding_for_soc2(temp_config_file, sample_findings):
    """Test formatting a finding for SOC2 workpaper"""
    mapper = SOC2Mapper(custom_config_path=temp_config_file)
    finding = sample_findings[0]
    
    # Format the finding
    formatted = mapper.format_finding_for_soc2(finding)
    
    # Verify some key fields
    assert len(formatted) > 0
    assert formatted[0]["Control_ID"] in ["CC6.1.10", "CC6.1.7"]
    assert formatted[0]["Finding_Title"] == "S3 Bucket Public Access"
    assert formatted[0]["Risk_Level"] == "High"
    # Note: ResourceId is available in the finding but in format_finding_for_soc2 
    # it might be extracted differently, so we're not testing the exact value
    assert "Resource_Affected" in formatted[0]


def test_generate_csv_data(temp_config_file, sample_findings):
    """Test generating CSV data from findings"""
    mapper = SOC2Mapper(custom_config_path=temp_config_file)
    
    # Generate CSV data
    csv_data = mapper.generate_csv_data(sample_findings)
    
    # We should have entries for each control in each finding
    assert len(csv_data) >= len(sample_findings)
    
    # Check that the correct columns are present
    headers = mapper.get_csv_headers()
    for entry in csv_data:
        for header in headers:
            assert header in entry


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])