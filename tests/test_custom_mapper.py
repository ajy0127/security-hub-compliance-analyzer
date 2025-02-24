#!/usr/bin/env python3
"""
Unit tests for the CustomControlMapper functionality.

These tests focus on the organization-specific mapping features:
1. Custom control definitions
2. Regex-based mapping
3. Resource-specific mapping
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

from src.lib.custom_mapper import CustomControlMapper, get_custom_mapper


@pytest.fixture
def sample_custom_mappings():
    """Sample custom control mappings for testing"""
    return {
        "custom_controls": {
            "ORG.SEC.1": "Custom security control 1",
            "ORG.SEC.2": "Custom security control 2"
        },
        "regex_mappings": {
            "password|credential": {
                "primary_controls": ["ORG.SEC.2", "CC6.1.2"],
                "secondary_controls": ["CC6.1.3"]
            },
            "encryption|encrypted": {
                "primary_controls": ["ORG.SEC.1", "CC6.1.7"],
                "secondary_controls": ["CC6.1.8"]
            }
        },
        "resource_mappings": {
            "AwsS3Bucket": {
                "primary_controls": ["ORG.SEC.1"],
                "secondary_controls": ["CC6.1.10"]
            },
            "AwsIamRole": {
                "primary_controls": ["ORG.SEC.2"],
                "secondary_controls": ["CC6.1.2"]
            }
        }
    }


@pytest.fixture
def temp_custom_config(sample_custom_mappings):
    """Create a temporary custom config file"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json.dump(sample_custom_mappings, f)
        temp_file = f.name
    
    yield temp_file
    
    # Cleanup
    os.unlink(temp_file)


@pytest.fixture
def sample_findings():
    """Sample findings for testing custom mapping"""
    return [
        # Finding with regex match in title
        {
            "Id": "finding-001",
            "Type": "Software and Configuration Checks/Something/Custom",
            "Title": "Unencrypted S3 bucket",
            "Description": "S3 bucket is not encrypted",
            "Severity": "HIGH",
            "ResourceType": "AwsS3Bucket",
            "ResourceId": "test-bucket"
        },
        # Finding with regex match in description
        {
            "Id": "finding-002",
            "Type": "Software and Configuration Checks/Something/Custom",
            "Title": "Insecure Configuration",
            "Description": "User has hardcoded password in configuration",
            "Severity": "CRITICAL",
            "ResourceType": "AwsLambdaFunction",
            "ResourceId": "lambda-function"
        },
        # Finding with resource mapping match
        {
            "Id": "finding-003",
            "Type": "Software and Configuration Checks/Something/Custom",
            "Title": "Misconfigured Role",
            "Description": "IAM role has excessive permissions",
            "Severity": "MEDIUM",
            "ResourceType": "AwsIamRole",
            "ResourceId": "role-name"
        }
    ]


def test_load_custom_config(temp_custom_config, sample_custom_mappings):
    """Test loading custom configuration"""
    # Mock environment variable to use our temp file
    with patch.dict(os.environ, {"CUSTOM_CONTROL_CONFIG_PATH": temp_custom_config}):
        mapper = CustomControlMapper()
        
        # Verify custom controls were loaded
        assert mapper.custom_controls == sample_custom_mappings["custom_controls"]
        assert mapper.regex_mappings == sample_custom_mappings["regex_mappings"]
        assert mapper.resource_mappings == sample_custom_mappings["resource_mappings"]
        
        # Verify control descriptions were added to main mappings
        for control_id, desc in sample_custom_mappings["custom_controls"].items():
            assert control_id in mapper.mappings["control_descriptions"]
            assert mapper.mappings["control_descriptions"][control_id] == desc


def test_regex_mapping(temp_custom_config, sample_findings):
    """Test regex-based mapping"""
    # Mock environment variable to use our temp file
    with patch.dict(os.environ, {"CUSTOM_CONTROL_CONFIG_PATH": temp_custom_config}):
        mapper = CustomControlMapper()
        
        # Test finding with "encryption" in title
        finding = sample_findings[0]
        mapped_controls = mapper.map_finding_to_controls(finding)
        
        # Should match the encryption regex pattern
        assert "ORG.SEC.1" in mapped_controls["primary_controls"]
        assert "CC6.1.7" in mapped_controls["primary_controls"]
        assert "CC6.1.8" in mapped_controls["secondary_controls"]
        
        # Test finding with "password" in description
        finding = sample_findings[1]
        mapped_controls = mapper.map_finding_to_controls(finding)
        
        # Should match the password regex pattern
        assert "ORG.SEC.2" in mapped_controls["primary_controls"]
        assert "CC6.1.2" in mapped_controls["primary_controls"]
        assert "CC6.1.3" in mapped_controls["secondary_controls"]


def test_resource_mapping(temp_custom_config, sample_findings):
    """Test resource-based mapping"""
    # Mock environment variable to use our temp file
    with patch.dict(os.environ, {"CUSTOM_CONTROL_CONFIG_PATH": temp_custom_config}):
        mapper = CustomControlMapper()
        
        # Test finding with S3 bucket resource
        finding = sample_findings[0]
        mapped_controls = mapper.map_finding_to_controls(finding)
        
        # Should match the S3 resource mapping
        assert "ORG.SEC.1" in mapped_controls["primary_controls"]
        assert "CC6.1.10" in mapped_controls["secondary_controls"]
        
        # Test finding with IAM role resource
        finding = sample_findings[2]
        mapped_controls = mapper.map_finding_to_controls(finding)
        
        # Should match the IAM role resource mapping
        assert "ORG.SEC.2" in mapped_controls["primary_controls"]
        assert "CC6.1.2" in mapped_controls["secondary_controls"]


def test_combined_mappings(temp_custom_config, sample_findings):
    """Test combining different mapping methods"""
    # Mock environment variable to use our temp file
    with patch.dict(os.environ, {"CUSTOM_CONTROL_CONFIG_PATH": temp_custom_config}):
        mapper = CustomControlMapper()
        
        # Finding with both regex match (encryption) and resource match (S3 bucket)
        finding = sample_findings[0]
        mapped_controls = mapper.map_finding_to_controls(finding)
        
        # Should include controls from both mapping methods
        assert "ORG.SEC.1" in mapped_controls["primary_controls"]
        assert "CC6.1.7" in mapped_controls["primary_controls"]
        assert "CC6.1.8" in mapped_controls["secondary_controls"]
        assert "CC6.1.10" in mapped_controls["secondary_controls"]
        
        # Ensure no duplicates
        assert len(mapped_controls["primary_controls"]) == len(set(mapped_controls["primary_controls"]))
        assert len(mapped_controls["secondary_controls"]) == len(set(mapped_controls["secondary_controls"]))
        
        # Ensure primary controls are not in secondary controls
        for control in mapped_controls["primary_controls"]:
            assert control not in mapped_controls["secondary_controls"]


def test_get_custom_mapper():
    """Test get_custom_mapper factory function"""
    mapper = get_custom_mapper()
    assert isinstance(mapper, CustomControlMapper)


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])