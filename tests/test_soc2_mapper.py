import pytest
from datetime import datetime
from src.lib.soc2_mapper import SOC2Mapper
import json
from pathlib import Path

@pytest.fixture
def soc2_mapper():
    return SOC2Mapper()

@pytest.fixture
def sample_finding():
    return {
        'Id': 'test-finding-001',
        'Type': 'Software and Configuration Checks/AWS Security Best Practices/S3',
        'Title': 'S3 Bucket Public Access',
        'Description': 'S3 bucket has public access enabled',
        'Severity': 'CRITICAL',
        'Resources': [{'Id': 'arn:aws:s3:::test-bucket'}],
        'Remediation': {
            'Recommendation': {
                'Text': 'Disable public access'
            }
        },
        'ProductArn': 'arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1',
        'CreatedAt': '2024-02-23T00:00:00Z',
        'UpdatedAt': '2024-02-23T01:00:00Z'
    }

def test_map_severity_to_risk(soc2_mapper):
    assert soc2_mapper.map_severity_to_risk('CRITICAL') == 'High'
    assert soc2_mapper.map_severity_to_risk('HIGH') == 'High'
    assert soc2_mapper.map_severity_to_risk('MEDIUM') == 'Medium'
    assert soc2_mapper.map_severity_to_risk('LOW') == 'Low'
    assert soc2_mapper.map_severity_to_risk('INFORMATIONAL') == 'Low'
    assert soc2_mapper.map_severity_to_risk('UNKNOWN') == 'Unknown'
    # Edge case: None severity
    assert soc2_mapper.map_severity_to_risk(None) == 'Unknown'
    # Edge case: Empty string
    assert soc2_mapper.map_severity_to_risk('') == 'Unknown'
    # Edge case: Invalid severity
    assert soc2_mapper.map_severity_to_risk('INVALID_SEVERITY') == 'Unknown'

def test_get_csv_headers(soc2_mapper):
    headers = soc2_mapper.get_csv_headers()
    assert isinstance(headers, list)
    assert 'Control_ID' in headers
    assert 'Finding_Title' in headers
    assert 'Risk_Level' in headers
    # Test order of headers
    assert headers.index('Control_ID') < headers.index('Finding_Title')
    assert headers.index('Finding_Title') < headers.index('Risk_Level')
    # Test all required headers are present
    required_headers = [
        'Control_ID', 'Control_Description', 'SecurityHub_Finding_ID',
        'Finding_Title', 'Finding_Description', 'Risk_Level',
        'Resource_Affected', 'Control_Status', 'Remediation_Steps',
        'Remediation_Timeline', 'Evidence_Reference', 'Audit_Impact',
        'Test_Procedures', 'Compensating_Controls', 'Finding_Created_At',
        'Last_Updated'
    ]
    assert all(header in headers for header in required_headers)
    assert len(headers) == len(required_headers)

def test_map_finding_to_controls_general(soc2_mapper):
    test_finding = {
        'Type': 'Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices'
    }
    mapped_controls = soc2_mapper.map_finding_to_controls(test_finding)
    assert isinstance(mapped_controls, dict)
    assert 'primary_controls' in mapped_controls
    assert 'secondary_controls' in mapped_controls
    assert isinstance(mapped_controls['primary_controls'], list)
    assert isinstance(mapped_controls['secondary_controls'], list)
    # Test specific controls are mapped
    assert 'CC6.1' in mapped_controls['primary_controls']
    assert 'CC8.1' in mapped_controls['secondary_controls']

def test_map_finding_to_controls_aws_services(soc2_mapper):
    # Test S3-related finding
    s3_finding = {
        'Type': 'Software and Configuration Checks/AWS Security Best Practices/S3'
    }
    s3_controls = soc2_mapper.map_finding_to_controls(s3_finding)
    assert 'CC6.1.10' in s3_controls['primary_controls']
    assert 'CC6.1.7' in s3_controls['primary_controls']
    
    # Test IAM-related finding
    iam_finding = {
        'Type': 'Software and Configuration Checks/AWS Security Best Practices/IAM'
    }
    iam_controls = soc2_mapper.map_finding_to_controls(iam_finding)
    assert 'CC6.1.2' in iam_controls['primary_controls']
    assert 'CC6.1.3' in iam_controls['primary_controls']
    
    # Test KMS-related finding
    kms_finding = {
        'Type': 'Software and Configuration Checks/AWS Security Best Practices/KMS'
    }
    kms_controls = soc2_mapper.map_finding_to_controls(kms_finding)
    assert 'CC6.1.8' in kms_controls['primary_controls']
    assert 'CC6.1.7' in kms_controls['primary_controls']

def test_map_finding_to_controls_security_services(soc2_mapper):
    # Test WAF-related finding
    waf_finding = {
        'Type': 'Software and Configuration Checks/AWS Security Best Practices/WAF'
    }
    waf_controls = soc2_mapper.map_finding_to_controls(waf_finding)
    assert 'CC6.6.3' in waf_controls['primary_controls']
    assert 'CC6.1.4' in waf_controls['primary_controls']
    
    # Test CloudTrail-related finding
    cloudtrail_finding = {
        'Type': 'Software and Configuration Checks/AWS Security Best Practices/CloudTrail'
    }
    cloudtrail_controls = soc2_mapper.map_finding_to_controls(cloudtrail_finding)
    assert 'CC6.6.2' in cloudtrail_controls['primary_controls']
    assert 'CC6.6.4' in cloudtrail_controls['primary_controls']

def test_map_finding_to_controls_container_services(soc2_mapper):
    # Test EKS-related finding
    eks_finding = {
        'Type': 'Software and Configuration Checks/AWS Security Best Practices/EKS'
    }
    eks_controls = soc2_mapper.map_finding_to_controls(eks_finding)
    assert 'CC7.1.5' in eks_controls['primary_controls']
    assert 'CC6.6.1' in eks_controls['primary_controls']

def test_get_control_description(soc2_mapper):
    # Test basic control description
    assert "logical access security" in soc2_mapper.get_control_description('CC6.1').lower()
    
    # Test AWS-specific control descriptions
    mfa_desc = soc2_mapper.get_control_description('CC6.1.2')
    assert "mfa" in mfa_desc.lower()
    assert "root accounts" in mfa_desc.lower()
    
    kms_desc = soc2_mapper.get_control_description('CC6.1.8')
    assert "kms" in kms_desc.lower()
    assert "key rotation" in kms_desc.lower()
    
    # Test non-existent control
    assert "Description not available" == soc2_mapper.get_control_description('NON_EXISTENT')
    # Test empty control ID
    assert "Description not available" == soc2_mapper.get_control_description('')
    # Test None control ID
    assert "Description not available" == soc2_mapper.get_control_description(None)

def test_partial_finding_type_match(soc2_mapper):
    # Test finding with partial type match
    partial_finding = {
        'Type': 'Software and Configuration Checks/AWS Security Best Practices/Something/S3/Bucket'
    }
    mapped_controls = soc2_mapper.map_finding_to_controls(partial_finding)
    assert len(mapped_controls['primary_controls']) > 0
    assert len(mapped_controls['secondary_controls']) > 0

def test_edge_cases_finding_type(soc2_mapper):
    # Test empty finding type
    empty_finding = {'Type': ''}
    empty_controls = soc2_mapper.map_finding_to_controls(empty_finding)
    assert len(empty_controls['primary_controls']) == 0
    assert len(empty_controls['secondary_controls']) == 0
    
    # Test missing Type field
    no_type_finding = {}
    no_type_controls = soc2_mapper.map_finding_to_controls(no_type_finding)
    assert len(no_type_controls['primary_controls']) == 0
    assert len(no_type_controls['secondary_controls']) == 0
    
    # Test None finding
    assert soc2_mapper.map_finding_to_controls(None) == {'primary_controls': [], 'secondary_controls': []}

def test_format_finding_for_soc2(soc2_mapper, sample_finding):
    formatted_findings = soc2_mapper.format_finding_for_soc2(sample_finding)
    assert isinstance(formatted_findings, list)
    assert len(formatted_findings) > 0
    
    first_finding = formatted_findings[0]
    # Test required fields
    assert first_finding['Control_ID']
    assert first_finding['Finding_Title'] == 'S3 Bucket Public Access'
    assert first_finding['Risk_Level'] == 'High'
    assert first_finding['Resource_Affected'] == 'arn:aws:s3:::test-bucket'
    
    # Test control status logic
    assert first_finding['Control_Status'] == 'Fail'  # Because severity is CRITICAL
    assert first_finding['Remediation_Timeline'] == '30 days'  # Because risk is High
    
    # Test date handling
    assert first_finding['Finding_Created_At'] == '2024-02-23T00:00:00Z'
    assert first_finding['Last_Updated'] == '2024-02-23T01:00:00Z'

def test_generate_csv_data(soc2_mapper, sample_finding):
    findings = [sample_finding]
    csv_data = soc2_mapper.generate_csv_data(findings)
    assert isinstance(csv_data, list)
    assert len(csv_data) > 0
    
    # Test CSV data structure
    first_row = csv_data[0]
    headers = soc2_mapper.get_csv_headers()
    assert all(header in first_row for header in headers)
    
    # Test multiple findings
    multiple_findings = [sample_finding, sample_finding]  # Duplicate for testing
    multiple_csv_data = soc2_mapper.generate_csv_data(multiple_findings)
    assert len(multiple_csv_data) > len(csv_data)

def test_init_file_not_found(monkeypatch, tmp_path):
    # Create a temporary invalid path
    invalid_path = tmp_path / 'nonexistent' / 'soc2_control_mappings.json'
    
    # Mock Path.parent to return our temp directory
    def mock_path(*args, **kwargs):
        return tmp_path
    monkeypatch.setattr(Path, 'parent', property(mock_path))
    
    # Test FileNotFoundError
    with pytest.raises(FileNotFoundError):
        SOC2Mapper()

def test_init_invalid_json(monkeypatch, tmp_path):
    # Create a temporary file with invalid JSON
    config_path = tmp_path / 'config'
    config_path.mkdir()
    invalid_json_path = config_path / 'soc2_control_mappings.json'
    invalid_json_path.write_text('{"invalid": json}')
    
    # Mock Path.parent to return our temp directory
    def mock_path(*args, **kwargs):
        return tmp_path
    monkeypatch.setattr(Path, 'parent', property(mock_path))
    
    # Test JSONDecodeError
    with pytest.raises(json.JSONDecodeError):
        SOC2Mapper() 