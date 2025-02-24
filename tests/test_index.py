import pytest
from datetime import datetime
import json
import boto3
from unittest.mock import MagicMock, patch
import sys
import os

# Import the functions directly from the module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.handlers.securityhub_handler import summarize_findings, generate_soc2_csv, lambda_handler

@pytest.fixture
def sample_findings():
    return [{
        'Id': 'test-finding-001',
        'AccountId': '123456789012',
        'Title': 'S3 Bucket Public Access',
        'Description': 'S3 bucket has public access enabled',
        'Severity': 'CRITICAL',
        'ResourceType': 'AwsS3Bucket',
        'ResourceId': 'test-bucket',
        'ResourceArn': 'arn:aws:s3:::test-bucket',
        'CreatedAt': '2024-02-23T00:00:00Z',
        'UpdatedAt': '2024-02-23T01:00:00Z',
        'Type': 'Software and Configuration Checks/AWS Security Best Practices/S3'
    }, {
        'Id': 'test-finding-002',
        'AccountId': '123456789012',
        'Title': 'IAM Root User Access Key',
        'Description': 'IAM root user has active access keys',
        'Severity': 'HIGH',
        'ResourceType': 'AwsIamUser',
        'ResourceId': 'root',
        'ResourceArn': 'arn:aws:iam::123456789012:root',
        'CreatedAt': '2024-02-23T00:00:00Z',
        'UpdatedAt': '2024-02-23T01:00:00Z',
        'Type': 'Software and Configuration Checks/AWS Security Best Practices/IAM'
    }]

@pytest.fixture
def mock_bedrock_response():
    return {
        'body': MagicMock(
            read=lambda: json.dumps({
                'content': [{'text': 'Test analysis summary'}]
            })
        )
    }

@pytest.fixture
def mock_env(monkeypatch):
    monkeypatch.setenv('SENDER_EMAIL', 'sender@example.com')
    monkeypatch.setenv('RECIPIENT_EMAIL', 'recipient@example.com')
    monkeypatch.setenv('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet')
    monkeypatch.setenv('FINDINGS_HOURS', '24')

def test_summarize_findings_success(sample_findings, mock_bedrock_response):
    with patch('boto3.client') as mock_boto3:
        mock_boto3.return_value.invoke_model.return_value = mock_bedrock_response
        summary = summarize_findings(sample_findings)
        assert summary is not None
        assert isinstance(summary, str)
        assert 'Test analysis summary' in summary
        assert 'critical findings' in summary.lower()

def test_summarize_findings_bedrock_error(sample_findings):
    with patch('boto3.client') as mock_boto3:
        mock_boto3.return_value.invoke_model.side_effect = Exception('Bedrock error')
        summary = summarize_findings(sample_findings)
        assert summary is None

def test_summarize_findings_empty():
    summary = summarize_findings([])
    assert summary is None

def test_generate_soc2_csv(sample_findings):
    csv_content = generate_soc2_csv(sample_findings)
    assert isinstance(csv_content, str)
    assert 'Control_ID' in csv_content
    assert 'Finding_Title' in csv_content
    assert 'S3 Bucket Public Access' in csv_content
    assert 'IAM Root User Access Key' in csv_content

def test_lambda_handler_success(sample_findings, mock_bedrock_response, mock_env):
    with patch('boto3.client') as mock_boto3:
        # Mock SecurityHub response
        mock_securityhub = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{'Findings': sample_findings}]
        mock_securityhub.get_paginator.return_value = paginator

        # Mock Bedrock response
        mock_bedrock = MagicMock()
        mock_bedrock.invoke_model.return_value = mock_bedrock_response

        # Mock SSM response
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {
            'Parameter': {
                'Value': json.dumps({
                    'recipients': [{
                        'email': 'recipient@example.com',
                        'frequency': 'weekly',
                        'report_type': ['detailed']
                    }]
                })
            }
        }

        # Mock SES response
        mock_ses = MagicMock()
        mock_ses.send_raw_email.return_value = {'MessageId': 'test-message-id'}

        def mock_client(service_name):
            if service_name == 'securityhub':
                return mock_securityhub
            elif service_name == 'bedrock-runtime':
                return mock_bedrock
            elif service_name == 'ssm':
                return mock_ssm
            elif service_name == 'ses':
                return mock_ses
            return MagicMock()

        mock_boto3.side_effect = mock_client

        response = lambda_handler({'frequency': 'weekly'}, {})
        assert response['statusCode'] == 200
        assert 'Successfully sent weekly SecurityHub SOC 2 analysis reports' in response['body']
        assert 'findingsAnalyzed' in response['body']

def test_lambda_handler_no_findings(mock_env):
    with patch('boto3.client') as mock_boto3:
        # Mock SecurityHub response
        mock_securityhub = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{'Findings': []}]
        mock_securityhub.get_paginator.return_value = paginator

        # Mock SSM response
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {
            'Parameter': {
                'Value': json.dumps({
                    'recipients': [{
                        'email': 'recipient@example.com',
                        'frequency': 'weekly',
                        'report_type': ['detailed']
                    }]
                })
            }
        }

        def mock_client(service_name):
            if service_name == 'securityhub':
                return mock_securityhub
            elif service_name == 'ssm':
                return mock_ssm
            return MagicMock()

        mock_boto3.side_effect = mock_client

        response = lambda_handler({'frequency': 'weekly'}, {})
        assert response['statusCode'] == 200
        assert 'Successfully sent weekly SecurityHub SOC 2 analysis reports' in response['body']
        assert '"findingsAnalyzed": 0' in response['body']

def test_lambda_handler_error(mock_env):
    with patch('boto3.client') as mock_boto3:
        mock_boto3.return_value.get_paginator.side_effect = Exception('Test error')
        response = lambda_handler({}, {})
        assert response['statusCode'] == 500
        assert 'error' in response['body']

def test_lambda_handler_ses_error(sample_findings, mock_bedrock_response, mock_env):
    with patch('boto3.client') as mock_boto3:
        # Mock SecurityHub response
        mock_securityhub = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{'Findings': sample_findings}]
        mock_securityhub.get_paginator.return_value = paginator

        # Mock Bedrock response
        mock_bedrock = MagicMock()
        mock_bedrock.invoke_model.return_value = mock_bedrock_response

        # Mock SSM response
        mock_ssm = MagicMock()
        mock_ssm.get_parameter.return_value = {
            'Parameter': {
                'Value': json.dumps({
                    'recipients': [{
                        'email': 'recipient@example.com',
                        'frequency': 'weekly',
                        'report_type': ['detailed']
                    }]
                })
            }
        }

        # Mock SES error
        mock_ses = MagicMock()
        mock_ses.send_raw_email.side_effect = Exception('SES error')

        def mock_client(service_name):
            if service_name == 'securityhub':
                return mock_securityhub
            elif service_name == 'bedrock-runtime':
                return mock_bedrock
            elif service_name == 'ssm':
                return mock_ssm
            elif service_name == 'ses':
                return mock_ses
            return MagicMock()

        mock_boto3.side_effect = mock_client

        response = lambda_handler({'frequency': 'weekly'}, {})
        assert response['statusCode'] == 500
        assert 'error' in response['body']

def test_lambda_handler_test_email(mock_env):
    with patch('boto3.client') as mock_boto3:
        # Mock SES response
        mock_ses = MagicMock()
        mock_ses.send_raw_email.return_value = {'MessageId': 'test-message-id'}

        def mock_client(service_name):
            if service_name == 'ses':
                return mock_ses
            return MagicMock()

        mock_boto3.side_effect = mock_client

        response = lambda_handler({
            'test_email': True,
            'recipient_email': 'test@example.com'
        }, {})
        assert response['statusCode'] == 200
        assert 'success' in response['body']
        assert 'message_id' in response['body'] 