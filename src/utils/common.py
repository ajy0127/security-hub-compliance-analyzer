"""
Common utilities for SecurityHub findings analysis.

This module contains shared functionalities used across the codebase:
- AWS client initialization with retry logic
- Email formatting and sending utilities
- Finding filtering and formatting
"""

import json
import logging
import boto3
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from botocore.config import Config

# Configure logging
logger = logging.getLogger(__name__)


def get_boto3_client(service_name: str, retry_attempts: int = 3) -> Any:
    """
    Get a boto3 client with retry logic configured.

    Args:
        service_name: AWS service name
        retry_attempts: Number of retry attempts for retryable errors

    Returns:
        Boto3 client with retry configuration
    """
    config = Config(
        retries={"max_attempts": retry_attempts, "mode": "standard"},
        user_agent_extra="SecurityHubSOC2Analyzer/1.0",
    )
    return boto3.client(service_name, config=config)


def send_email(
    sender: str,
    recipient: str,
    subject: str,
    body_text: str,
    body_html: str,
    attachment_content: Optional[str] = None,
    attachment_filename: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Send an email with optional attachment using Amazon SES.

    Args:
        sender: Email address of the sender
        recipient: Email address of the recipient
        subject: Email subject line
        body_text: Plain text email body
        body_html: HTML formatted email body
        attachment_content: Content of the attachment (optional)
        attachment_filename: Filename for the attachment (optional)

    Returns:
        SES response dictionary

    Raises:
        Exception: If there's an error sending the email
    """
    ses = get_boto3_client("ses")

    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient

    # Create multipart/alternative for text and HTML versions
    msg_body = MIMEMultipart("alternative")

    # Add text part
    text_part = MIMEText(body_text.encode("utf-8"), "plain", "utf-8")
    msg_body.attach(text_part)

    # Add HTML part
    html_part = MIMEText(body_html.encode("utf-8"), "html", "utf-8")
    msg_body.attach(html_part)

    # Attach message body
    msg.attach(msg_body)

    # Add attachment if provided
    if attachment_content and attachment_filename:
        attachment = MIMEApplication(attachment_content.encode("utf-8"))
        attachment.add_header(
            "Content-Disposition", "attachment", filename=attachment_filename
        )
        msg.attach(attachment)

    try:
        response = ses.send_raw_email(
            Source=sender,
            Destinations=[recipient],
            RawMessage={"Data": msg.as_string()},
        )
        logger.info(f"Email sent successfully. MessageId: {response['MessageId']}")
        return response
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}", exc_info=True)
        raise


def get_findings_from_securityhub(
    hours: int, filter_params: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Retrieve findings from AWS SecurityHub with pagination.

    Args:
        hours: Number of hours to look back for findings
        filter_params: Additional filter parameters to apply

    Returns:
        List of SecurityHub findings
    """
    try:
        # Calculate time window
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)

        # Set up base filters
        time_filter = {
            "UpdatedAt": [
                {"Start": start_time.isoformat(), "End": end_time.isoformat()}
            ]
        }

        # Combine with additional filters if provided
        filters = time_filter
        if filter_params:
            filters.update(filter_params)

        # Get SecurityHub client with retry logic
        securityhub = get_boto3_client("securityhub")

        # Use paginator to handle pagination
        findings = []
        paginator = securityhub.get_paginator("get_findings")
        for page in paginator.paginate(Filters=filters):
            findings.extend(page["Findings"])

        logger.info(f"Retrieved {len(findings)} findings from SecurityHub")
        return findings

    except Exception as e:
        logger.error(
            f"Error retrieving findings from SecurityHub: {str(e)}", exc_info=True
        )
        raise


def format_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format a SecurityHub finding for easier processing.

    Args:
        finding: Raw SecurityHub finding JSON

    Returns:
        Formatted finding dictionary
    """
    # Extract resource information safely
    resource = finding.get("Resources", [{}])[0]

    return {
        "AccountId": finding.get("AwsAccountId", "N/A"),
        "Title": finding.get("Title", "N/A"),
        "Description": finding.get("Description", "N/A"),
        "Severity": finding.get("Severity", {}).get("Label", "N/A"),
        "ResourceType": resource.get("Type", "N/A"),
        "ResourceId": resource.get("Id", "N/A"),
        "ResourceArn": resource.get("Details", {})
        .get("AwsS3Bucket", {})
        .get("Arn", resource.get("Id", "N/A")),
        "ComplianceStatus": finding.get("Compliance", {}).get("Status", "N/A"),
        "RecordState": finding.get("RecordState", "N/A"),
        "LastObservedAt": finding.get("LastObservedAt", "N/A"),
        "Type": finding.get("Type", "N/A"),
        "Id": finding.get("Id", "N/A"),
        "CreatedAt": finding.get("CreatedAt", "N/A"),
        "UpdatedAt": finding.get("UpdatedAt", "N/A"),
        "ProductArn": finding.get("ProductArn", "N/A"),
        "Remediation": finding.get("Remediation", {}),
    }


def format_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Format a list of SecurityHub findings.

    Args:
        findings: List of raw SecurityHub findings

    Returns:
        List of formatted findings
    """
    return [format_finding(finding) for finding in findings]


def invoke_bedrock_model(
    prompt: str,
    model_id: str,
    max_tokens: int = 2000,
    temperature: float = 0.5,
    top_p: float = 1.0,
) -> Optional[str]:
    """
    Invoke Amazon Bedrock model with retry logic.

    Args:
        prompt: The prompt to send to the model
        model_id: Amazon Bedrock model ID
        max_tokens: Maximum tokens in the response
        temperature: Temperature parameter for model
        top_p: Top-p parameter for model

    Returns:
        Model response text, or None if request fails
    """
    try:
        # Get Bedrock client with retry configuration
        bedrock = get_boto3_client("bedrock-runtime")

        # Prepare request body
        body = {
            "messages": [{"role": "user", "content": prompt}],
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": top_p,
        }

        # Request structured format if Claude 3 model
        if "claude-3" in model_id.lower():
            logger.info(f"Using structured format for {model_id}")

        # Invoke model
        response = bedrock.invoke_model(
            modelId=model_id,
            body=json.dumps(body),
        )

        # Parse response
        response_body = json.loads(response["body"].read())

        # Extract text based on response format
        if "content" in response_body and isinstance(response_body["content"], list):
            # Claude 3 format
            return response_body["content"][0]["text"]
        elif "completion" in response_body:
            # Claude 2 format
            return response_body["completion"]
        else:
            logger.warning(f"Unexpected response format: {response_body.keys()}")
            return None

    except Exception as e:
        logger.error(f"Error invoking Bedrock model: {str(e)}", exc_info=True)
        return None
