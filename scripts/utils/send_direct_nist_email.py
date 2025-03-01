#!/usr/bin/env python3
"""
Send a direct NIST 800-53 report email using AWS SES.
"""

import boto3
import os
import json
import argparse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from datetime import datetime

def send_nist_email(profile_name, sender_email, recipient_email):
    """Send a direct NIST 800-53 report email using AWS SES."""
    # Create a session with the specified profile
    session = boto3.Session(profile_name=profile_name)
    
    # Create SES client
    ses = session.client('ses')
    
    # Create message container
    msg = MIMEMultipart('mixed')
    msg['Subject'] = f'AWS SecurityHub NIST 800-53 Compliance Report - {datetime.now().strftime("%Y-%m-%d")}'
    msg['From'] = sender_email
    msg['To'] = recipient_email
    
    # Sample findings statistics
    stats = {
        "total": 10,
        "critical": 1,
        "high": 3,
        "medium": 5,
        "low": 1
    }
    
    # Sample analysis text
    analysis = """## Executive Summary

The security findings in your AWS environment reveal several areas that require attention to maintain NIST 800-53 compliance. While the majority of findings are medium severity, there are critical and high-severity issues that pose significant security risks and should be addressed promptly.

## NIST 800-53 Impact

These findings directly impact your compliance with several key NIST 800-53 control families:

1. **Access Control (AC)**: Multiple findings related to improper access controls, particularly around least privilege principles.
2. **System and Information Integrity (SI)**: Issues with encryption at rest and failure to implement security configuration baselines.
3. **Configuration Management (CM)**: Several instances of improper configuration of AWS services.

## Key Recommendations

1. **Enable Encryption for S3 Buckets**: Implement server-side encryption for all S3 buckets to protect sensitive data at rest.
2. **Remove Root User Access Keys**: Eliminate IAM root user access keys to reduce the risk of unauthorized privileged access.
3. **Enforce CloudTrail Encryption**: Enable encryption for CloudTrail logs to ensure the integrity of audit data.

## Auditor's Perspective

As a NIST 800-53 auditor with over 15 years of experience, I can confirm that these findings would represent significant concerns during a formal assessment. The presence of unencrypted data storage and root access keys in particular would likely result in compliance gaps that would need to be addressed before certification.

In my experience, organizations typically require 4-6 weeks to remediate these types of findings, starting with the critical and high-severity issues. I recommend developing a formal remediation plan with clear timelines and ownership assignments for each finding.

For your NIST 800-53 assessment readiness, I would prioritize addressing the encryption findings first, as these align with multiple controls and represent the most straightforward path to improving your compliance posture."""
    
    # Create HTML content
    css_style = """
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #232f3e; }
        .summary { background-color: #f8f8f8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .critical { color: #d13212; }
        .high { color: #ff9900; }
        .medium { color: #d9b43c; }
        .low { color: #6b6b6b; }
        .auditor-perspective { 
            background-color: #f0f7ff; 
            padding: 20px; 
            border-left: 5px solid #0073bb; 
            margin: 20px 0; 
            border-radius: 5px;
            font-style: italic;
        }
    """
    
    # Use raw string for CSS to avoid escape sequence issues
    
    # Preprocess the analysis text to avoid f-string backslash issues
    formatted_analysis = analysis.replace('##', '<h2>')
    formatted_analysis = formatted_analysis.replace('\n\n', '</h2><p>')
    formatted_analysis = formatted_analysis.replace('\n', '<br>')
    formatted_analysis = formatted_analysis.replace('</h2><p>', '</h2><p>')
    formatted_analysis = formatted_analysis + '</p>'
    
    html_content = f"""<html>
<head>
    <style>
{css_style}
    </style>
</head>
<body>
    <h1>{msg['Subject']}</h1>
    <p>Report generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>
    
    <div class="summary">
        <h3>Finding Summary</h3>
        <p><strong>Total Findings:</strong> {stats['total']}</p>
        <p><strong class="critical">Critical:</strong> {stats['critical']}</p>
        <p><strong class="high">High:</strong> {stats['high']}</p>
        <p><strong class="medium">Medium:</strong> {stats['medium']}</p>
        <p><strong class="low">Low:</strong> {stats['low']}</p>
    </div>
    
    <div class="analysis-content">
        {formatted_analysis}
    </div>
    
    <p>Note: This is a direct test email to verify delivery of NIST 800-53 reports. A CSV report would normally be attached.</p>
</body>
</html>"""
    
    # Attach HTML part
    html_part = MIMEText(html_content, 'html')
    msg.attach(html_part)
    
    # Create a sample CSV attachment
    csv_content = """Title,Severity,Finding Type,NIST 800-53 Controls,Resource ID,Account ID,Region,Description
S3 buckets should have server-side encryption enabled,HIGH,Software and Configuration Checks,SC-28,arn:aws:s3:::example-bucket-123,123456789012,us-east-1,S3 bucket doesn't have encryption enabled
IAM root user access key should not exist,CRITICAL,Software and Configuration Checks/Policy,AC-6,AWS::::Account:123456789012,123456789012,us-east-1,Root account has active access keys
CloudTrail should have encryption at-rest enabled,MEDIUM,Software and Configuration Checks,SC-28,arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events,123456789012,us-east-1,CloudTrail isn't encrypted"""
    
    # Attach CSV
    attachment = MIMEApplication(csv_content.encode('utf-8'))
    attachment.add_header('Content-Disposition', 'attachment', filename='nist800-53_findings.csv')
    msg.attach(attachment)
    
    # Send email
    try:
        response = ses.send_raw_email(
            Source=sender_email,
            Destinations=[recipient_email],
            RawMessage={'Data': msg.as_string()}
        )
        print(f"Email sent successfully: {response}")
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send direct NIST 800-53 report email via AWS SES")
    parser.add_argument("--profile", default="sandbox", help="AWS profile name to use")
    parser.add_argument("--sender", required=True, help="Verified sender email address")
    parser.add_argument("--recipient", required=True, help="Recipient email address")
    
    args = parser.parse_args()
    
    send_nist_email(args.profile, args.sender, args.recipient)