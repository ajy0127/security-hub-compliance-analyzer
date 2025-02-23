"""
AWS SecurityHub SOC 2 Compliance Analyzer

This Lambda function analyzes AWS SecurityHub findings and generates SOC 2-compliant reports.
It performs the following main tasks:
1. Retrieves SecurityHub findings from the specified time window
2. Maps findings to relevant SOC 2 controls
3. Generates an AI-powered analysis using Amazon Bedrock
4. Creates a SOC 2 workpaper in CSV format
5. Sends the analysis and workpaper via email

The function can be triggered:
- On a schedule (weekly, bi-weekly, monthly)
- Immediately for testing and verification
"""

import boto3
from datetime import datetime, timedelta
import json
import logging
import csv
import io
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import os
from src.lib.soc2_mapper import SOC2Mapper

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def summarize_findings(findings):
    """
    Generate an AI-powered analysis of SecurityHub findings with SOC 2 context.

    This function:
    1. Separates findings by severity (CRITICAL and HIGH)
    2. Maps findings to SOC 2 controls
    3. Uses Amazon Bedrock to generate a comprehensive analysis

    Args:
        findings (list): List of SecurityHub finding objects

    Returns:
        str: AI-generated analysis text, or None if analysis fails
    """
    if not findings:
        return None

    # Get environment variables
    bedrock_model_id = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")

    # Separate findings by severity
    critical_findings = [f for f in findings if f["Severity"] == "CRITICAL"]
    high_findings = [f for f in findings if f["Severity"] == "HIGH"]

    # Limit high severity findings to prevent token limit issues
    max_high_findings = 10
    high_findings_truncated = high_findings[:max_high_findings]

    # Combine findings for analysis
    selected_findings = critical_findings + high_findings_truncated

    logger.info(
        "Analyzing {} critical and {} high severity findings".format(
            len(critical_findings), min(len(high_findings), max_high_findings)
        )
    )

    # Map findings to SOC 2 controls and prepare for analysis
    soc2_mapper = SOC2Mapper()
    summary_findings = []

    for f in selected_findings:
        mapped_controls = soc2_mapper.map_finding_to_controls(f)
        finding_summary = {
            "AccountId": f.get("AccountId", "N/A"),
            "Title": f.get("Title", "N/A"),
            "Severity": f.get("Severity", "N/A"),
            "ResourceType": f.get("ResourceType", "N/A"),
            "ResourceId": f.get("ResourceId", "N/A"),
            "ResourceArn": f.get("ResourceArn", "N/A"),
            "Description": (
                f.get("Description", "N/A")[:200] + "..."
                if len(f.get("Description", "")) > 200
                else f.get("Description", "N/A")
            ),
            "SOC2_Controls": {
                "Primary": mapped_controls["primary_controls"],
                "Secondary": mapped_controls["secondary_controls"],
            },
        }
        summary_findings.append(finding_summary)

    # Prepare prompt for AI analysis
    bedrock = boto3.client("bedrock-runtime")

    # Define prompt sections
    findings_data = json.dumps(summary_findings, indent=2)
    overview_items = [
        "List findings with ID and resources",
        "Explain compliance impact",
    ]
    severity_items = [
        "Summarize findings and control implications",
        "Identify control failure patterns",
    ]
    impact_items = ["Group by control categories", "Highlight high-risk controls"]
    action_items = ["List remediation steps", "Timeline recommendations"]

    # Build sections with proper indentation
    overview = "1. Critical Findings Overview:\n" + "\n".join(
        f"   - {item}" for item in overview_items
    )
    severity = "2. High Severity Issues:\n" + "\n".join(
        f"   - {item}" for item in severity_items
    )
    impact = "3. SOC 2 Control Impact Analysis:\n" + "\n".join(
        f"   - {item}" for item in impact_items
    )
    actions = "4. Recommended Actions:\n" + "\n".join(
        f"   - {item}" for item in action_items
    )

    # Combine prompt sections
    prompt = (
        "Human: Analyze the following security findings with SOC 2 context:\n"
        f"{findings_data}\n\n"
        "Please provide a comprehensive security and compliance analysis:\n"
        f"{overview}\n{severity}\n{impact}\n{actions}\n\n"
        "Please ensure the summary is clear and actionable with control references. A:"
    )

    try:
        response = bedrock.invoke_model(
            modelId=bedrock_model_id,
            body=json.dumps(
                {
                    "messages": [{"role": "user", "content": prompt}],
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 2000,
                    "temperature": 0.5,
                    "top_p": 1,
                }
            ),
        )
        summary = json.loads(response["body"].read())["content"][0]["text"]

        # Add a note about the findings breakdown
        summary_note = (
            f"\n\nAnalysis includes all {len(critical_findings)} critical findings"
        )
        if len(high_findings) > max_high_findings:
            high_count = f"{max_high_findings} out of {len(high_findings)}"
            summary_note += f" and {high_count} high severity findings"
        else:
            summary_note += f" and all {len(high_findings)} high severity findings"

        summary += summary_note
        logger.info("Successfully generated summary")
        return summary.strip()

    except Exception as e:
        logger.error(f"Error calling Anthropic Claude 3 Sonnet model: {str(e)}")
        return None


def generate_soc2_csv(findings):
    """Generate SOC 2 workpaper CSV from findings"""
    soc2_mapper = SOC2Mapper()
    csv_data = soc2_mapper.generate_csv_data(findings)

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=soc2_mapper.get_csv_headers())
    writer.writeheader()
    writer.writerows(csv_data)

    return output.getvalue()


def get_recipients_config():
    """Get recipients configuration from SSM Parameter Store"""
    ssm = boto3.client('ssm')
    param = ssm.get_parameter(Name='/securityhub/recipients')
    return json.loads(param['Parameter']['Value'])


def get_findings(hours):
    """Get SecurityHub findings from the last N hours"""
    securityhub = boto3.client('securityhub')
    now = datetime.utcnow()
    start_time = now - timedelta(hours=hours)
    
    filters = {
        'UpdatedAt': [{'Start': start_time.isoformat(), 'End': now.isoformat()}]
    }
    
    findings = []
    paginator = securityhub.get_paginator('get_findings')
    for page in paginator.paginate(Filters=filters):
        findings.extend(page['Findings'])
    
    return findings


def analyze_findings_with_bedrock(findings, report_type="detailed"):
    """Analyze findings using Amazon Bedrock"""
    bedrock = boto3.client('bedrock-runtime')
    model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet')
    
    # Prepare findings summary based on report type
    if report_type == "summary":
        findings_text = f"Summary of {len(findings)} SecurityHub findings:\n"
        for finding in findings[:5]:  # Only include top 5 findings for summary
            findings_text += f"- {finding['Title']} (Severity: {finding['Severity']['Label']})\n"
    else:
        findings_text = "Detailed analysis of SecurityHub findings:\n"
        for finding in findings:
            findings_text += (
                f"Title: {finding['Title']}\n"
                f"Severity: {finding['Severity']['Label']}\n"
                f"Description: {finding['Description']}\n"
                f"Resource: {finding['Resources'][0]['Type']}\n"
                f"---\n"
            )
    
    prompt = f"""
    Analyze these AWS SecurityHub findings from a SOC 2 compliance perspective:
    {findings_text}
    
    Please provide:
    1. Overall risk assessment
    2. Impact on SOC 2 controls
    3. Recommended remediation steps
    4. Compliance status summary
    """
    
    response = bedrock.invoke_model(
        modelId=model_id,
        body=json.dumps({
            "prompt": prompt,
            "max_tokens": 2048,
            "temperature": 0.7
        })
    )
    
    return json.loads(response['body'])['completion']


def send_report(recipients, findings_analysis, frequency):
    """Send report to specified recipients"""
    ses = boto3.client('ses')
    
    for recipient in recipients:
        if recipient['frequency'] != frequency:
            continue
            
        msg = MIMEMultipart()
        msg['Subject'] = f'SecurityHub SOC 2 Analysis Report ({frequency.capitalize()})'
        msg['From'] = recipient['email']  # Sender must be verified in SES
        msg['To'] = recipient['email']
        
        # Create report content based on recipient preferences
        report_content = ""
        for report_type in recipient.get('report_type', ['detailed']):
            analysis = analyze_findings_with_bedrock(findings_analysis, report_type)
            report_content += f"\n\n{report_type.upper()} REPORT:\n{analysis}"
        
        msg.attach(MIMEText(report_content, 'plain'))
        
        ses.send_raw_email(
            Source=msg['From'],
            Destinations=[msg['To']],
            RawMessage={'Data': msg.as_string()}
        )


def send_test_email(recipient_email):
    """
    Send an immediate test email to verify the setup.
    
    Args:
        recipient_email (str): Email address to send the test to
        
    Returns:
        dict: Response containing success/failure status and message ID
    """
    try:
        ses = boto3.client('ses')
        
        # Create the email message
        msg = MIMEMultipart()
        msg['Subject'] = 'SecurityHub SOC 2 Analyzer - Test Email'
        msg['From'] = recipient_email  # Must be verified in SES
        msg['To'] = recipient_email
        
        # Create the email body
        body = """
        SecurityHub SOC 2 Analyzer Test Email
        
        This email confirms that your SecurityHub SOC 2 Analyzer is properly configured.
        
        Configuration Details:
        - Email Delivery: Working
        - Recipient Address: {email}
        - Current Time: {timestamp}
        
        Next Steps:
        1. Regular reports will be delivered based on your configured schedule
        2. Check the user guide for customizing report frequencies and recipients
        3. Monitor the first automated report for full functionality verification
        
        If you received this email, your basic email configuration is working correctly.
        
        For more information, please consult the documentation.
        """.format(
            email=recipient_email,
            timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        )
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send the email
        response = ses.send_raw_email(
            Source=msg['From'],
            Destinations=[msg['To']],
            RawMessage={'Data': msg.as_string()}
        )
        
        logger.info(f"Test email sent successfully to {recipient_email}")
        return {
            'success': True,
            'message_id': response['MessageId']
        }
        
    except Exception as e:
        logger.error(f"Error sending test email: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }


def lambda_handler(event, context):
    """Main Lambda handler function"""
    try:
        # Check if this is a test email request
        if event.get('test_email'):
            recipient_email = event.get('recipient_email')
            if not recipient_email:
                raise ValueError("recipient_email is required for test emails")
                
            # Send test email
            result = send_test_email(recipient_email)
            return {
                'statusCode': 200 if result['success'] else 500,
                'body': json.dumps(result)
            }
        
        # Regular report processing
        frequency = event.get('frequency', 'weekly')
        config = get_recipients_config()
        hours = int(os.environ.get('FINDINGS_HOURS', '24'))
        
        findings = get_findings(hours)
        send_report(config['recipients'], findings, frequency)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully sent {frequency} SecurityHub SOC 2 analysis reports',
                'findingsAnalyzed': len(findings)
            })
        }
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }
