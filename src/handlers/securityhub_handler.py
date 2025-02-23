"""
AWS SecurityHub SOC 2 Compliance Analyzer

This Lambda function analyzes AWS SecurityHub findings and generates SOC 2-compliant reports.
It performs the following main tasks:
1. Retrieves SecurityHub findings from the specified time window
2. Maps findings to relevant SOC 2 controls
3. Generates an AI-powered analysis using Amazon Bedrock
4. Creates a SOC 2 workpaper in CSV format
5. Sends the analysis and workpaper via email

The function runs on a schedule and focuses on CRITICAL and HIGH severity findings.
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


def lambda_handler(event, context):
    """
    Main Lambda function handler.

    This function:
    1. Retrieves recent SecurityHub findings
    2. Generates analysis and workpaper
    3. Prepares email with attachments
    4. Sends email using Amazon SES

    Args:
        event: Lambda event object
        context: Lambda context object

    Returns:
        dict: Response object with status code and message
    """
    try:
        # Get environment variables
        sender_email = os.environ.get("SENDER_EMAIL")
        recipient_email = os.environ.get("RECIPIENT_EMAIL")
        findings_hours = int(os.environ.get("FINDINGS_HOURS", "24"))

        if not sender_email or not recipient_email:
            raise ValueError(
                "Missing required environment variables: SENDER_EMAIL and RECIPIENT_EMAIL"
            )

        security_hub = boto3.client("securityhub")

        # Get findings from the last X hours
        start_time = datetime.now() - timedelta(hours=findings_hours)

        # Get findings
        findings_response = security_hub.get_findings(
            Filters={
                "CreatedAt": [
                    {"Start": start_time.isoformat(), "End": datetime.now().isoformat()}
                ],
                "SeverityLabel": [
                    {"Value": "CRITICAL", "Comparison": "EQUALS"},
                    {"Value": "HIGH", "Comparison": "EQUALS"},
                ],
            }
        )

        findings = findings_response["Findings"]

        if not findings:
            logger.info("No findings found in the specified time period")
            return {"statusCode": 200, "body": json.dumps("No findings to analyze")}

        # Generate analysis summary
        summary = summarize_findings(findings)

        # Generate SOC 2 workpaper CSV
        csv_content = generate_soc2_csv(findings)

        # Create email
        msg = MIMEMultipart()
        msg["Subject"] = (
            f'SecurityHub SOC 2 Compliance Report - {datetime.now().strftime("%Y-%m-%d")}'
        )
        msg["From"] = sender_email
        msg["To"] = recipient_email

        # Attach summary
        msg.attach(MIMEText(summary or "Error generating analysis", "plain"))

        # Attach CSV
        csv_attachment = MIMEApplication(csv_content.encode("utf-8"))
        csv_attachment.add_header(
            "Content-Disposition",
            "attachment",
            filename=f'soc2_findings_{datetime.now().strftime("%Y%m%d")}.csv',
        )
        msg.attach(csv_attachment)

        # Send email
        ses = boto3.client("ses")
        ses.send_raw_email(
            Source=sender_email,
            Destinations=[recipient_email],
            RawMessage={"Data": msg.as_string()},
        )

        logger.info("Successfully sent email with findings analysis")

        return {
            "statusCode": 200,
            "body": json.dumps("Successfully analyzed findings and sent report"),
        }

    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps(f"Error processing findings: {str(e)}"),
        }
