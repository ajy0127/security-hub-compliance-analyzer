import csv
import io
import json
import logging
import os
import argparse
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

import boto3

from soc2_mapper import SOC2Mapper
from utils import format_datetime, get_resource_id

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_findings(hours):
    """Get SecurityHub findings from the last X hours"""
    securityhub = boto3.client("securityhub")

    # Calculate time window
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=int(hours))

    # Format times for SecurityHub API
    start_time_str = format_datetime(start_time)
    end_time_str = format_datetime(end_time)

    # Query SecurityHub for findings
    try:
        logger.info(
            f"Querying SecurityHub for findings between {start_time_str} and {end_time_str}"
        )
        response = securityhub.get_findings(
            Filters={
                "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
                "UpdatedAt": [{"Start": start_time_str, "End": end_time_str}],
            },
            MaxResults=100,
        )

        findings = response.get("Findings", [])
        logger.info(f"Found {len(findings)} findings")
        return findings

    except Exception as e:
        logger.error(f"Error getting findings from SecurityHub: {str(e)}")
        return []


def analyze_findings(findings, soc2_mapper):
    """Analyze findings and generate statistics"""
    if not findings:
        return "No findings to analyze.", {}

    # Get environment variables
    bedrock_model_id = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")

    # Map findings to SOC 2 controls
    mapped_findings = []
    for finding in findings:
        mapped_finding = soc2_mapper.map_finding(finding)
        mapped_findings.append(mapped_finding)

    # Generate summary statistics
    stats = {
        "total": len(findings),
        "critical": len(
            [f for f in findings if f.get("Severity", {}).get("Label") == "CRITICAL"]
        ),
        "high": len(
            [f for f in findings if f.get("Severity", {}).get("Label") == "HIGH"]
        ),
        "medium": len(
            [f for f in findings if f.get("Severity", {}).get("Label") == "MEDIUM"]
        ),
        "low": len(
            [f for f in findings if f.get("Severity", {}).get("Label") == "LOW"]
        ),
    }

    # Group findings by SOC 2 control
    control_findings = {}
    for finding in mapped_findings:
        controls = finding.get("SOC2Controls", "Unknown")
        if isinstance(controls, list):
            controls = ", ".join(controls)

        if controls not in control_findings:
            control_findings[controls] = []

        control_findings[controls].append(finding)

    try:
        # Use Amazon Bedrock to analyze findings
        bedrock = boto3.client("bedrock-runtime")

        # Prepare prompt for Bedrock
        prompt = f"""
        You are a SOC 2 compliance expert analyzing AWS SecurityHub findings. 
        
        Here are the statistics of the findings:
        - Total findings: {stats['total']}
        - Critical findings: {stats['critical']}
        - High findings: {stats['high']}
        - Medium findings: {stats['medium']}
        - Low findings: {stats['low']}
        
        Here are the top findings mapped to SOC 2 controls:
        {json.dumps(mapped_findings[:20], indent=2)}
        
        Here are the findings grouped by SOC 2 control:
        {json.dumps({k: len(v) for k, v in control_findings.items()}, indent=2)}
        
        Please provide a concise analysis of these findings with the following sections:
        1. Executive Summary: A brief overview of the security posture
        2. SOC 2 Impact: How these findings affect SOC 2 compliance
        3. Key Recommendations: Top 3-5 actions to address the most critical issues
        
        Keep your response under 1000 words and focus on actionable insights.
        """

        # Call Bedrock
        logger.info(f"Calling Bedrock model {bedrock_model_id} for analysis")
        response = bedrock.invoke_model(
            modelId=bedrock_model_id,
            body=json.dumps(
                {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 1000,
                    "messages": [{"role": "user", "content": prompt}],
                }
            ),
        )

        # Parse response
        response_body = json.loads(response["body"].read())
        analysis = response_body["content"][0]["text"]
        logger.info("Successfully generated analysis with Bedrock")
        return analysis, stats

    except Exception as e:
        logger.error(f"Error generating analysis with Bedrock: {str(e)}")

        # Fallback to basic analysis if Bedrock fails
        return (
            f"""
        ## SecurityHub Findings Summary
        
        Total findings: {stats['total']}
        - Critical: {stats['critical']}
        - High: {stats['high']}
        - Medium: {stats['medium']}
        - Low: {stats['low']}
        
        Please review the attached CSV for details on all findings.
        """,
            stats,
        )


def generate_csv(findings, soc2_mapper):
    """Generate a CSV file with findings mapped to SOC 2 controls"""
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow(
        [
            "Title",
            "Severity",
            "Finding Type",
            "SOC 2 Controls",
            "Resource ID",
            "Account ID",
            "Region",
            "Description",
        ]
    )

    # Write findings
    for finding in findings:
        mapped_finding = soc2_mapper.map_finding(finding)
        controls = mapped_finding.get("SOC2Controls", "Unknown")
        if isinstance(controls, list):
            controls = ", ".join(controls)

        writer.writerow(
            [
                finding.get("Title", ""),
                finding.get("Severity", {}).get("Label", ""),
                ", ".join(finding.get("Types", ["Unknown"])),
                controls,
                get_resource_id(finding),
                finding.get("AwsAccountId", ""),
                finding.get("Region", ""),
                finding.get("Description", ""),
            ]
        )

    return output.getvalue()


def send_email(recipient_email, findings, analysis, stats, soc2_mapper):
    """Send email with findings and analysis"""
    ses = boto3.client("ses")
    sender_email = os.environ.get("SENDER_EMAIL")

    if not sender_email or not recipient_email:
        logger.error("Sender or recipient email not configured")
        return False

    # Create message
    msg = MIMEMultipart("mixed")
    msg["Subject"] = (
        f'AWS SecurityHub SOC 2 Compliance Report - {datetime.now().strftime("%Y-%m-%d")}'
    )
    msg["From"] = sender_email
    msg["To"] = recipient_email

    # Create HTML body
    html_part = MIMEText(
        f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1, h2, h3 {{ color: #232f3e; }}
            .summary {{ background-color: #f8f8f8; padding: 15px; border-radius: 5px; }}
            .critical {{ color: #d13212; }}
            .high {{ color: #ff9900; }}
            .medium {{ color: #d9b43c; }}
        </style>
    </head>
    <body>
        <h1>AWS SecurityHub SOC 2 Compliance Report</h1>
        <p>Report generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>
        
        <div class="summary">
            <h2>Finding Summary</h2>
            <p><strong>Total Findings:</strong> {stats['total']}</p>
            <p><strong class="critical">Critical:</strong> {stats['critical']}</p>
            <p><strong class="high">High:</strong> {stats['high']}</p>
            <p><strong class="medium">Medium:</strong> {stats['medium']}</p>
        </div>
        
        <h2>Analysis</h2>
        <div>
            {analysis.replace('\\n', '<br>')}
        </div>
        
        <p>A detailed CSV report is attached with all findings mapped to SOC 2 controls.</p>
    </body>
    </html>
    """,
        "html",
    )

    # Attach HTML part
    msg.attach(html_part)

    # Create CSV attachment
    csv_data = generate_csv(findings, soc2_mapper)
    attachment = MIMEApplication(csv_data.encode("utf-8"))
    attachment.add_header(
        "Content-Disposition", "attachment", filename="securityhub_soc2_findings.csv"
    )
    msg.attach(attachment)

    # Send email
    try:
        logger.info(f"Sending email to {recipient_email}")
        response = ses.send_raw_email(
            Source=sender_email,
            Destinations=[recipient_email],
            RawMessage={"Data": msg.as_string()},
        )
        logger.info(f"Email sent successfully: {response}")
        return True
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
        return False


def send_test_email(recipient_email):
    """Send a test email"""
    ses = boto3.client("ses")
    sender_email = os.environ.get("SENDER_EMAIL")

    if not sender_email or not recipient_email:
        logger.error("Sender or recipient email not configured")
        return False

    # Create message
    msg = MIMEMultipart("mixed")
    msg["Subject"] = "AWS SecurityHub SOC 2 Analyzer - Test Email"
    msg["From"] = sender_email
    msg["To"] = recipient_email

    # Create HTML body
    html_part = MIMEText(
        f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1, h2 {{ color: #232f3e; }}
            .box {{ background-color: #f8f8f8; padding: 15px; border-radius: 5px; }}
        </style>
    </head>
    <body>
        <h1>AWS SecurityHub SOC 2 Analyzer - Test Email</h1>
        
        <div class="box">
            <h2>Configuration Test Successful</h2>
            <p>This email confirms that your SecurityHub SOC 2 Analyzer is properly configured for email delivery.</p>
            <p>Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>
        </div>
        
        <p>The analyzer will send reports according to the configured schedule.</p>
    </body>
    </html>
    """,
        "html",
    )

    # Attach HTML part
    msg.attach(html_part)

    # Send email
    try:
        logger.info(f"Sending test email to {recipient_email}")
        response = ses.send_raw_email(
            Source=sender_email,
            Destinations=[recipient_email],
            RawMessage={"Data": msg.as_string()},
        )
        logger.info(f"Test email sent successfully: {response}")
        return True
    except Exception as e:
        logger.error(f"Error sending test email: {str(e)}")
        return False


def lambda_handler(event, context):
    """Main Lambda handler"""
    logger.info(f"Event received: {json.dumps(event)}")

    # Initialize SOC2 mapper
    soc2_mapper = SOC2Mapper()

    # Check if this is a test email request
    if event.get("test_email"):
        recipient_email = event.get("test_email")
        if not recipient_email:
            return {
                "statusCode": 400,
                "body": json.dumps("Recipient email not provided for test"),
            }

        # Send a test email
        success = send_test_email(recipient_email)

        return {
            "statusCode": 200 if success else 500,
            "body": json.dumps(
                "Test email sent successfully"
                if success
                else "Failed to send test email"
            ),
        }

    # Get configuration
    hours = event.get("hours", os.environ.get("FINDINGS_HOURS", "24"))
    recipient_email = event.get("email", os.environ.get("RECIPIENT_EMAIL"))
    generate_csv_file = event.get("generate_csv", False)

    if not recipient_email:
        logger.error("Recipient email not configured")
        return {"statusCode": 500, "body": json.dumps("Recipient email not configured")}

    # Get findings
    findings = get_findings(hours)

    if not findings:
        logger.info("No findings found")
        return {"statusCode": 200, "body": json.dumps("No findings to report")}

    # Generate analysis
    analysis, stats = analyze_findings(findings, soc2_mapper)

    # Generate CSV if requested
    csv_path = None
    if generate_csv_file:
        csv_data = generate_csv(findings, soc2_mapper)
        csv_path = "/tmp/securityhub_soc2_findings.csv"
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write(csv_data)

    # Send email
    success = send_email(recipient_email, findings, analysis, stats, soc2_mapper)

    return {
        "statusCode": 200 if success else 500,
        "body": json.dumps(
            "Email sent successfully" if success else "Failed to send email"
        ),
    }


def cli_handler():
    """Command-line interface handler"""
    parser = argparse.ArgumentParser(description="AWS SecurityHub SOC 2 Analyzer")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate a report")
    report_parser.add_argument(
        "--email", required=True, help="Email address to send the report to"
    )
    report_parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Number of hours to look back for findings",
    )
    report_parser.add_argument(
        "--csv", action="store_true", help="Generate a CSV file with findings"
    )
    report_parser.add_argument("--csv-path", help="Path to save the CSV file")

    # Test email command
    test_parser = subparsers.add_parser("test-email", help="Send a test email")
    test_parser.add_argument(
        "--email", required=True, help="Email address to send the test email to"
    )

    args = parser.parse_args()

    # Set up logging for CLI
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Initialize SOC2 mapper
    soc2_mapper = SOC2Mapper()

    if args.command == "report":
        # Set environment variables
        os.environ["RECIPIENT_EMAIL"] = args.email
        os.environ["SENDER_EMAIL"] = args.email  # For simplicity, use same email

        # Get findings
        findings = get_findings(args.hours)

        if not findings:
            print("No findings found in the specified time period.")
            return

        # Generate analysis
        analysis, stats = analyze_findings(findings, soc2_mapper)

        # Print summary to console
        print(f"\nAWS SecurityHub SOC 2 Compliance Report")
        print(
            f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        )
        print(f"Finding Summary:")
        print(f"Total Findings: {stats['total']}")
        print(f"Critical: {stats['critical']}")
        print(f"High: {stats['high']}")
        print(f"Medium: {stats['medium']}")
        print(f"Low: {stats['low']}\n")

        print("Analysis:")
        print(analysis)

        # Generate CSV if requested
        if args.csv:
            csv_data = generate_csv(findings, soc2_mapper)
            csv_path = (
                args.csv_path
                or f"securityhub_soc2_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )

            with open(csv_path, "w", encoding="utf-8") as f:
                f.write(csv_data)

            print(f"\nCSV report saved to: {csv_path}")

        # Send email
        if input("\nSend email report? (y/n): ").lower() == "y":
            success = send_email(args.email, findings, analysis, stats, soc2_mapper)
            if success:
                print(f"Email sent successfully to {args.email}")
            else:
                print(f"Failed to send email to {args.email}")

    elif args.command == "test-email":
        # Set environment variables
        os.environ["RECIPIENT_EMAIL"] = args.email
        os.environ["SENDER_EMAIL"] = args.email  # For simplicity, use same email

        # Send test email
        success = send_test_email(args.email)
        if success:
            print(f"Test email sent successfully to {args.email}")
        else:
            print(f"Failed to send test email to {args.email}")

    else:
        parser.print_help()


if __name__ == "__main__":
    cli_handler()
