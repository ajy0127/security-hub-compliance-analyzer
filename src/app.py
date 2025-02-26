"""
MIT License

Copyright (c) 2025 [Your Name or Organization]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import argparse
import csv
import io
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import boto3

from soc2_mapper import SOC2Mapper
from utils import format_datetime, get_resource_id

# =========================================================================
# AWS SecurityHub SOC2 Compliance Analyzer
# =========================================================================
# This application analyzes AWS SecurityHub findings and maps them to SOC2 
# controls to help GRC professionals monitor compliance. It can run as both
# an AWS Lambda function or as a standalone CLI utility.
#
# Main functionality:
# 1. Retrieves findings from AWS SecurityHub
# 2. Maps findings to SOC2 controls using pattern matching
# 3. Uses Amazon Bedrock to generate natural language analysis
# 4. Creates and sends professional compliance reports via email
# 5. Provides CLI functionality for local operation
# ========================================================================= 

# Configure logging for both Lambda and CLI environments
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_findings(hours):
    """
    Retrieve security findings from AWS SecurityHub for a specified time period.
    
    This function queries the AWS SecurityHub API to get active, failed compliance 
    findings that have been updated within the specified time window. It filters
    for findings that:
    - Have a ComplianceStatus of "FAILED" (indicating non-compliance)
    - Are in an "ACTIVE" RecordState (not archived)
    - Have a "NEW" WorkflowStatus (not yet addressed)
    - Were updated within the specified time window
    
    Args:
        hours (int or str): Number of hours to look back for findings
        
    Returns:
        list: A list of SecurityHub finding dictionaries or an empty list if no findings
              or if an error occurs
    """
    securityhub = boto3.client("securityhub")

    # Calculate time window for the query
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=int(hours))

    # Format times in the format required by SecurityHub API
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
            MaxResults=100,  # Limit results to prevent oversized responses
        )

        findings = response.get("Findings", [])
        logger.info(f"Found {len(findings)} findings")
        return findings

    except Exception as e:
        logger.error(f"Error getting findings from SecurityHub: {str(e)}")
        return []  # Return empty list on error to prevent downstream failures


def analyze_findings(findings, soc2_mapper):
    """
    Analyze SecurityHub findings and generate an expert compliance analysis using AI.
    
    This function:
    1. Maps raw SecurityHub findings to relevant SOC2 controls
    2. Generates summary statistics by severity level
    3. Groups findings by SOC2 control
    4. Uses Amazon Bedrock's Claude model to generate a professional compliance analysis
    5. Provides a fallback basic analysis if Bedrock is unavailable
    
    Args:
        findings (list): List of SecurityHub finding dictionaries
        soc2_mapper (SOC2Mapper): Instance of SOC2Mapper for mapping findings to controls
        
    Returns:
        tuple: (analysis_text, statistics_dict)
            - analysis_text: String containing the detailed analysis
            - statistics_dict: Dictionary with count of findings by severity
    """
    if not findings:
        return "No findings to analyze.", {}

    # Get the configured Bedrock model ID from environment variables (with default)
    bedrock_model_id = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")

    # Map each finding to corresponding SOC2 controls
    mapped_findings = []
    for finding in findings:
        mapped_finding = soc2_mapper.map_finding(finding)
        mapped_findings.append(mapped_finding)

    # Generate summary statistics by severity level
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

    # Group findings by SOC2 control for better analysis
    control_findings = {}
    for finding in mapped_findings:
        controls = finding.get("SOC2Controls", "Unknown")
        # Convert list of controls to string for dictionary key
        if isinstance(controls, list):
            controls = ", ".join(controls)

        # Initialize list for this control if it doesn't exist
        if controls not in control_findings:
            control_findings[controls] = []

        control_findings[controls].append(finding)

    try:
        # Use Amazon Bedrock's Claude model to generate expert analysis
        bedrock = boto3.client("bedrock-runtime")

        # Construct prompt for AI to generate professional compliance analysis
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
        
        Then, add a section titled "Auditor's Perspective" written from the perspective of a seasoned SOC 2 auditor with 15+ years of experience. This narrative should:
        1. Evaluate the severity of these findings in the context of a SOC 2 audit
        2. Explain the different impacts these findings would have on SOC 2 Type 1 vs Type 2 audits
        3. Provide specific remediation and mitigation advice that would satisfy an auditor's requirements
        4. Include language and terminology that a professional auditor would use
        5. Offer a professional opinion on the timeline and effort required to address these issues before an audit
        
        The auditor's perspective should be written in first person and should sound authoritative but constructive.
        
        Keep your total response under 1500 words and focus on actionable insights.
        """

        # Call Bedrock API with the prompt
        logger.info(f"Calling Bedrock model {bedrock_model_id} for analysis")
        response = bedrock.invoke_model(
            modelId=bedrock_model_id,
            body=json.dumps(
                {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 1500,
                    "messages": [{"role": "user", "content": prompt}],
                }
            ),
        )

        # Parse the response from Bedrock
        response_body = json.loads(response["body"].read())
        analysis = response_body["content"][0]["text"]
        logger.info("Successfully generated analysis with Bedrock")
        return analysis, stats

    except Exception as e:
        logger.error(f"Error generating analysis with Bedrock: {str(e)}")

        # Provide a simple fallback analysis if Bedrock call fails
        # This ensures the report generation doesn't fail completely
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
    """
    Generate a CSV report containing all findings mapped to SOC2 controls.
    
    Creates a CSV-formatted string with detailed information about each finding, 
    including their mapped SOC2 controls for easy analysis and documentation.
    This CSV can be used for:
    - Detailed audit evidence
    - Compliance tracking
    - Issue remediation planning
    - Historical record-keeping
    
    Args:
        findings (list): List of SecurityHub finding dictionaries
        soc2_mapper (SOC2Mapper): Instance of SOC2Mapper to map findings to controls
        
    Returns:
        str: CSV-formatted string containing all findings with their details
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Define CSV headers for the report
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

    # Process each finding and write it to the CSV
    for finding in findings:
        # Map the finding to SOC2 controls
        mapped_finding = soc2_mapper.map_finding(finding)
        
        # Format the controls as a comma-separated string
        controls = mapped_finding.get("SOC2Controls", "Unknown")
        if isinstance(controls, list):
            controls = ", ".join(controls)

        # Write the finding details as a row in the CSV
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

    # Return the CSV as a string
    return output.getvalue()


def send_email(recipient_email, findings, analysis, stats, soc2_mapper):
    """
    Send a professional email report with findings analysis and CSV attachment.
    
    Creates and sends a formatted HTML email containing:
    - Summary statistics of security findings by severity
    - Detailed AI-generated analysis with compliance impact assessment
    - CSV attachment with all findings for detailed review
    
    The email uses professional formatting with security-focused color coding
    and styling to make the report easy to read and interpret.
    
    Args:
        recipient_email (str): Email address to send the report to
        findings (list): List of SecurityHub finding dictionaries
        analysis (str): Text analysis of the findings (from analyze_findings)
        stats (dict): Statistics dictionary with counts by severity
        soc2_mapper (SOC2Mapper): Instance of SOC2Mapper to map findings to controls
        
    Returns:
        bool: True if email sent successfully, False otherwise
    """
    ses = boto3.client("ses")
    sender_email = os.environ.get("SENDER_EMAIL")

    # Validate that both sender and recipient emails are configured
    if not sender_email or not recipient_email:
        logger.error("Sender or recipient email not configured")
        return False

    # Create the email message container
    msg = MIMEMultipart("mixed")
    msg["Subject"] = (
        f'AWS SecurityHub SOC 2 Compliance Report - {datetime.now().strftime("%Y-%m-%d")}'
    )
    msg["From"] = sender_email
    msg["To"] = recipient_email

    # Format the analysis text to replace newlines with HTML line breaks for proper display
    formatted_analysis = analysis.replace("\n", "<br>")

    # Create HTML body with professional styling
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
            .auditor-perspective {{ 
                background-color: #f0f7ff; 
                padding: 20px; 
                border-left: 5px solid #0073bb; 
                margin: 20px 0; 
                border-radius: 5px;
                font-style: italic;
            }}
            .auditor-perspective h2 {{ 
                color: #0073bb; 
                margin-top: 0;
            }}
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
            {formatted_analysis}
        </div>
        
        <p>A detailed CSV report is attached with all findings mapped to SOC 2 controls.</p>
    </body>
    </html>
    """,
        "html",
    )

    # Attach the HTML part to the email
    msg.attach(html_part)

    # Generate and attach CSV report as an attachment
    csv_data = generate_csv(findings, soc2_mapper)
    attachment = MIMEApplication(csv_data.encode("utf-8"))
    attachment.add_header(
        "Content-Disposition",
        "attachment",
        filename="security_hub_compliance_findings.csv",
    )
    msg.attach(attachment)

    # Send the email using Amazon SES
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
    """
    Send a test email to verify email configuration is working correctly.
    
    This function is used to validate that:
    1. Both sender and recipient email addresses are verified in Amazon SES
    2. The Lambda function has proper SES permissions to send emails
    3. The email formatting and delivery process works as expected
    
    It sends a simple formatted email with no attachments as a validation check.
    
    Args:
        recipient_email (str): Email address to send the test email to
        
    Returns:
        bool: True if test email sent successfully, False otherwise
    """
    ses = boto3.client("ses")
    sender_email = os.environ.get("SENDER_EMAIL")

    # Validate that both sender and recipient emails are configured
    if not sender_email or not recipient_email:
        logger.error("Sender or recipient email not configured")
        return False

    # Create email message container for the test
    msg = MIMEMultipart("mixed")
    msg["Subject"] = "AWS SecurityHub SOC 2 Analyzer - Test Email"
    msg["From"] = sender_email
    msg["To"] = recipient_email

    # Create HTML body with minimal styling for the test
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

    # Attach the HTML content to the email
    msg.attach(html_part)

    # Send the test email using Amazon SES
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
    """
    Main AWS Lambda function entry point for the SecurityHub SOC2 Analyzer.
    
    This handler processes incoming Lambda events and orchestrates the entire analysis
    and reporting workflow. It supports two main operational modes:
    
    1. Test Email Mode: When the event contains {"test_email": true}, it sends a
       test email to verify email delivery configuration is working correctly.
       
    2. Analysis Mode: The default mode that:
       a. Retrieves SecurityHub findings for a specified time period
       b. Maps findings to SOC2 controls
       c. Generates AI-powered analysis using Amazon Bedrock
       d. Creates and sends professional email reports
       e. Optionally saves CSV data to a file
    
    Args:
        event (dict): Lambda event data that can contain configuration parameters:
            - test_email (bool): When true, sends a test email instead of a full report
            - recipient_email (str): Override the default recipient email for test mode
            - hours (int/str): Number of hours to look back for findings (default: 24)
            - email (str): Override the default recipient email for analysis mode
            - generate_csv (bool): Whether to save CSV data to a file in /tmp
        context (LambdaContext): AWS Lambda context object (not used)
        
    Returns:
        dict: Response containing status code and message
              - statusCode: 200 for success, 400/500 for errors
              - body: Description of the result or error
    """
    logger.info(f"Event received: {json.dumps(event)}")

    # Initialize the SOC2 mapper for mapping findings to controls
    soc2_mapper = SOC2Mapper()

    # === TEST EMAIL MODE ===
    # Check if this is a test email request ({"test_email": true})
    if event.get("test_email"):
        # Get recipient email from either the event or environment variables
        recipient_email = event.get(
            "recipient_email", os.environ.get("RECIPIENT_EMAIL")
        )
        if not recipient_email:
            return {
                "statusCode": 400,
                "body": json.dumps("Recipient email not provided for test"),
            }

        # Send a test email to verify configuration
        success = send_test_email(recipient_email)

        return {
            "statusCode": 200 if success else 500,
            "body": json.dumps(
                "Test email sent successfully"
                if success
                else "Failed to send test email"
            ),
        }

    # === ANALYSIS MODE ===
    # Get configuration from event or environment variables
    hours = event.get("hours", os.environ.get("FINDINGS_HOURS", "24"))
    recipient_email = event.get("email", os.environ.get("RECIPIENT_EMAIL"))
    generate_csv_file = event.get("generate_csv", False)

    # Validate essential configuration
    if not recipient_email:
        logger.error("Recipient email not configured")
        return {"statusCode": 500, "body": json.dumps("Recipient email not configured")}

    # Retrieve SecurityHub findings for the specified time period
    findings = get_findings(hours)

    # Check if we have any findings to process
    if not findings:
        logger.info("No findings found")
        return {"statusCode": 200, "body": json.dumps("No findings to report")}

    # Generate analysis of findings using AI
    analysis, stats = analyze_findings(findings, soc2_mapper)

    # Generate CSV file if requested (for local saving or additional processing)
    csv_path = None
    if generate_csv_file:
        csv_data = generate_csv(findings, soc2_mapper)
        csv_path = "/tmp/security_hub_compliance_findings.csv"
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write(csv_data)
        logger.info(f"CSV file saved to {csv_path}")

    # Send email report with findings and analysis
    success = send_email(recipient_email, findings, analysis, stats, soc2_mapper)

    # Return result to caller
    return {
        "statusCode": 200 if success else 500,
        "body": json.dumps(
            "Email sent successfully" if success else "Failed to send email"
        ),
    }


def cli_handler():
    """
    Command-line interface handler for running the tool locally.
    
    This function provides a command-line interface to the SecurityHub SOC2 Analyzer,
    allowing users to run the tool without deploying it as a Lambda function.
    
    It supports two main commands:
    1. 'report' - Generate and optionally email a compliance report
    2. 'test-email' - Send a test email to verify email configuration
    
    The CLI provides a user-friendly interface with interactive prompts and
    formatted console output for local testing and development.
    
    Args:
        None - Arguments are parsed from the command line
        
    Returns:
        None
    """
    # Set up command-line argument parser with subcommands
    parser = argparse.ArgumentParser(description="AWS SecurityHub SOC 2 Analyzer")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Configure 'report' subcommand and its arguments
    report_parser = subparsers.add_parser("report", help="Generate a compliance report")
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
    report_parser.add_argument(
        "--csv-path", 
        help="Path to save the CSV file (default: timestamped filename)"
    )

    # Configure 'test-email' subcommand and its arguments
    test_parser = subparsers.add_parser("test-email", help="Send a test email")
    test_parser.add_argument(
        "--email", required=True, help="Email address to send the test email to"
    )

    # Parse command-line arguments
    args = parser.parse_args()

    # Set up logging configuration for CLI environment
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Initialize SOC2 mapper for mapping findings to controls
    soc2_mapper = SOC2Mapper()

    # === REPORT COMMAND ===
    if args.command == "report":
        # Set environment variables for the email functions
        os.environ["RECIPIENT_EMAIL"] = args.email
        os.environ["SENDER_EMAIL"] = args.email  # For simplicity, use same email

        # Retrieve findings from SecurityHub
        print(f"Retrieving SecurityHub findings from the last {args.hours} hours...")
        findings = get_findings(args.hours)

        if not findings:
            print("No findings found in the specified time period.")
            return

        # Generate AI-powered analysis of findings
        print("Analyzing findings and generating report...")
        analysis, stats = analyze_findings(findings, soc2_mapper)

        # Print summary report to console with formatting
        print(f"\nAWS SecurityHub SOC 2 Compliance Report")
        print(f"=" * 50)
        print(
            f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        )
        print(f"Finding Summary:")
        print(f"- Total Findings: {stats['total']}")
        print(f"- Critical: {stats['critical']}")
        print(f"- High: {stats['high']}")
        print(f"- Medium: {stats['medium']}")
        print(f"- Low: {stats['low']}\n")

        print("Analysis:")
        print("-" * 50)
        print(analysis)
        print("-" * 50)

        # Generate CSV file if requested
        if args.csv:
            csv_data = generate_csv(findings, soc2_mapper)
            # Use provided path or generate a timestamped filename
            csv_path = args.csv_path or (
                f"security_hub_compliance_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )

            with open(csv_path, "w", encoding="utf-8") as f:
                f.write(csv_data)

            print(f"\nCSV report saved to: {csv_path}")

        # Prompt user for email confirmation
        if input("\nSend email report? (y/n): ").lower() == "y":
            print(f"Sending email to {args.email}...")
            success = send_email(args.email, findings, analysis, stats, soc2_mapper)
            if success:
                print(f"Email sent successfully to {args.email}")
            else:
                print(f"Failed to send email to {args.email}")

    # === TEST EMAIL COMMAND ===
    elif args.command == "test-email":
        # Set environment variables for the email functions
        os.environ["RECIPIENT_EMAIL"] = args.email
        os.environ["SENDER_EMAIL"] = args.email  # For simplicity, use same email

        # Send test email to verify configuration
        print(f"Sending test email to {args.email}...")
        success = send_test_email(args.email)
        if success:
            print(f"Test email sent successfully to {args.email}")
            print("If you don't receive the email, check your spam folder and verify that the email is verified in SES.")
        else:
            print(f"Failed to send test email to {args.email}")
            print("Make sure the email address is verified in Amazon SES and your AWS credentials have SES permissions.")

    # No valid command specified, show help
    else:
        parser.print_help()


# Entry point when script is run directly
if __name__ == "__main__":
    cli_handler()
