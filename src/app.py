"""MIT License for AWS SecurityHub Compliance Analyzer - Multi-Framework Support."""

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

from soc2_mapper import SOC2Mapper  # Keep this for backward compatibility

try:
    from framework_mapper import FrameworkMapper
    from mapper_factory import MapperFactory, load_frameworks
except ImportError:
    # When running directly
    from src.framework_mapper import FrameworkMapper
    from src.mapper_factory import MapperFactory, load_frameworks
from utils import format_datetime, get_resource_id

# Configure logging for both Lambda and CLI environments
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_findings(hours, framework_id=None):
    """
    Retrieve security findings from AWS SecurityHub for a specified time period.

    This function queries the AWS SecurityHub API to get active, failed compliance
    findings that have been updated within the specified time window. It filters
    for findings that:
    - Have a ComplianceStatus of "FAILED" (indicating non-compliance)
    - Are in an "ACTIVE" RecordState (not archived)
    - Have a "NEW" WorkflowStatus (not yet addressed)
    - Were updated within the specified time window
    - Optionally match a specific compliance framework

    Args:
        hours (int or str): Number of hours to look back for findings
        framework_id (str, optional): Specific framework ID to filter by

    Returns:
        dict: Dictionary of findings grouped by framework ID, or a list if specific framework
              is requested. Empty if no findings or if an error occurs.
    """
    securityhub = boto3.client("securityhub")

    # Calculate time window for the query
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=int(hours))

    # Format times in the format required by SecurityHub API
    start_time_str = format_datetime(start_time)
    end_time_str = format_datetime(end_time)

    # Load framework configurations
    frameworks = load_frameworks()

    # Filter to specific framework if requested
    if framework_id:
        # Case-insensitive framework ID matching
        framework_id_upper = framework_id.upper()
        frameworks = [f for f in frameworks if f["id"].upper() == framework_id_upper]
        if not frameworks:
            logger.error(f"Framework {framework_id} not found")
            return {} if framework_id else []

    # Query SecurityHub for findings for each framework
    all_findings = {}
    for framework in frameworks:
        try:
            logger.info(
                f"Querying SecurityHub for {framework['name']} findings between {start_time_str} and {end_time_str}"
            )

            # Base filters that apply to all queries
            filters = {
                "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
                "UpdatedAt": [{"Start": start_time_str, "End": end_time_str}],
            }

            # Add framework-specific filter using the ARN
            # Note: Security Hub uses Standards.Arn or StandardsArn depending on the API version
            # Try both patterns to ensure compatibility
            try:
                # First try with StandardsArn (newer pattern)
                framework_filter = {
                    "StandardsArn": [
                        {"Value": framework["arn"], "Comparison": "EQUALS"}
                    ]
                }
                response = securityhub.get_findings(
                    Filters={**filters, **framework_filter},
                    MaxResults=100,  # Limit results to prevent oversized responses
                )
            except Exception as e:
                if "ValidationException" in str(e):
                    # Fall back to Standards.Arn (older pattern)
                    framework_filter = {
                        "Standards.Arn": [
                            {"Value": framework["arn"], "Comparison": "EQUALS"}
                        ]
                    }
                    response = securityhub.get_findings(
                        Filters={**filters, **framework_filter},
                        MaxResults=100,  # Limit results to prevent oversized responses
                    )
                else:
                    # Re-raise if it's not a validation exception
                    raise

            framework_findings = response.get("Findings", [])
            logger.info(
                f"Found {len(framework_findings)} findings for {framework['name']}"
            )

            all_findings[framework["id"]] = framework_findings

        except Exception as e:
            logger.error(f"Error getting {framework['name']} findings: {str(e)}")
            all_findings[framework["id"]] = []

    # If specific framework requested, return just those findings
    if framework_id and framework_id.upper() in all_findings:
        return all_findings[framework_id.upper()]

    return all_findings


def analyze_findings(findings, mappers, framework_id=None, combined=False):
    """
    Analyze SecurityHub findings and generate an expert compliance analysis using AI.

    This function:
    1. Maps raw SecurityHub findings to relevant framework controls
    2. Generates summary statistics by severity level
    3. Groups findings by framework control
    4. Uses Amazon Bedrock's Claude model to generate a professional compliance analysis
    5. Provides a fallback basic analysis if Bedrock is unavailable

    Args:
        findings (dict or list): Findings grouped by framework ID, or list if single framework
        mappers (dict or FrameworkMapper): Dictionary of mappers by framework ID, or single mapper
        framework_id (str, optional): Specific framework ID to analyze
        combined (bool, optional): Whether to generate a combined analysis for all frameworks

    Returns:
        tuple: (analyses_dict, statistics_dict)
            - analyses_dict: Dictionary of analysis texts by framework ID (or 'combined')
            - statistics_dict: Dictionary of statistics by framework ID
    """
    # Get the configured Bedrock model ID from environment variables (with default)
    bedrock_model_id = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet")

    # Initialize results
    analyses = {}
    stats = {}

    # Normalize input to handle both single framework and multiple frameworks cases
    if isinstance(findings, list):
        # Convert single framework findings list to dict format
        framework_id = framework_id or "SOC2"  # Default to SOC2 if not specified
        findings = {framework_id: findings}

        # Convert single mapper to dict format if needed
        if not isinstance(mappers, dict):
            mappers = {framework_id: mappers}

    # Check if we have any findings
    if not findings or not any(findings.values()):
        return {"combined": "No findings to analyze."}, {}

    # Process each framework's findings
    for framework_id, framework_findings in findings.items():
        if not framework_findings:
            analyses[framework_id] = f"No findings to analyze for {framework_id}."
            stats[framework_id] = {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }
            continue

        # Get appropriate mapper for this framework
        mapper = mappers.get(framework_id)
        if not mapper:
            logger.error(f"No mapper available for {framework_id}")
            continue

        # Map each finding to corresponding framework controls
        mapped_findings = []
        for finding in framework_findings:
            mapped_finding = mapper.map_finding(finding)
            mapped_findings.append(mapped_finding)

        # Generate summary statistics by severity level
        framework_stats = {
            "total": len(framework_findings),
            "critical": len(
                [
                    f
                    for f in framework_findings
                    if f.get("Severity", {}).get("Label") == "CRITICAL"
                ]
            ),
            "high": len(
                [
                    f
                    for f in framework_findings
                    if f.get("Severity", {}).get("Label") == "HIGH"
                ]
            ),
            "medium": len(
                [
                    f
                    for f in framework_findings
                    if f.get("Severity", {}).get("Label") == "MEDIUM"
                ]
            ),
            "low": len(
                [
                    f
                    for f in framework_findings
                    if f.get("Severity", {}).get("Label") == "LOW"
                ]
            ),
        }
        stats[framework_id] = framework_stats

        # Get control attribute name (e.g., "SOC2Controls", "NIST800-53Controls")
        control_attr = mapper.get_control_id_attribute()

        # Group findings by control for better analysis
        control_findings = {}
        for finding in mapped_findings:
            controls = finding.get(control_attr, "Unknown")
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

            # Get framework name from configuration
            frameworks = load_frameworks()
            framework_name = next(
                (f["name"] for f in frameworks if f["id"] == framework_id), framework_id
            )

            # Construct prompt for AI to generate professional compliance analysis
            prompt = f"""You are a {framework_name} compliance expert analyzing AWS SecurityHub findings.

Here are the statistics of the findings:
- Total findings: {framework_stats['total']}
- Critical findings: {framework_stats['critical']}
- High findings: {framework_stats['high']}
- Medium findings: {framework_stats['medium']}
- Low findings: {framework_stats['low']}

Here are the top findings mapped to {framework_name} controls:
{json.dumps(mapped_findings[:20], indent=2)}

Here are the findings grouped by {framework_name} control:
{json.dumps({k: len(v) for k, v in control_findings.items()}, indent=2)}

Please provide a concise analysis of these findings with the following sections:
1. Executive Summary: A brief overview of the security posture
2. {framework_name} Impact: How these findings affect {framework_name} compliance
3. Key Recommendations: Top 3-5 actions to address the most critical issues

Then, add a section titled "Auditor's Perspective" written from the perspective of a seasoned {framework_name} auditor with 15+ years of experience. This narrative should:
1. Evaluate the severity of these findings in the context of a {framework_name} audit
2. Explain the different impacts these findings would have on different types of {framework_name} assessments
3. Provide specific remediation and mitigation advice that would satisfy an auditor's requirements
4. Include language and terminology that a professional auditor would use
5. Offer a professional opinion on the timeline and effort required to address these issues before an audit

The auditor's perspective should be written in first person and should sound authoritative but constructive.

Keep your total response under 1500 words and focus on actionable insights."""

            # Call Bedrock API with the prompt
            logger.info(
                f"Calling Bedrock model {bedrock_model_id} for {framework_id} analysis"
            )
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
            logger.info(
                f"Successfully generated analysis for {framework_id} with Bedrock"
            )
            analyses[framework_id] = analysis

        except Exception as e:
            logger.error(
                f"Error generating analysis for {framework_id} with Bedrock: {str(e)}"
            )

            # Provide a simple fallback analysis if Bedrock call fails
            # This ensures the report generation doesn't fail completely
            analyses[framework_id] = (
                f"""## {framework_name} Findings Summary

Total findings: {framework_stats['total']}
- Critical: {framework_stats['critical']}
- High: {framework_stats['high']}
- Medium: {framework_stats['medium']}
- Low: {framework_stats['low']}

Please review the attached CSV for details on all findings."""
            )

    # Generate combined analysis if requested
    if combined and len(findings) > 1:
        try:
            # Use Amazon Bedrock's Claude model to generate combined analysis
            bedrock = boto3.client("bedrock-runtime")

            # Generate summary of frameworks and their findings
            frameworks_summary = []
            for framework_id, framework_findings in findings.items():
                framework_stats = stats[framework_id]
                frameworks = load_frameworks()
                framework_name = next(
                    (f["name"] for f in frameworks if f["id"] == framework_id),
                    framework_id,
                )
                frameworks_summary.append(
                    f"{framework_name}: {framework_stats['total']} findings "
                    f"({framework_stats['critical']} critical, {framework_stats['high']} high, "
                    f"{framework_stats['medium']} medium, {framework_stats['low']} low)"
                )

            # Construct prompt for combined analysis
            prompt = f"""You are a compliance expert analyzing AWS SecurityHub findings across multiple compliance frameworks.

Here is a summary of findings across different frameworks:
{chr(10).join(f"- {s}" for s in frameworks_summary)}

Please provide a concise cross-framework analysis with the following sections:
1. Executive Summary: A brief overview of the overall security posture
2. Framework Comparison: How compliance issues overlap and differ across frameworks
3. Key Priorities: Top 3-5 actions that would have the greatest impact across multiple frameworks
4. Strategic Roadmap: A suggested approach to addressing findings in a way that efficiently satisfies multiple frameworks

Keep your response under 1500 words and focus on actionable insights that address requirements across frameworks."""

            # Call Bedrock API with the prompt
            logger.info(
                f"Calling Bedrock model {bedrock_model_id} for combined framework analysis"
            )
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
            combined_analysis = response_body["content"][0]["text"]
            logger.info("Successfully generated combined analysis with Bedrock")
            analyses["combined"] = combined_analysis

        except Exception as e:
            logger.error(f"Error generating combined analysis with Bedrock: {str(e)}")

            # Provide a simple fallback combined analysis
            framework_stats_text = []
            for framework_id, framework_stats in stats.items():
                frameworks = load_frameworks()
                framework_name = next(
                    (f["name"] for f in frameworks if f["id"] == framework_id),
                    framework_id,
                )
                framework_stats_text.append(
                    f"## {framework_name} Summary\n\n"
                    f"Total findings: {framework_stats['total']}\n"
                    f"- Critical: {framework_stats['critical']}\n"
                    f"- High: {framework_stats['high']}\n"
                    f"- Medium: {framework_stats['medium']}\n"
                    f"- Low: {framework_stats['low']}\n"
                )

            analyses["combined"] = (
                "# Multi-Framework Compliance Summary\n\n"
                "This report contains findings across multiple compliance frameworks.\n\n"
                f"{chr(10).join(framework_stats_text)}\n\n"
                "Please review the framework-specific sections and attached CSVs for details on all findings."
            )

    return analyses, stats


def generate_csv(findings, mappers, framework_id=None):
    """
    Generate a CSV report containing all findings mapped to framework controls.

    Creates a CSV-formatted string with detailed information about each finding,
    including their mapped framework controls for easy analysis and documentation.
    This CSV can be used for:
    - Detailed audit evidence
    - Compliance tracking
    - Issue remediation planning
    - Historical record-keeping

    Args:
        findings (dict or list): Findings grouped by framework ID, or list if single framework
        mappers (dict or FrameworkMapper): Dictionary of mappers by framework ID, or single mapper
        framework_id (str, optional): Specific framework ID to generate CSV for

    Returns:
        dict or str: Dictionary of CSV strings by framework ID, or single CSV string if framework_id specified
    """
    # Normalize input to handle both single framework and multiple frameworks cases
    if isinstance(findings, list):
        # Convert single framework findings list to dict format
        framework_id = framework_id or "SOC2"  # Default to SOC2 if not specified
        findings = {framework_id: findings}

        # Convert single mapper to dict format if needed
        if not isinstance(mappers, dict):
            mappers = {framework_id: mappers}

    # If specific framework requested, only process that one
    if framework_id and framework_id in findings:
        frameworks_to_process = {framework_id: findings[framework_id]}
    else:
        frameworks_to_process = findings

    # Dictionary to hold CSV data for each framework
    csv_data = {}

    # Process each framework's findings
    for framework_id, framework_findings in frameworks_to_process.items():
        if not framework_findings:
            csv_data[framework_id] = ""
            continue

        # Get appropriate mapper for this framework
        mapper = mappers.get(framework_id)
        if not mapper:
            logger.error(f"No mapper available for {framework_id}")
            continue

        # Get framework name from configuration
        frameworks = load_frameworks()
        framework_name = next(
            (f["name"] for f in frameworks if f["id"] == framework_id), framework_id
        )

        # Get control attribute name (e.g., "SOC2Controls", "NIST800-53Controls")
        control_attr = mapper.get_control_id_attribute()

        # Create CSV for this framework
        output = io.StringIO()
        writer = csv.writer(output)

        # Define CSV headers for the report
        writer.writerow(
            [
                "Title",
                "Severity",
                "Finding Type",
                f"{framework_name} Controls",
                "Resource ID",
                "Account ID",
                "Region",
                "Description",
            ]
        )

        # Process each finding and write it to the CSV
        for finding in framework_findings:
            # Map the finding to framework controls
            mapped_finding = mapper.map_finding(finding)

            # Format the controls as a comma-separated string
            controls = mapped_finding.get(control_attr, "Unknown")
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

        # Store the CSV data for this framework
        csv_data[framework_id] = output.getvalue()

    # If specific framework requested, return just that CSV
    if framework_id and framework_id in csv_data:
        return csv_data[framework_id]

    return csv_data


def send_email(
    recipient_email,
    findings,
    analyses,
    stats,
    mappers,
    selected_framework=None,
    include_combined=True,
):
    """
    Send a professional email report with findings analysis and CSV attachments.

    Creates and sends a formatted HTML email containing:
    - Summary statistics of security findings by severity for each framework
    - Detailed AI-generated analysis with compliance impact assessment
    - CSV attachments with all findings mapped to respective framework controls

    The email uses professional formatting with security-focused color coding
    and styling to make the report easy to read and interpret.

    Args:
        recipient_email (str): Email address to send the report to
        findings (dict or list): Findings grouped by framework ID, or list if single framework
        analyses (dict): Analysis text for each framework (from analyze_findings)
        stats (dict): Statistics dictionary with counts by severity for each framework
        mappers (dict or FrameworkMapper): Dictionary of mappers by framework ID, or single mapper
        selected_framework (str, optional): Only include this framework in the email report
        include_combined (bool, optional): Whether to include combined analysis in the report

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    ses = boto3.client("ses")
    sender_email = os.environ.get("SENDER_EMAIL")

    # Validate that both sender and recipient emails are configured
    if not sender_email or not recipient_email:
        logger.error("Sender or recipient email not configured")
        return False

    # Normalize input to handle both single framework and multiple frameworks cases
    if isinstance(findings, list):
        # Convert single framework findings list to dict format
        framework_id = selected_framework or "SOC2"  # Default to SOC2 if not specified
        findings = {framework_id: findings}

        # Convert single mapper to dict format if needed
        if not isinstance(mappers, dict):
            mappers = {framework_id: mappers}

    # If specific framework requested, only include that one
    if selected_framework:
        if selected_framework in findings:
            frameworks_to_include = [selected_framework]
        else:
            logger.error(
                f"Selected framework {selected_framework} not found in findings"
            )
            return False
    else:
        frameworks_to_include = list(findings.keys())

    # Get framework names from configuration
    frameworks_config = load_frameworks()
    framework_names = {f["id"]: f["name"] for f in frameworks_config}

    # Create the email message container
    msg = MIMEMultipart("mixed")

    # Determine the email subject based on frameworks included
    if len(frameworks_to_include) == 1:
        framework_name = framework_names.get(
            frameworks_to_include[0], frameworks_to_include[0]
        )
        subject = f'AWS SecurityHub {framework_name} Compliance Report - {datetime.now().strftime("%Y-%m-%d")}'
    else:
        subject = f'AWS SecurityHub Multi-Framework Compliance Report - {datetime.now().strftime("%Y-%m-%d")}'

    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient_email

    # Generate framework-specific sections
    framework_sections = []

    # First add combined analysis if available and requested
    if "combined" in analyses and include_combined and len(frameworks_to_include) > 1:
        formatted_combined_analysis = analyses["combined"].replace("\n", "<br>")
        framework_sections.append(
            f"""
        <div id="combined-analysis">
            <h2>Cross-Framework Analysis</h2>
            <div class="analysis-content">
                {formatted_combined_analysis}
            </div>
        </div>
        <hr>
        """
        )

    # Add framework-specific sections
    for framework_id in frameworks_to_include:
        if framework_id not in findings or not findings[framework_id]:
            continue

        framework_name = framework_names.get(framework_id, framework_id)
        framework_stats = stats.get(
            framework_id, {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        )
        framework_analysis = analyses.get(
            framework_id, f"No analysis available for {framework_name}"
        )
        formatted_analysis = framework_analysis.replace("\n", "<br>")

        framework_sections.append(
            f"""
        <div id="{framework_id}-analysis" class="framework-section">
            <h2>{framework_name} Compliance Analysis</h2>
            
            <div class="summary">
                <h3>Finding Summary</h3>
                <p><strong>Total Findings:</strong> {framework_stats['total']}</p>
                <p><strong class="critical">Critical:</strong> {framework_stats['critical']}</p>
                <p><strong class="high">High:</strong> {framework_stats['high']}</p>
                <p><strong class="medium">Medium:</strong> {framework_stats['medium']}</p>
                <p><strong class="low">Low:</strong> {framework_stats['low']}</p>
            </div>
            
            <div class="analysis-content">
                {formatted_analysis}
            </div>
        </div>
        <hr>
        """
        )

    # Create HTML body with professional styling
    html_part = MIMEText(
        f"""<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #232f3e; }}
        .summary {{ background-color: #f8f8f8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .critical {{ color: #d13212; }}
        .high {{ color: #ff9900; }}
        .medium {{ color: #d9b43c; }}
        .low {{ color: #6b6b6b; }}
        .auditor-perspective {{ 
            background-color: #f0f7ff; 
            padding: 20px; 
            border-left: 5px solid #0073bb; 
            margin: 20px 0; 
            border-radius: 5px;
            font-style: italic;
        }}
        .auditor-perspective h2, .auditor-perspective h3 {{ 
            color: #0073bb; 
            margin-top: 0;
        }}
        .framework-section {{
            margin-bottom: 30px;
        }}
        hr {{
            border: 0;
            height: 1px;
            background-color: #d0d0d0;
            margin: 30px 0;
        }}
        .framework-nav {{
            background-color: #f0f0f0;
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .framework-nav a {{
            margin-right: 15px;
            color: #0073bb;
            text-decoration: none;
            font-weight: bold;
        }}
        .framework-nav a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <h1>{subject}</h1>
    <p>Report generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>
    
    <!-- Framework navigation menu for multi-framework reports -->
    {
    f'''<div class="framework-nav">
        Jump to:
        {"<a href='#combined-analysis'>Cross-Framework Analysis</a>" if "combined" in analyses and include_combined and len(frameworks_to_include) > 1 else ""}
        {" ".join(f"<a href='#{fid}-analysis'>{framework_names.get(fid, fid)}</a>" for fid in frameworks_to_include if fid in findings and findings[fid])}
    </div>''' if len(frameworks_to_include) > 1 else ""
    }
    
    {"".join(framework_sections)}
    
    <p>Detailed CSV reports are attached with all findings mapped to their respective framework controls.</p>
</body>
</html>""",
        "html",
    )

    # Attach the HTML part to the email
    msg.attach(html_part)

    # Generate and attach CSV reports as attachments
    csv_data = generate_csv(findings, mappers)

    # Add each framework's CSV as an attachment
    for framework_id in frameworks_to_include:
        if framework_id not in csv_data or not csv_data[framework_id]:
            continue

        framework_name = framework_names.get(framework_id, framework_id)
        attachment = MIMEApplication(csv_data[framework_id].encode("utf-8"))
        attachment.add_header(
            "Content-Disposition",
            "attachment",
            filename=f"{framework_id.lower()}_compliance_findings.csv",
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

    # Get list of supported frameworks
    frameworks = load_frameworks()
    framework_list = ", ".join([f"{f['name']} ({f['id']})" for f in frameworks])

    # Create email message container for the test
    msg = MIMEMultipart("mixed")
    msg["Subject"] = "AWS SecurityHub Compliance Analyzer - Test Email"
    msg["From"] = sender_email
    msg["To"] = recipient_email

    # Create HTML body with minimal styling for the test
    html_part = MIMEText(
        f"""<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #232f3e; }}
        .box {{ background-color: #f8f8f8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .framework-list {{ background-color: #f0f7ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>AWS SecurityHub Compliance Analyzer - Test Email</h1>

    <div class="box">
        <h2>Configuration Test Successful</h2>
        <p>This email confirms that your SecurityHub Compliance Analyzer is properly configured for email delivery.</p>
        <p>Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>
    </div>
    
    <div class="framework-list">
        <h2>Supported Compliance Frameworks</h2>
        <p>This analyzer supports the following compliance frameworks:</p>
        <p>{framework_list}</p>
    </div>

    <p>The analyzer will send reports according to the configured schedule. You can specify which framework(s) to analyze using the command-line options or Lambda event parameters.</p>
</body>
</html>""",
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
    Main AWS Lambda function entry point for the SecurityHub Compliance Analyzer.

    This handler processes incoming Lambda events and orchestrates the entire analysis
    and reporting workflow. It supports several operational modes:

    1. List Frameworks Mode: When the event contains {"list_frameworks": true}, it returns
       the list of supported compliance frameworks.

    2. Test Email Mode: When the event contains {"test_email": true}, it sends a
       test email to verify email delivery configuration is working correctly.

    3. Analysis Mode: The default mode that:
       a. Retrieves SecurityHub findings for a specified time period
       b. Maps findings to framework controls
       c. Generates AI-powered analysis using Amazon Bedrock
       d. Creates and sends professional email reports
       e. Optionally saves CSV data to a file

    Args:
        event (dict): Lambda event data that can contain configuration parameters:
            - list_frameworks (bool): When true, returns list of supported frameworks
            - test_email (bool): When true, sends a test email instead of a full report
            - recipient_email (str): Override the default recipient email for test mode
            - hours (int/str): Number of hours to look back for findings (default: 24)
            - email (str): Override the default recipient email for analysis mode
            - framework (str): Specific framework to analyze (SOC2, NIST800-53, or "all")
            - generate_csv (bool): Whether to save CSV data to a file in /tmp
            - combined_analysis (bool): Whether to include a combined cross-framework analysis
        context (LambdaContext): AWS Lambda context object (not used)

    Returns:
        dict: Response containing status code and message
              - statusCode: 200 for success, 400/500 for errors
              - body: Description of the result or error
    """
    logger.info(f"Event received: {json.dumps(event)}")

    # === LIST FRAMEWORKS MODE ===
    # Check if this is a request to list supported frameworks
    if event.get("list_frameworks"):
        # Get all supported frameworks
        frameworks = load_frameworks()
        return {
            "statusCode": 200,
            "body": json.dumps(
                {"message": "Supported compliance frameworks", "frameworks": frameworks}
            ),
        }

    # === TEST EMAIL MODE ===
    # Check if this is a test email request ({"test_email": true})
    elif event.get("test_email"):
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
    framework_id = event.get("framework", os.environ.get("DEFAULT_FRAMEWORK", "all"))
    generate_csv_file = event.get("generate_csv", False)
    include_combined = event.get("combined_analysis", True)

    # Validate essential configuration
    if not recipient_email:
        logger.error("Recipient email not configured")
        return {"statusCode": 500, "body": json.dumps("Recipient email not configured")}

    # Initialize all framework mappers
    mappers = MapperFactory.get_all_mappers()
    if not mappers:
        logger.error("Failed to initialize framework mappers")
        return {
            "statusCode": 500,
            "body": json.dumps("Failed to initialize framework mappers"),
        }

    # Retrieve SecurityHub findings for the specified time period and framework
    if framework_id.lower() == "all":
        # Retrieve findings for all frameworks
        findings = get_findings(hours)
    else:
        # Retrieve findings for specific framework
        framework_findings = get_findings(hours, framework_id)
        if isinstance(framework_findings, dict):
            # API returned dictionary format
            findings = framework_findings
        else:
            # API returned list format (single framework)
            findings = {framework_id: framework_findings}

    # Check if we have any findings to process
    if not findings or not any(findings.values()):
        logger.info("No findings found")
        return {"statusCode": 200, "body": json.dumps("No findings to report")}

    # Generate analysis of findings using AI
    analyses, stats = analyze_findings(
        findings,
        mappers,
        None,  # No need to specify framework_id since it's already filtered in findings
        include_combined
        and len(findings)
        > 1,  # Only do combined analysis if we have multiple frameworks
    )

    # Generate CSV files if requested (for local saving or additional processing)
    if generate_csv_file:
        csv_data = generate_csv(findings, mappers)
        # Save each framework's CSV to a separate file
        for framework_id, framework_csv in csv_data.items():
            if not framework_csv:
                continue

            csv_path = f"/tmp/{framework_id.lower()}_compliance_findings.csv"
            with open(csv_path, "w", encoding="utf-8") as f:
                f.write(framework_csv)
            logger.info(f"CSV file for {framework_id} saved to {csv_path}")

    # Send email report with findings and analysis
    success = send_email(
        recipient_email,
        findings,
        analyses,
        stats,
        mappers,
        None,  # No need for selected_framework (it's already filtered)
        include_combined,
    )

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

    This function provides a command-line interface to the SecurityHub Compliance Analyzer,
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
    parser = argparse.ArgumentParser(description="AWS SecurityHub Compliance Analyzer")
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
        "--framework",
        default="all",
        help="Compliance framework to analyze (SOC2, NIST800-53, or 'all')",
    )
    report_parser.add_argument(
        "--no-combined",
        action="store_true",
        help="Disable combined cross-framework analysis",
    )
    report_parser.add_argument(
        "--csv", action="store_true", help="Generate CSV file(s) with findings"
    )
    report_parser.add_argument(
        "--csv-path", help="Directory to save CSV file(s) (default: current directory)"
    )

    # Configure 'test-email' subcommand and its arguments
    test_parser = subparsers.add_parser("test-email", help="Send a test email")
    test_parser.add_argument(
        "--email", required=True, help="Email address to send the test email to"
    )

    # Configure 'list-frameworks' subcommand
    list_parser = subparsers.add_parser(
        "list-frameworks", help="List supported compliance frameworks"
    )

    # Parse command-line arguments
    args = parser.parse_args()

    # Set up logging configuration for CLI environment
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Load supported frameworks
    frameworks = load_frameworks()

    # Initialize framework mappers
    mappers = MapperFactory.get_all_mappers()

    # === LIST FRAMEWORKS COMMAND ===
    if args.command == "list-frameworks":
        print("\nSupported Compliance Frameworks:")
        print("-" * 30)
        for framework in frameworks:
            print(f"ID: {framework['id']}")
            print(f"Name: {framework['name']}")
            print(f"Description: {framework['description']}")
            print("-" * 30)
        return

    # === REPORT COMMAND ===
    elif args.command == "report":
        # Set environment variables for the email functions
        os.environ["RECIPIENT_EMAIL"] = args.email
        os.environ["SENDER_EMAIL"] = args.email  # For simplicity, use same email

        # Determine which framework(s) to analyze
        framework_id = args.framework
        include_combined = not args.no_combined

        # Retrieve findings from SecurityHub
        if framework_id.lower() == "all":
            print(
                f"Retrieving findings for all frameworks from the last {args.hours} hours..."
            )
            findings = get_findings(args.hours)
        else:
            print(
                f"Retrieving {framework_id} findings from the last {args.hours} hours..."
            )
            framework_findings = get_findings(args.hours, framework_id)
            if isinstance(framework_findings, dict):
                findings = framework_findings
            else:
                findings = {framework_id: framework_findings}

        # Check if we have any findings to process
        if not findings or not any(findings.values()):
            print("No findings found in the specified time period.")
            return

        # Generate AI-powered analysis of findings
        print("Analyzing findings and generating report...")
        analyses, stats = analyze_findings(
            findings, mappers, None, include_combined and len(findings) > 1
        )

        # Print summary report to console with formatting
        if len(findings) == 1:
            # Single framework report
            framework_id = next(iter(findings.keys()))
            framework_name = next(
                (f["name"] for f in frameworks if f["id"] == framework_id), framework_id
            )
            framework_stats = stats[framework_id]
            framework_analysis = analyses[framework_id]

            print(f"\nAWS SecurityHub {framework_name} Compliance Report")
            print(f"=" * 60)
            print(
                f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
            )
            print(f"Finding Summary:")
            print(f"- Total Findings: {framework_stats['total']}")
            print(f"- Critical: {framework_stats['critical']}")
            print(f"- High: {framework_stats['high']}")
            print(f"- Medium: {framework_stats['medium']}")
            print(f"- Low: {framework_stats['low']}\n")

            print("Analysis:")
            print("-" * 60)
            print(framework_analysis)
            print("-" * 60)
        else:
            # Multi-framework report
            print(f"\nAWS SecurityHub Multi-Framework Compliance Report")
            print(f"=" * 60)
            print(
                f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
            )

            # Print combined analysis if available
            if "combined" in analyses:
                print("Cross-Framework Analysis:")
                print("-" * 60)
                print(analyses["combined"])
                print("-" * 60)

            # Print summary for each framework
            for framework_id, framework_stats in stats.items():
                framework_name = next(
                    (f["name"] for f in frameworks if f["id"] == framework_id),
                    framework_id,
                )
                print(f"\n{framework_name} Finding Summary:")
                print(f"- Total Findings: {framework_stats['total']}")
                print(f"- Critical: {framework_stats['critical']}")
                print(f"- High: {framework_stats['high']}")
                print(f"- Medium: {framework_stats['medium']}")
                print(f"- Low: {framework_stats['low']}")

        # Generate CSV file(s) if requested
        if args.csv:
            csv_data = generate_csv(findings, mappers)

            # Determine base directory for CSV files
            csv_base_dir = args.csv_path or os.getcwd()

            # Save each framework's CSV
            for framework_id, framework_csv in csv_data.items():
                if not framework_csv:
                    continue

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                csv_path = os.path.join(
                    csv_base_dir,
                    f"{framework_id.lower()}_compliance_findings_{timestamp}.csv",
                )

                with open(csv_path, "w", encoding="utf-8") as f:
                    f.write(framework_csv)

                print(f"\nCSV report for {framework_id} saved to: {csv_path}")

        # Prompt user for email confirmation
        if input("\nSend email report? (y/n): ").lower() == "y":
            print(f"Sending email to {args.email}...")
            success = send_email(
                args.email, findings, analyses, stats, mappers, None, include_combined
            )
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
            print(
                "If you don't receive the email, check your spam folder and verify that the email is verified in SES."
            )
        else:
            print(f"Failed to send test email to {args.email}")
            print(
                "Make sure the email address is verified in Amazon SES and your AWS credentials have SES permissions."
            )

    # No valid command specified, show help
    else:
        parser.print_help()


# Entry point when script is run directly
if __name__ == "__main__":
    cli_handler()
