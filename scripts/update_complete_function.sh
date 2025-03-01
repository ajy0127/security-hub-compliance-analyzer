#!/bin/bash
# Script to create and deploy a comprehensive Lambda package with full NIST 800-53 support

# Set variables
FUNCTION_NAME="security-hub-compliance-analyzer-SecurityHubAnalyzer"
S3_BUCKET="openauditorcode"
ZIP_FILE="lambda-code.zip"
PROFILE="sandbox"

echo "Creating comprehensive Lambda deployment package..."

# Create a temporary directory
TEMP_DIR=$(mktemp -d)
echo "Created temporary directory: $TEMP_DIR"

# Get the project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Create directory structure
mkdir -p "$TEMP_DIR/config/mappings"
mkdir -p "$TEMP_DIR/mappers"

# Copy the actual framework configurations
echo "Copying configuration files..."
cp "$PROJECT_ROOT/config/frameworks.json" "$TEMP_DIR/config/"
cp "$PROJECT_ROOT/config/mappings/soc2_mappings.json" "$TEMP_DIR/config/mappings/"
cp "$PROJECT_ROOT/config/mappings/nist800_53_mappings.json" "$TEMP_DIR/config/mappings/"

# Copy the mapper modules
echo "Copying mapper modules..."
cp "$PROJECT_ROOT/src/mappers/__init__.py" "$TEMP_DIR/mappers/"
cp "$PROJECT_ROOT/src/mappers/soc2_mapper.py" "$TEMP_DIR/mappers/"
cp "$PROJECT_ROOT/src/mappers/nist_mapper.py" "$TEMP_DIR/mappers/"

# Copy utility files
echo "Copying utility files..."
cp "$PROJECT_ROOT/src/utils.py" "$TEMP_DIR/"
cp "$PROJECT_ROOT/src/soc2_mapper.py" "$TEMP_DIR/"  # For backward compatibility

# Copy and modify framework_mapper.py
echo "Copying framework mapper..."
cat "$PROJECT_ROOT/src/framework_mapper.py" | sed 's/from src\./from /g' > "$TEMP_DIR/framework_mapper.py"

# Copy and modify mapper_factory.py
echo "Copying mapper factory..."
cat "$PROJECT_ROOT/src/mapper_factory.py" | sed 's/from src\./from /g' | sed 's/from \.mappers/from mappers/g' > "$TEMP_DIR/mapper_factory.py"

# Create a fixed app.py for Lambda
echo "Creating application file..."
cat > "$TEMP_DIR/app.py" << 'EOL'
"""AWS SecurityHub Compliance Analyzer with multi-framework support."""

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

# Import for backward compatibility
from soc2_mapper import SOC2Mapper  

# Import new mapper factory system for multi-framework support
from framework_mapper import FrameworkMapper
from mapper_factory import MapperFactory, load_frameworks
from utils import format_datetime, get_resource_id

# Configure logging for both Lambda and CLI environments
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_findings(hours, framework_id=None):
    """
    Retrieve security findings from AWS SecurityHub for a specified time period.
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


def lambda_handler(event, context):
    """
    Main AWS Lambda function entry point for the SecurityHub Compliance Analyzer.
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
EOL

# Create requirements file with all dependencies
cat > "$TEMP_DIR/requirements.txt" << 'EOL'
boto3>=1.28.0
EOL

# Change to temp directory and create ZIP file
cd "$TEMP_DIR"
echo "Creating ZIP file..."
zip -r "$ZIP_FILE" .

# Upload to S3
echo "Uploading to S3..."
aws s3 cp "$ZIP_FILE" "s3://$S3_BUCKET/$ZIP_FILE" --profile "$PROFILE"

# Update Lambda function
echo "Updating Lambda function..."
aws lambda update-function-code \
  --function-name "$FUNCTION_NAME" \
  --s3-bucket "$S3_BUCKET" \
  --s3-key "$ZIP_FILE" \
  --profile "$PROFILE"

# Update Lambda configuration to ensure adequate resources
echo "Updating Lambda configuration..."
aws lambda update-function-configuration \
  --function-name "$FUNCTION_NAME" \
  --handler "app.lambda_handler" \
  --memory-size 2048 \
  --timeout 300 \
  --environment "Variables={SENDER_EMAIL=alexanderjyawn@gmail.com,RECIPIENT_EMAIL=alexanderjyawn@gmail.com,DEFAULT_FRAMEWORK=all,BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0}" \
  --profile "$PROFILE"

# Clean up
cd "$PROJECT_ROOT"
rm -rf "$TEMP_DIR"
echo "Temporary directory removed."

echo "Lambda function update completed."