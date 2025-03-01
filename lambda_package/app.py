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


def get_nist_control_status():
    """
    Retrieve NIST 800-53 control status directly from SecurityHub.
    
    This function:
    1. Identifies the NIST 800-53 standard in enabled standards
    2. Retrieves all control details for the standard
    3. Collects status information for each control
    
    Returns:
        dict: Dictionary containing control details with their status
              Empty if NIST 800-53 standard not found or if an error occurs
    """
    try:
        securityhub = boto3.client("securityhub")
        
        # Step 1: Get list of enabled standards
        logger.info("Getting list of enabled Security Hub standards")
        standards_response = securityhub.get_enabled_standards()
        
        # Find NIST 800-53 standard
        nist_standard = None
        for standard in standards_response.get("StandardsSubscriptions", []):
            if "nist" in standard.get("StandardsArn", "").lower() and "800-53" in standard.get("StandardsArn", ""):
                nist_standard = standard
                logger.info(f"Found NIST 800-53 standard: {nist_standard['StandardsArn']}")
                break
                
        if not nist_standard:
            logger.warning("NIST 800-53 standard not found in enabled standards")
            return {}
            
        # Step 2: Get control details for the NIST standard
        logger.info(f"Getting controls for standard: {nist_standard['StandardsSubscriptionArn']}")
        
        # Initialize for pagination
        next_token = None
        all_controls = {}
        
        # Paginate through all controls
        while True:
            if next_token:
                controls_response = securityhub.describe_standards_controls(
                    StandardsSubscriptionArn=nist_standard['StandardsSubscriptionArn'],
                    NextToken=next_token
                )
            else:
                controls_response = securityhub.describe_standards_controls(
                    StandardsSubscriptionArn=nist_standard['StandardsSubscriptionArn']
                )
                
            # Process controls in this batch
            for control in controls_response.get("Controls", []):
                control_id = control.get("ControlId", "")
                # Extract just the control identifier (e.g., "AC-1" from "NIST.800-53.r5-AC-1")
                # This assumes a specific format - adjust the regex as needed
                import re
                match = re.search(r"([A-Z]+-\d+(?:\.\d+)?)", control_id)
                if match:
                    short_id = match.group(1)
                else:
                    short_id = control_id
                    
                # Map SecurityHub status to our simplified values
                status = control.get("ControlStatus", "UNKNOWN").upper()
                if status == "ENABLED":
                    # For enabled controls, we need to check if they're passing
                    if control.get("ComplianceStatus", "").upper() == "PASSED":
                        status = "PASSED"
                    else:
                        status = "FAILED"
                elif status == "DISABLED":
                    status = "NOT_APPLICABLE"
                
                # Store control with its status
                all_controls[short_id] = {
                    "id": control_id,
                    "title": control.get("Title", ""),
                    "description": control.get("Description", ""),
                    "status": status,
                    "severity": control.get("SeverityRating", "MEDIUM"),
                    "disabled": control.get("DisabledReason", "") != "",
                    "related_requirements": control.get("RelatedRequirements", [])
                }
            
            # Check if there are more controls
            next_token = controls_response.get("NextToken")
            if not next_token:
                break
                
        logger.info(f"Retrieved {len(all_controls)} NIST 800-53 controls")
        return all_controls
        
    except Exception as e:
        logger.error(f"Error retrieving NIST 800-53 control status: {str(e)}")
        return {}

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


def generate_nist_cato_report():
    """
    Generate a comprehensive cATO status report for NIST 800-53 controls.
    
    This function:
    1. Retrieves NIST 800-53 control status directly from SecurityHub
    2. Aggregates controls by family (AC, CM, IA, etc.)
    3. Calculates compliance statistics and cATO readiness metrics
    4. Creates a detailed report suitable for cATO reporting
    
    Returns:
        tuple: (report_text, statistics_dict, control_families_dict)
            - report_text: Markdown formatted report text
            - statistics_dict: Statistics including counts by status
            - control_families_dict: Controls grouped by family with status counts
    """
    # Get control status data
    controls = get_nist_control_status()
    
    if not controls:
        return "No NIST 800-53 controls found or enabled.", {}, {}
    
    # Initialize statistics
    stats = {
        "total": len(controls),
        "passed": 0,
        "failed": 0,
        "unknown": 0,
        "not_applicable": 0,
        "warning": 0,
        "disabled": 0,
        # Severity counts
        "critical": 0, 
        "high": 0,
        "medium": 0,
        "low": 0
    }
    
    # Initialize control families dictionary
    control_families = {}
    
    # Process each control
    for control_id, control in controls.items():
        # Update status counts
        status = control.get("status", "UNKNOWN").upper()
        if status == "PASSED":
            stats["passed"] += 1
        elif status == "FAILED":
            stats["failed"] += 1
        elif status == "WARNING":
            stats["warning"] += 1
        elif status == "NOT_APPLICABLE":
            stats["not_applicable"] += 1
        else:
            stats["unknown"] += 1
            
        # Count disabled controls
        if control.get("disabled", False):
            stats["disabled"] += 1
            
        # Update severity counts
        severity = control.get("severity", "MEDIUM").upper()
        if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            stats[severity.lower()] += 1
            
        # Group by control family (e.g., AC-1 belongs to AC family)
        # Try to extract the control family from the ID
        if '-' in control_id:
            family = control_id.split('-')[0]
        elif '.' in control_id:
            # Handle AWS specific control IDs like ACM.1
            family = control_id.split('.')[0]
        else:
            family = "OTHER"
            
        # If the family is numeric or doesn't look like a control family, put it in OTHER
        if family.isdigit() or len(family) < 2:
            family = "OTHER"
        
        if family not in control_families:
            control_families[family] = {
                "name": family,
                "controls": [],
                "passed": 0,
                "failed": 0,
                "total": 0,
                "compliance_percentage": 0
            }
            
        # Add control to its family
        control_families[family]["controls"].append(control)
        control_families[family]["total"] += 1
        
        if status == "PASSED":
            control_families[family]["passed"] += 1
        elif status == "FAILED":
            control_families[family]["failed"] += 1
            
    # Calculate compliance percentage for each family
    for family in control_families.values():
        if family["total"] > 0:
            family["compliance_percentage"] = (family["passed"] / family["total"]) * 100
            
    # Calculate overall compliance percentage
    if stats["total"] > 0:
        stats["compliance_percentage"] = ((stats["passed"] + stats["not_applicable"]) / stats["total"]) * 100
    else:
        stats["compliance_percentage"] = 0
        
    # Sort families by compliance percentage (ascending, so less compliant families are first)
    sorted_families = dict(sorted(
        control_families.items(),
        key=lambda x: x[1]["compliance_percentage"]
    ))
    
    # Generate the cATO status report text
    report = f"""# NIST 800-53 Control Status for cATO

## Executive Summary

This report provides the current implementation status of NIST 800-53 controls for Continuous Authorization to Operate (cATO).

* **Total Controls**: {stats['total']}
* **Passed**: {stats['passed']} ({stats['compliance_percentage']:.1f}%)
* **Failed**: {stats['failed']}
* **Unknown/Not Checked**: {stats['unknown']}
* **Not Applicable**: {stats['not_applicable']}

## Control Family Status

"""

    # Add control family summaries
    for family_id, family in sorted_families.items():
        report += f"### {family_id} Family\n\n"
        report += f"* **Controls**: {family['total']}\n"
        report += f"* **Compliance**: {family['compliance_percentage']:.1f}%\n"
        report += f"* **Passed**: {family['passed']}\n"
        report += f"* **Failed**: {family['failed']}\n\n"
        
    # Add cATO specific recommendations based on compliance state
    report += "## cATO Recommendations\n\n"
    
    if stats["compliance_percentage"] < 50:
        report += """**Initial cATO Implementation Phase**

Your environment is in the early stages of cATO readiness. Focus on:

1. Prioritize implementation of critical control families (AC, IA, SC)
2. Establish a System Security Plan (SSP) with detailed POA&M
3. Implement monitoring for critical controls first
"""
    elif stats["compliance_percentage"] < 80:
        report += """**Intermediate cATO Implementation Phase**

Your environment is making good progress toward cATO. Focus on:

1. Address failed controls in high-priority families
2. Implement automation for continuous monitoring
3. Document evidence collection processes
4. Begin developing authorization packages
"""
    else:
        report += """**Advanced cATO Implementation Phase**

Your environment is well positioned for cATO. Focus on:

1. Complete automation of all control assessments
2. Implement deviation detection and response
3. Document successful cATO processes for auditors
4. Verify integration with agency risk management systems
"""
    
    return report, stats, control_families


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

    For NIST 800-53 reports, it also includes ASCII art charts visualizing the findings
    distribution by severity and control family to support cATO reporting.

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

        # For NIST 800-53, add a cATO report header
        if framework_id == "NIST800-53":
            writer.writerow(["Test Agency Continuous Authorization to Operate (cATO) Compliance Report"])
            writer.writerow([f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC"])
            writer.writerow([])
        else:
            writer.writerow([f"AWS SecurityHub {framework_name} Compliance Report"])
            writer.writerow([f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC"])
            writer.writerow([])

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
        control_family_count = {}  # Track findings by control family
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}  # Track findings by severity
        
        for finding in framework_findings:
            # Map the finding to framework controls
            mapped_finding = mapper.map_finding(finding)

            # Format the controls as a comma-separated string
            controls = mapped_finding.get(control_attr, "Unknown")
            if isinstance(controls, list):
                controls = ", ".join(controls)
            
            # Extract severity for counting
            severity = finding.get("Severity", {}).get("Label", "INFORMATIONAL")
            if severity in severity_count:
                severity_count[severity] += 1
            
            # Extract control family for NIST tracking (uses first two letters of control ID)
            if framework_id == "NIST800-53" and isinstance(mapped_finding.get(control_attr), list):
                for control in mapped_finding.get(control_attr, []):
                    if "-" in control:
                        # Skip if not a standard control format
                        continue
                    family = control[:2] if len(control) >= 2 else "Unknown"
                    control_family_count[family] = control_family_count.get(family, 0) + 1

            # Write the finding details as a row in the CSV
            writer.writerow(
                [
                    finding.get("Title", ""),
                    severity,
                    ", ".join(finding.get("Types", ["Unknown"])),
                    controls,
                    get_resource_id(finding),
                    finding.get("AwsAccountId", ""),
                    finding.get("Region", ""),
                    finding.get("Description", ""),
                ]
            )
        
        # For NIST 800-53, add chart visualizations to help with cATO reporting
        if framework_id == "NIST800-53":
            writer.writerow([])
            writer.writerow(["FINDINGS DISTRIBUTION CHARTS FOR cATO REPORTING"])
            writer.writerow([])
            
            # Add severity distribution chart
            writer.writerow(["Findings by Severity Level (cATO Risk Assessment)"])
            max_count = max(severity_count.values()) if severity_count.values() else 0
            if max_count > 0:
                for severity, count in severity_count.items():
                    if count > 0:  # Only show severities with findings
                        bar_length = int(40 * count / max_count)
                        bar = "█" * bar_length
                        writer.writerow([f"{severity}: {count} {bar}"])
            else:
                writer.writerow(["No findings to display"])
            
            writer.writerow([])
            
            # Add control family distribution chart
            if control_family_count:
                writer.writerow(["Findings by NIST 800-53 Control Family (cATO Control Coverage)"])
                max_count = max(control_family_count.values()) if control_family_count.values() else 0
                if max_count > 0:
                    # Sort by count (descending)
                    sorted_families = sorted(control_family_count.items(), key=lambda x: x[1], reverse=True)
                    for family, count in sorted_families:
                        bar_length = int(40 * count / max_count)
                        bar = "█" * bar_length
                        writer.writerow([f"{family}: {count} {bar}"])
                else:
                    writer.writerow(["No control family data to display"])
            
            writer.writerow([])
            writer.writerow(["cATO Implementation Recommendations:"])
            writer.writerow(["1. Address critical findings immediately to maintain ATO status"])
            writer.writerow(["2. Prioritize high-severity findings within the next 7 days"])
            writer.writerow(["3. Update POA&M documentation with the findings in this report"])
            writer.writerow(["4. Schedule automated controls testing based on this assessment"])
        
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
    nist_control_families=None,
):
    """
    Send a professional email report with findings analysis and CSV attachments.

    Creates and sends a formatted HTML email containing:
    - Summary statistics of security findings by severity for each framework
    - Detailed AI-generated analysis with compliance impact assessment
    - CSV attachments with all findings mapped to respective framework controls

    The email uses professional formatting with security-focused color coding
    and styling to make the report easy to read and interpret. For NIST 800-53
    reports, it includes specialized cATO content with control family breakdowns.

    Args:
        recipient_email (str): Email address to send the report to
        findings (dict or list): Findings grouped by framework ID, or list if single framework
        analyses (dict): Analysis text for each framework (from analyze_findings)
        stats (dict): Statistics dictionary with counts by severity for each framework
        mappers (dict or FrameworkMapper): Dictionary of mappers by framework ID, or single mapper
        selected_framework (str, optional): Only include this framework in the email report
        include_combined (bool, optional): Whether to include combined analysis in the report
        nist_control_families (dict, optional): NIST 800-53 control families with status for enhanced cATO reporting

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

    # Use the cATO-specific subject line for NIST 800-53 reports
    if len(frameworks_to_include) == 1 and frameworks_to_include[0] == "NIST800-53":
        subject = f'Test Agency Weekly cATO Update - {datetime.now().strftime("%Y-%m-%d")}'
    elif len(frameworks_to_include) == 1:
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
        # Process markdown formatting for better display
        formatted_combined_analysis = analyses["combined"]
        formatted_combined_analysis = formatted_combined_analysis.replace('# ', '<h1>').replace('## ', '<h2>').replace('### ', '<h3>')
        formatted_combined_analysis = formatted_combined_analysis.replace('\n\n', '</p><p>')
        
        # Handle bold and italic formatting
        formatted_combined_analysis = formatted_combined_analysis.replace('**', '<strong>')
        formatted_combined_analysis = formatted_combined_analysis.replace('*', '<em>')
        
        # Make sure all tags are properly closed
        for tag in ['h1', 'h2', 'h3', 'strong', 'em']:
            count = formatted_combined_analysis.count(f'<{tag}>')
            if count > formatted_combined_analysis.count(f'</{tag}>'):
                formatted_combined_analysis += f'</{tag}>'
        
        framework_sections.append(
            f"""
        <div id="combined-analysis">
            <h2>Cross-Framework Analysis</h2>
            <div class="analysis-content">
                <p>{formatted_combined_analysis}</p>
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
        
        # Process markdown formatting for better display
        formatted_analysis = framework_analysis
        formatted_analysis = formatted_analysis.replace('# ', '<h1>').replace('## ', '<h2>').replace('### ', '<h3>')
        formatted_analysis = formatted_analysis.replace('\n\n', '</p><p>')
        
        # Handle bold and italic formatting
        formatted_analysis = formatted_analysis.replace('**', '<strong>')
        formatted_analysis = formatted_analysis.replace('*', '<em>')
        
        # Make sure all tags are properly closed
        for tag in ['h1', 'h2', 'h3', 'strong', 'em', 'p']:
            count = formatted_analysis.count(f'<{tag}>')
            if count > formatted_analysis.count(f'</{tag}>'):
                formatted_analysis += f'</{tag}>'

        # Create specialized content for NIST 800-53 with cATO focus
        if framework_id == "NIST800-53":
            # Custom cATO-focused content for NIST 800-53 with enhanced control family information
            # Determine if we have the enhanced cATO stats
            has_cato_stats = 'compliance_percentage' in framework_stats
            
            # Set the cATO readiness percentage
            if has_cato_stats:
                cato_readiness = framework_stats['compliance_percentage']
            else:
                # Fallback to the original calculation based on findings
                cato_readiness = max(5, min(95, 100 - (framework_stats['critical'] * 15 + framework_stats['high'] * 10 + framework_stats['medium'] * 5) / max(1, framework_stats['total'])))
            
            # Create control family chart if we have the data
            control_family_html = ""
            if nist_control_families:
                control_family_html = """
                <div class="cato-section">
                    <h3>NIST 800-53 Control Family Status</h3>
                    <p>This breakdown shows compliance status by control family:</p>
                    <table class="control-family-table">
                        <tr>
                            <th>Family</th>
                            <th>Controls</th>
                            <th>Compliance</th>
                            <th>Status</th>
                        </tr>
                """
                
                # Sort control families by compliance percentage (ascending)
                sorted_families = sorted(
                    nist_control_families.items(),
                    key=lambda x: x[1]["compliance_percentage"] if "compliance_percentage" in x[1] else 0
                )
                
                # Add rows for each control family
                for family_id, family in sorted_families:
                    if family.get("total", 0) > 0:
                        compliance = family.get("compliance_percentage", 0)
                        color_class = "critical"
                        if compliance >= 80:
                            color_class = "low"
                        elif compliance >= 50:
                            color_class = "medium"
                        elif compliance >= 30:
                            color_class = "high"
                            
                        control_family_html += f"""
                        <tr>
                            <td><strong>{family_id}</strong></td>
                            <td>{family.get("total", 0)}</td>
                            <td class="{color_class}">{compliance:.1f}%</td>
                            <td>
                                <div class="mini-meter">
                                    <span style="width: {compliance}%"></span>
                                </div>
                            </td>
                        </tr>
                        """
                
                control_family_html += """
                    </table>
                    <p class="meter-label">Control families sorted by compliance level (lowest first)</p>
                </div>
                """
                
            # Create main NIST section
            framework_sections.append(
                f"""
            <div id="{framework_id}-analysis" class="framework-section">
                <h2>Test Agency Continuous Authorization to Operate (cATO) Status Update</h2>
                
                <div class="summary">
                    <h3>NIST 800-53 Compliance Summary</h3>
                    {"<p><strong>Controls:</strong> " + str(framework_stats.get('total', 0)) + "</p>" if has_cato_stats else ""}
                    {"<p><strong class='passed'>Passed:</strong> " + str(framework_stats.get('passed', 0)) + "</p>" if has_cato_stats else ""}
                    {"<p><strong class='failed'>Failed:</strong> " + str(framework_stats.get('failed', 0)) + "</p>" if has_cato_stats else ""}
                    {"<p><strong>Not Applicable:</strong> " + str(framework_stats.get('not_applicable', 0)) + "</p>" if has_cato_stats else ""}
                    {"<p><strong>Unknown:</strong> " + str(framework_stats.get('unknown', 0)) + "</p>" if has_cato_stats else ""}
                    {"<hr>" if has_cato_stats else ""}
                    <p><strong>Security Findings:</strong> {framework_stats['total']}</p>
                    <p><strong class="critical">Critical:</strong> {framework_stats['critical']}</p>
                    <p><strong class="high">High:</strong> {framework_stats['high']}</p>
                    <p><strong class="medium">Medium:</strong> {framework_stats['medium']}</p>
                    <p><strong class="low">Low:</strong> {framework_stats['low']}</p>
                </div>
                
                <div class="cato-section">
                    <h3>Current Implementation Status</h3>
                    <p>This section provides a status update on the Test Agency's continuous Authorization to Operate (cATO) implementation based on NIST 800-53 control compliance status.</p>
                    <div class="meter">
                        <span style="width: {cato_readiness}%">cATO Readiness</span>
                    </div>
                    <p class="meter-label">Current cATO implementation progress: {cato_readiness:.1f}%</p>
                </div>
                
                {control_family_html}

                <div class="analysis-content">
                    <p>{formatted_analysis}</p>
                </div>
                
                <div class="cato-section">
                    <h3>Recommended Next Steps for cATO Maturity</h3>
                    <ul>
                        {f"<li class='critical-action'>Address {framework_stats['critical']} critical findings immediately to maintain cATO compliance</li>" if framework_stats['critical'] > 0 else ""}
                        {f"<li class='high-action'>Remediate high severity findings within 7 days to improve cATO posture</li>" if framework_stats['high'] > 0 else ""}
                        {"<li>Focus on improving compliance in low-performing control families</li>"}
                        {"<li>Implement continuous monitoring for AC and CM control families</li>"}
                        {"<li>Strengthen automation of security assessments</li>"}
                        {"<li>Update System Security Plan (SSP) to reflect current controls implementation</li>"}
                    </ul>
                </div>
                
                <div class="cato-section">
                    <h3>Immediate Actions Required</h3>
                    <p>To support ongoing cATO compliance, please prioritize the following actions:</p>
                    <ol>
                        {f"<li>Resolve all <strong class='critical'>{framework_stats['critical']}</strong> critical findings within 48 hours</li>" if framework_stats['critical'] > 0 else ""}
                        {f"<li>Address all <strong class='high'>{framework_stats['high']}</strong> high severity findings this week</li>" if framework_stats['high'] > 0 else ""}
                        {"<li>Review and update the Plan of Action & Milestones (POA&M) document</li>"}
                        {"<li>Schedule cATO implementation review meeting with the security team</li>"}
                        {"<li>Run a verification assessment for the most critical control families</li>"}
                    </ol>
                </div>
            </div>
            <hr>
            """
            )
        else:
            # Standard formatting for non-NIST frameworks
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
                    <p>{formatted_analysis}</p>
                </div>
            </div>
            <hr>
            """
            )

    # Create HTML body with professional styling
    html_content = f"""<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; color: #333333; }}
        h1, h2, h3 {{ color: #232f3e; }}
        .summary {{ background-color: #f8f8f8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .critical {{ color: #d13212; }}
        .high {{ color: #ff9900; }}
        .medium {{ color: #d9b43c; }}
        .low {{ color: #6b6b6b; }}
        .passed {{ color: #2bc253; }}
        .failed {{ color: #d13212; }}
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
        p {{ line-height: 1.5; margin-bottom: 1em; }}
        a {{ color: #0073bb; }}
        ul, ol {{ margin-bottom: 1em; padding-left: 20px; }}
        li {{ margin-bottom: 0.5em; }}
        
        /* cATO specific styling */
        .cato-section {{
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            border-left: 4px solid #0073bb;
        }}
        .critical-action {{
            color: #d13212;
            font-weight: bold;
        }}
        .high-action {{
            color: #ff9900;
            font-weight: bold;
        }}
        
        /* Control family table styling */
        .control-family-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        .control-family-table th {{
            background-color: #e0e0e0;
            padding: 8px;
            text-align: left;
            font-weight: bold;
        }}
        .control-family-table td {{
            padding: 8px;
            border-bottom: 1px solid #ddd;
        }}
        .control-family-table tr:hover {{
            background-color: #f9f9f9;
        }}
        
        /* Progress meters */
        .meter {{ 
            height: 20px;
            position: relative;
            background: #f3f3f3;
            border-radius: 25px;
            padding: 5px;
            box-shadow: inset 0 -1px 1px rgba(255,255,255,0.3);
            margin: 15px 0;
        }}
        .meter > span {{
            display: block;
            height: 100%;
            border-top-right-radius: 8px;
            border-bottom-right-radius: 8px;
            border-top-left-radius: 20px;
            border-bottom-left-radius: 20px;
            background-color: #2bc253;
            background-image: linear-gradient(
                center bottom,
                rgb(43,194,83) 37%,
                rgb(84,240,84) 69%
            );
            box-shadow: 
                inset 0 2px 9px  rgba(255,255,255,0.3),
                inset 0 -2px 6px rgba(0,0,0,0.4);
            position: relative;
            overflow: hidden;
            text-align: center;
            color: white;
            font-weight: bold;
            text-shadow: 1px 1px 1px rgba(0,0,0,0.5);
            line-height: 20px;
        }}
        .meter-label {{
            font-size: 0.8em;
            color: #666;
            text-align: center;
            margin-top: 5px;
        }}
        
        /* Mini meters for control family table */
        .mini-meter {{
            height: 12px;
            position: relative;
            background: #f3f3f3;
            border-radius: 10px;
            width: 100%;
            box-shadow: inset 0 -1px 1px rgba(255,255,255,0.3);
        }}
        .mini-meter > span {{
            display: block;
            height: 100%;
            border-radius: 10px;
            background-color: #2bc253;
            background-image: linear-gradient(
                center bottom,
                rgb(43,194,83) 37%,
                rgb(84,240,84) 69%
            );
            box-shadow: inset 0 2px 9px rgba(255,255,255,0.3);
            position: relative;
            overflow: hidden;
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
</html>"""

    # Attach the HTML part to the email
    html_part = MIMEText(html_content, "html", "utf-8")
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
    html_content = f"""<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; color: #333333; }}
        h1, h2 {{ color: #232f3e; }}
        .box {{ background-color: #f8f8f8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .framework-list {{ background-color: #f0f7ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        p {{ line-height: 1.5; margin-bottom: 1em; }}
        a {{ color: #0073bb; }}
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
</html>"""

    # Attach the HTML content to the email
    html_part = MIMEText(html_content, "html", "utf-8")
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

    # Process different frameworks: standard approach for most, special handling for NIST 800-53
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

    # Special case for NIST 800-53 - we might have control status even with no findings
    if framework_id.upper() == "NIST800-53":
        logger.info("NIST 800-53 requested - proceeding with control status even if no findings")
        
        try:
            # Generate NIST 800-53 cATO report
            report_text, nist_stats, control_families = generate_nist_cato_report()
            
            # Add extra logging to debug
            logger.info(f"Generated NIST report with stats: {json.dumps(nist_stats)}")
            logger.info(f"Control families: {len(control_families)}")
            
            # Create special analysis for NIST 800-53
            analyses = {
                "NIST800-53": report_text
            }
            
            # Create stats dictionary in the format expected by the email function
            # Make sure we have default values for all required fields
            stats = {
                "NIST800-53": {
                    "total": nist_stats.get("total", 0),
                    "critical": nist_stats.get("critical", 0),
                    "high": nist_stats.get("high", 0),
                    "medium": nist_stats.get("medium", 0),
                    "low": nist_stats.get("low", 0),
                    # Add cATO specific stats
                    "passed": nist_stats.get("passed", 0),
                    "failed": nist_stats.get("failed", 0),
                    "unknown": nist_stats.get("unknown", 0),
                    "not_applicable": nist_stats.get("not_applicable", 0),
                    "compliance_percentage": nist_stats.get("compliance_percentage", 0)
                }
            }
        except Exception as e:
            logger.error(f"Error generating NIST cATO report: {str(e)}")
            # Create placeholder report and stats
            report_text = "Error generating NIST 800-53 control status report."
            analyses = {"NIST800-53": report_text}
            stats = {
                "NIST800-53": {
                    "total": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "passed": 0,
                    "failed": 0,
                    "unknown": 0,
                    "not_applicable": 0,
                    "compliance_percentage": 0
                }
            }
            control_families = {}
        
        # If no findings, create empty placeholder
        if not findings or not any(findings.values()):
            findings = {"NIST800-53": []}
        
        # Send email with control family data
        success = send_email(
            recipient_email,
            findings,
            analyses,
            stats,
            mappers,
            None,
            include_combined,
            nist_control_families=control_families
        )
        
        return {
            "statusCode": 200 if success else 500,
            "body": json.dumps(
                "NIST 800-53 control status report sent successfully" 
                if success 
                else "Failed to send NIST 800-53 control status report"
            ),
        }
    
    # For other frameworks, check if we have any findings to process
    elif not findings or not any(findings.values()):
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
    # Check if this is a NIST 800-53 report with control families
    if framework_id.upper() == "NIST800-53" and "NIST800-53_CONTROL_FAMILIES" in findings:
        # Extract control families and remove from findings to avoid confusion
        control_families = findings.pop("NIST800-53_CONTROL_FAMILIES")
        
        # Send email with enhanced NIST control data
        success = send_email(
            recipient_email,
            findings,
            analyses,
            stats,
            mappers,
            None,  # No need for selected_framework (it's already filtered)
            include_combined,
            nist_control_families=control_families  # Pass the control families for enhanced reporting
        )
    else:
        # Regular email without control families
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
