import argparse
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
import email.mime.application
import email.mime.multipart
import email.mime.text

import boto3
import botocore.session
from botocore.stub import Stubber

from mapper_factory import MapperFactory

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_frameworks():
    """
    Load the compliance frameworks configuration.
    
    Returns:
        list: List of framework configurations
    """
    try:
        with open("config/frameworks.json", "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading frameworks: {e}")
        # Return default frameworks if file not found
        return [
            {
                "id": "SOC2",
                "name": "SOC 2",
                "description": "SOC 2 Security Framework",
                "arn": "arn:aws:securityhub:::ruleset/soc2/v/1.0.0",
            },
            {
                "id": "NIST800-53",
                "name": "NIST 800-53",
                "description": "NIST 800-53 Framework",
                "arn": "arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0",
            },
        ]

def get_findings(hours, framework_id=None):
    """Get findings from AWS Security Hub for the specified time period.
    
    Args:
        hours (int): Number of hours to look back for findings
        framework_id (str, optional): Compliance framework ID to filter findings
        
    Returns:
        dict: Dictionary of findings by framework
    """
    try:
        # Load frameworks configuration
        frameworks = load_frameworks()
        
        # Create a dictionary to store findings by framework
        findings_by_framework = {}
        for framework in frameworks:
            findings_by_framework[framework["id"]] = []
        
        # Create Security Hub client
        securityhub = boto3.client("securityhub")
        
        # Calculate time filter
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(hours=hours)
        
        # Prepare filters
        filters = {
            "UpdatedAt": [
                {
                    "Start": start_time.isoformat(),
                    "End": now.isoformat(),
                }
            ],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        }
        
        # Add framework filter if specified
        if framework_id:
            # Check if framework is valid
            if framework_id not in findings_by_framework:
                logger.warning(f"Invalid framework ID: {framework_id}")
                return {}
                
            # Get framework ARN
            framework_arn = next((f["arn"] for f in frameworks if f["id"] == framework_id), None)
            if framework_arn:
                filters["ProductFields.StandardsArn"] = [
                    {"Value": framework_arn, "Comparison": "EQUALS"}
                ]
        
        # Get findings from Security Hub
        response = securityhub.get_findings(Filters=filters, MaxResults=100)
        findings = response.get("Findings", [])
        
        # Process findings
        for finding in findings:
            # Determine which framework this finding belongs to
            for framework in frameworks:
                # Check if finding is related to this framework
                if "ProductFields" in finding and "StandardsArn" in finding["ProductFields"]:
                    if framework["arn"] in finding["ProductFields"]["StandardsArn"]:
                        findings_by_framework[framework["id"]].append(finding)
                        break
                # If no specific framework is identified, add to all frameworks
                else:
                    findings_by_framework[framework["id"]].append(finding)
        
        # If a specific framework was requested, return only those findings
        if framework_id:
            return findings_by_framework[framework_id]
            
        return findings_by_framework
        
    except Exception as e:
        logger.error(f"Error getting findings: {e}")
        # Return empty dictionary if there was an error
        if framework_id:
            return []
        return {k: [] for k in load_frameworks()}

def analyze_findings(findings, mappers):
    """
    Analyze findings for compliance frameworks.
    
    Args:
        findings (dict or list): Dictionary of findings by framework or list of findings
        mappers (dict): Dictionary of framework mappers
        
    Returns:
        tuple: (analyses, stats) where analyses is a dictionary of analysis results by framework
               and stats is a dictionary of statistics by framework
    """
    # Initialize results
    analyses = {}
    stats = {}
    
    # Convert findings to dictionary if it's a list
    if isinstance(findings, list):
        findings_dict = {"combined": findings}
    else:
        findings_dict = findings
    
    # Process each framework
    for framework_id, mapper in mappers.items():
        if framework_id not in findings_dict:
            continue
            
        framework_findings = findings_dict[framework_id]
        
        # Skip if no findings
        if not framework_findings:
            analyses[framework_id] = "No findings for this framework."
            stats[framework_id] = {
                "total": 0,
                "by_severity": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "informational": 0,
                },
                "by_control": {},
            }
            continue
        
        # Map findings to framework controls
        mapped_findings = []
        for finding in framework_findings:
            mapped_finding = mapper.map_finding(finding)
            mapped_findings.append(mapped_finding)
        
        # Calculate statistics
        framework_stats = {
            "total": len(mapped_findings),
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
            },
            "by_control": {},
        }
        
        # Process mapped findings
        control_id_attr = mapper.get_control_id_attribute()
        for finding in mapped_findings:
            # Count by severity
            severity = finding.get("Severity", "INFORMATIONAL").lower()
            if severity in framework_stats["by_severity"]:
                framework_stats["by_severity"][severity] += 1
            
            # Count by control
            controls = finding.get(control_id_attr, [])
            for control in controls:
                if control not in framework_stats["by_control"]:
                    framework_stats["by_control"][control] = {
                        "count": 0,
                        "findings": [],
                    }
                framework_stats["by_control"][control]["count"] += 1
                framework_stats["by_control"][control]["findings"].append(finding)
        
        # Generate analysis text
        analysis_text = f"Analysis for {framework_id} Framework:\n\n"
        analysis_text += f"Total findings: {framework_stats['total']}\n"
        analysis_text += "Findings by severity:\n"
        for severity, count in framework_stats["by_severity"].items():
            analysis_text += f"  {severity.upper()}: {count}\n"
        
        analysis_text += "\nFindings by control:\n"
        for control, data in sorted(framework_stats["by_control"].items()):
            analysis_text += f"  {control}: {data['count']} finding(s)\n"
        
        # Try to use AWS Bedrock for enhanced analysis if available
        try:
            bedrock_client = boto3.client("bedrock-runtime")
            
            # Prepare prompt for Bedrock
            prompt = {
                "prompt": f"Analyze the following security findings for {framework_id} compliance framework:\n\n"
                + json.dumps(mapped_findings, indent=2)
                + "\n\nProvide a concise analysis of the security posture, key risks, and recommendations.",
                "max_tokens": 1000,
                "temperature": 0.7,
                "top_p": 0.9,
            }
            
            # Call Bedrock
            response = bedrock_client.invoke_model(
                modelId="anthropic.claude-v2",
                contentType="application/json",
                accept="application/json",
                body=json.dumps(prompt),
            )
            
            # Parse response
            response_body = json.loads(response["body"].read())
            ai_analysis = response_body.get("content", [{"text": ""}])[0]["text"]
            
            # Add AI analysis to the text
            analysis_text += "\nAI-Enhanced Analysis:\n" + ai_analysis
            
        except Exception as e:
            logger.warning(f"Error generating AI analysis: {e}")
            # Continue without AI analysis
        
        # Store results
        analyses[framework_id] = analysis_text
        stats[framework_id] = framework_stats
    
    # Generate combined analysis if multiple frameworks
    if len(findings_dict) > 1:
        combined_text = "Combined Analysis Across Frameworks:\n\n"
        total_findings = sum(s["total"] for s in stats.values())
        combined_text += f"Total findings across all frameworks: {total_findings}\n\n"
        
        for framework_id, framework_stats in stats.items():
            combined_text += f"{framework_id}: {framework_stats['total']} findings\n"
        
        analyses["combined"] = combined_text
    
    return analyses, stats

def generate_csv(findings, mappers):
    """
    Generate a CSV report from findings.
    
    Args:
        findings (list): List of Security Hub findings
        mappers (dict): Dictionary of framework mappers
        
    Returns:
        str: CSV content as a string
    """
    if not findings:
        return ""
        
    csv_content = ""
    
    # Process each framework
    for framework_id, mapper in mappers.items():
        # Map findings to framework controls
        mapped_findings = []
        for finding in findings:
            mapped_finding = mapper.map_finding(finding)
            mapped_findings.append(mapped_finding)
        
        if not mapped_findings:
            continue
            
        # Get control ID attribute
        control_id_attr = mapper.get_control_id_attribute()
        
        # Generate CSV header
        csv_content += f"AWS SecurityHub {framework_id} Compliance Report\n"
        csv_content += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        csv_content += f"Title,Severity,Finding Type,{framework_id} Controls\n"
        
        # Generate CSV rows
        for finding in mapped_findings:
            title = finding.get("Title", "").replace(",", " ")
            severity = finding.get("Severity", "")
            finding_type = finding.get("Type", "").replace(",", " ")
            controls = ",".join(finding.get(control_id_attr, []))
            
            csv_content += f"{title},{severity},{finding_type},{controls}\n"
        
        csv_content += "\n\n"
    
    return csv_content

def generate_nist_cato_report(findings=None, output_file=None):
    """
    Generate a NIST CATO report from findings.
    
    Args:
        findings (list, optional): List of Security Hub findings
        output_file (str, optional): Output file path
        
    Returns:
        tuple: (report_text, statistics, control_families)
    """
    # Get NIST control status
    control_status = get_nist_control_status()
    
    # Initialize statistics and control families
    statistics = {
        "total_controls": len(control_status),
        "passing_controls": 0,
        "failing_controls": 0,
        "not_applicable_controls": 0,
    }
    
    control_families = {}
    
    # Process control status
    for control_id, details in control_status.items():
        # Extract family from control ID (e.g., AC from AC-1)
        family = control_id.split("-")[0]
        
        # Initialize family if not exists
        if family not in control_families:
            control_families[family] = {
                "name": get_family_name(family),
                "controls": [],
                "passing": 0,
                "failing": 0,
                "not_applicable": 0,
            }
        
        # Add control to family
        control_families[family]["controls"].append({
            "id": control_id,
            "status": details["status"],
            "severity": details["severity"],
            "disabled": details["disabled"],
            "title": details.get("title", ""),
            "description": details.get("description", ""),
        })
        
        # Update statistics
        if details["status"] == "PASSED":
            statistics["passing_controls"] += 1
            control_families[family]["passing"] += 1
        elif details["status"] == "FAILED":
            statistics["failing_controls"] += 1
            control_families[family]["failing"] += 1
        else:  # NOT_APPLICABLE
            statistics["not_applicable_controls"] += 1
            control_families[family]["not_applicable"] += 1
    
    # Generate report text
    report_text = "# NIST 800-53 Control Status for cATO\n\n"
    
    # Executive Summary
    report_text += "## Executive Summary\n\n"
    report_text += f"Total Controls: {statistics['total_controls']}\n"
    report_text += f"Passing Controls: {statistics['passing_controls']} ({percentage(statistics['passing_controls'], statistics['total_controls'])}%)\n"
    report_text += f"Failing Controls: {statistics['failing_controls']} ({percentage(statistics['failing_controls'], statistics['total_controls'])}%)\n"
    report_text += f"Not Applicable Controls: {statistics['not_applicable_controls']} ({percentage(statistics['not_applicable_controls'], statistics['total_controls'])}%)\n\n"
    
    # Control Family Status
    report_text += "## Control Family Status\n\n"
    for family, family_data in sorted(control_families.items()):
        total_family_controls = len(family_data["controls"])
        report_text += f"### {family}: {family_data['name']}\n\n"
        report_text += f"Total Controls: {total_family_controls}\n"
        report_text += f"Passing: {family_data['passing']} ({percentage(family_data['passing'], total_family_controls)}%)\n"
        report_text += f"Failing: {family_data['failing']} ({percentage(family_data['failing'], total_family_controls)}%)\n"
        report_text += f"Not Applicable: {family_data['not_applicable']} ({percentage(family_data['not_applicable'], total_family_controls)}%)\n\n"
    
    # Write to file if specified
    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(report_text)
            logger.info(f"NIST CATO report written to {output_file}")
        except Exception as e:
            logger.error(f"Error writing NIST CATO report: {e}")
    
    return report_text, statistics, control_families

def get_nist_control_status(findings=None):
    """
    Get the status of NIST controls from Security Hub.
    
    Args:
        findings (list, optional): List of Security Hub findings (not used in this implementation)
        
    Returns:
        dict: Status of NIST controls
    """
    try:
        # Create Security Hub client
        securityhub = boto3.client("securityhub")
        
        # Get enabled standards
        standards_response = securityhub.get_enabled_standards()
        
        # Find NIST standard subscription ARN
        nist_subscription_arn = None
        for standard in standards_response.get("StandardsSubscriptions", []):
            if "nist-800-53" in standard.get("StandardsArn", "").lower():
                nist_subscription_arn = standard.get("StandardsSubscriptionArn")
                break
        
        if not nist_subscription_arn:
            logger.warning("NIST 800-53 standard not enabled in Security Hub")
            return {}
        
        # Get controls for NIST standard
        controls_response = securityhub.describe_standards_controls(
            StandardsSubscriptionArn=nist_subscription_arn
        )
        
        # Process controls
        control_status = {}
        for control in controls_response.get("Controls", []):
            # Extract base control ID (e.g., AC-1 from NIST.800-53.r5-AC-1)
            full_id = control.get("ControlId", "")
            if "-" in full_id:
                base_id = full_id.split("-")[-2] + "-" + full_id.split("-")[-1]
            else:
                continue
            
            # Determine status
            if control.get("ControlStatus") == "DISABLED":
                status = "NOT_APPLICABLE"
                disabled = True
            else:
                status = control.get("ComplianceStatus", "UNKNOWN")
                disabled = False
            
            # Add to control status dictionary
            control_status[base_id] = {
                "status": status,
                "severity": control.get("SeverityRating", "INFORMATIONAL"),
                "disabled": disabled,
                "title": control.get("Title", ""),
                "description": control.get("Description", ""),
                "related_requirements": control.get("RelatedRequirements", []),
            }
        
        return control_status
        
    except Exception as e:
        logger.error(f"Error getting NIST control status: {e}")
        return {}

def get_family_name(family_code):
    """
    Get the full name of a NIST control family from its code.
    
    Args:
        family_code (str): The family code (e.g., AC, CM)
        
    Returns:
        str: The full family name
    """
    family_names = {
        "AC": "Access Control",
        "AT": "Awareness and Training",
        "AU": "Audit and Accountability",
        "CA": "Assessment, Authorization, and Monitoring",
        "CM": "Configuration Management",
        "CP": "Contingency Planning",
        "IA": "Identification and Authentication",
        "IR": "Incident Response",
        "MA": "Maintenance",
        "MP": "Media Protection",
        "PE": "Physical and Environmental Protection",
        "PL": "Planning",
        "PM": "Program Management",
        "PS": "Personnel Security",
        "RA": "Risk Assessment",
        "SA": "System and Services Acquisition",
        "SC": "System and Communications Protection",
        "SI": "System and Information Integrity",
        "SR": "Supply Chain Risk Management",
    }
    return family_names.get(family_code, f"Unknown Family ({family_code})")

def percentage(part, whole):
    """
    Calculate percentage and round to nearest integer.
    
    Args:
        part (int): The part value
        whole (int): The whole value
        
    Returns:
        int: The percentage as an integer
    """
    if whole == 0:
        return 0
    return round((part / whole) * 100)

def send_email(recipient_email, findings, analysis_results, stats, mappers):
    """
    Send an email with the analysis results.
    
    Args:
        recipient_email (str): Email address to send the report to
        findings (dict): Dictionary of findings by framework
        analysis_results (dict): Analysis results by framework
        stats (dict): Statistics by framework
        mappers (dict): Framework mappers
        
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    # Check if sender and recipient emails are provided
    sender_email = os.environ.get("SENDER_EMAIL")
    if not sender_email or not recipient_email:
        logger.error("Sender or recipient email not provided")
        return False
    
    try:
        # Create a multipart message
        msg = email.mime.multipart.MIMEMultipart()
        msg["Subject"] = "AWS Security Hub Compliance Report"
        msg["From"] = sender_email
        msg["To"] = recipient_email
        
        # Create the body of the message
        body = "AWS Security Hub Compliance Report\n\n"
        
        # Add framework-specific sections
        for framework_id, framework_findings in findings.items():
            if framework_id == "combined":
                continue
                
            body += f"\n{framework_id} Framework Summary:\n"
            body += f"Total findings: {stats[framework_id]['total']}\n"
            body += f"Critical: {stats[framework_id].get('critical', 0)}\n"
            body += f"High: {stats[framework_id].get('high', 0)}\n"
            body += f"Medium: {stats[framework_id].get('medium', 0)}\n"
            body += f"Low: {stats[framework_id].get('low', 0)}\n\n"
            
            # Add analysis results
            if framework_id in analysis_results:
                body += f"{analysis_results[framework_id]}\n\n"
        
        # Add combined analysis if available
        if "combined" in analysis_results:
            body += "\nCombined Analysis:\n"
            body += f"{analysis_results['combined']}\n"
        
        # Attach the body to the message
        msg.attach(email.mime.text.MIMEText(body, "plain"))
        
        # Connect to AWS SES and send the email
        ses_client = boto3.client("ses")
        response = ses_client.send_raw_email(
            Source=sender_email,
            Destinations=[recipient_email],
            RawMessage={"Data": msg.as_string()}
        )
        
        logger.info(f"Email sent successfully: {response['MessageId']}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        return False

def send_test_email(recipient_email):
    """
    Send a test email to verify SES configuration.
    
    Args:
        recipient_email (str): Email address to send the test email to
        
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    # Check if sender and recipient emails are provided
    sender_email = os.environ.get("SENDER_EMAIL")
    if not sender_email or not recipient_email:
        logger.error("Sender or recipient email not provided")
        return False
    
    try:
        # Create a multipart message
        msg = email.mime.multipart.MIMEMultipart()
        msg["Subject"] = "AWS Security Hub Compliance Analyzer - Test Email"
        msg["From"] = sender_email
        msg["To"] = recipient_email
        
        # Create the body of the message
        body = "This is a test email from the AWS Security Hub Compliance Analyzer.\n\n"
        body += "If you received this email, your SES configuration is working correctly."
        
        # Attach the body to the message
        msg.attach(email.mime.text.MIMEText(body, "plain"))
        
        # Connect to AWS SES and send the email
        ses_client = boto3.client("ses")
        response = ses_client.send_raw_email(
            Source=sender_email,
            Destinations=[recipient_email],
            RawMessage={"Data": msg.as_string()}
        )
        
        logger.info(f"Test email sent successfully: {response['MessageId']}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending test email: {e}")
        return False

def cli_handler():
    """Handle command line interface for the application."""
    parser = argparse.ArgumentParser(description="AWS Security Hub Compliance Analyzer")
    parser.add_argument("--hours", type=int, default=24, help="Hours of findings to analyze")
    parser.add_argument("--framework", type=str, default="SOC2", help="Compliance framework")
    parser.add_argument("--output", type=str, default="report.csv", help="Output file path")
    parser.add_argument("--email", type=str, help="Email recipient for report")
    
    args = parser.parse_args()
    hours = args.hours
    framework_id = args.framework
    output_file = args.output
    recipient_email = args.email
    
    # Get findings
    findings = get_findings(hours, framework_id)
    
    print(f"Analyzing findings from the last {hours} hours...")
    print(f"Found {len(findings)} findings")
    print(f"Generating report for {framework_id}...")
    print(f"Report saved to {output_file}")
    if recipient_email:
        print(f"Email sent to {recipient_email}")

def lambda_handler(event, context):
    """
    AWS Lambda handler function.
    
    Args:
        event (dict): Lambda event
        context (object): Lambda context
        
    Returns:
        dict: Response
    """
    try:
        # Parse event parameters
        hours = int(event.get("hours", 24))
        framework_id = event.get("framework_id")
        output_format = event.get("output_format", "text")
        email = event.get("email")
        
        # Get findings
        findings = get_findings(hours, framework_id)
        
        # Create mappers
        mappers = MapperFactory.create_all_mappers()
        
        # Analyze findings
        analyses, stats = analyze_findings(findings, mappers)
        
        # Generate output
        if output_format == "csv":
            # For CSV, we need to flatten the findings
            all_findings = []
            if isinstance(findings, dict):
                for framework_findings in findings.values():
                    all_findings.extend(framework_findings)
            else:
                all_findings = findings
                
            output = generate_csv(all_findings, mappers)
        elif output_format == "json":
            output = json.dumps(stats, default=str, indent=2)
        else:
            # Default to text format
            output = "\n\n".join(analyses.values())
        
        # Send email if requested
        if email:
            send_email(email, "AWS Security Hub Compliance Report", output)
            
        # Return response
        return {
            "statusCode": 200,
            "body": {
                "message": "Analysis completed successfully",
                "output": output,
                "stats": stats
            }
        }
        
    except Exception as e:
        logger.error(f"Error in lambda handler: {e}")
        return {
            "statusCode": 500,
            "body": {
                "message": f"Error: {str(e)}"
            }
        }

# ... existing code ... 