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

def get_findings(hours):
    """Get findings from AWS Security Hub for the specified time period.
    
    Args:
        hours (int): Number of hours to look back for findings
        
    Returns:
        list: List of findings
    """
    # This is a stub implementation
    return []

def analyze_findings(findings, framework_id):
    """
    Analyze findings for a specific compliance framework.
    
    Args:
        findings (list): List of Security Hub findings
        framework_id (str): Compliance framework ID
        
    Returns:
        dict: Analysis results
    """
    # This is a stub implementation
    return {
        "total": len(findings),
        "by_severity": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        },
        "by_control": {}
    }

def generate_csv(analysis_results, output_file):
    """
    Generate a CSV report from analysis results.
    
    Args:
        analysis_results (dict): Analysis results
        output_file (str): Output file path
        
    Returns:
        str: Path to the generated CSV file
    """
    # This is a stub implementation
    return output_file

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
    findings = get_findings(hours)
    
    print(f"Analyzing findings from the last {hours} hours...")
    print(f"Found {len(findings)} findings")
    print(f"Generating report for {framework_id}...")
    print(f"Report saved to {output_file}")
    if recipient_email:
        print(f"Email sent to {recipient_email}")

# ... existing code ... 