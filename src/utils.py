import logging

# Configure logging
logger = logging.getLogger()


def format_datetime(dt):
    """Format a datetime object into ISO 8601 format used by SecurityHub API."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def get_resource_id(finding):
    """Extract the affected resource ID from a SecurityHub finding."""
    if "Resources" in finding and finding["Resources"]:
        return finding["Resources"][0].get("Id", "Unknown")
    return "Unknown"


def get_account_id(finding):
    """Extract the AWS account ID from a SecurityHub finding."""
    return finding.get("AwsAccountId", "Unknown")


def get_region(finding):
    """Extract the AWS region from a SecurityHub finding."""
    return finding.get("Region", "Unknown")


def truncate_text(text, max_length=200):
    """Truncate a text string to a specified maximum length with ellipsis."""
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."


def format_severity(severity):
    """Format a severity value for consistent display."""
    if isinstance(severity, dict):
        return severity.get("Label", "UNKNOWN")
    return severity or "UNKNOWN"


def group_by_severity(findings):
    """Group a list of findings by their severity level."""
    # Initialize results with all standard severity levels
    result = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFORMATIONAL": []}

    # Group each finding by its severity
    for finding in findings:
        severity = format_severity(finding.get("Severity"))
        if severity in result:
            result[severity].append(finding)
        else:
            # If severity level doesn't match standard levels, put in INFORMATIONAL
            result["INFORMATIONAL"].append(finding)

    return result


def group_by_control(findings, soc2_mapper):
    """Group a list of findings by their associated SOC2 controls."""
    result = {}

    # For each finding, get its mapped SOC2 controls and add it to those control groups
    for finding in findings:
        mapped_finding = soc2_mapper.map_finding(finding)
        controls = mapped_finding.get("SOC2Controls", [])

        # Add the finding to each control's list
        for control in controls:
            if control not in result:
                result[control] = []
            result[control].append(finding)

    return result
