import logging

# Configure logging
logger = logging.getLogger()


def format_datetime(dt):
    """Format datetime for SecurityHub API"""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def get_resource_id(finding):
    """Extract resource ID from finding"""
    if "Resources" in finding and finding["Resources"]:
        return finding["Resources"][0].get("Id", "Unknown")
    return "Unknown"


def get_account_id(finding):
    """Extract AWS account ID from finding"""
    return finding.get("AwsAccountId", "Unknown")


def get_region(finding):
    """Extract AWS region from finding"""
    return finding.get("Region", "Unknown")


def truncate_text(text, max_length=200):
    """Truncate text to specified length"""
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."


def format_severity(severity):
    """Format severity for display"""
    if isinstance(severity, dict):
        return severity.get("Label", "UNKNOWN")
    return severity or "UNKNOWN"


def group_by_severity(findings):
    """Group findings by severity"""
    result = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFORMATIONAL": []}

    for finding in findings:
        severity = format_severity(finding.get("Severity"))
        if severity in result:
            result[severity].append(finding)
        else:
            result["INFORMATIONAL"].append(finding)

    return result


def group_by_control(findings, soc2_mapper):
    """Group findings by SOC2 control"""
    result = {}

    for finding in findings:
        mapped_finding = soc2_mapper.map_finding(finding)
        controls = mapped_finding.get("SOC2Controls", [])

        for control in controls:
            if control not in result:
                result[control] = []
            result[control].append(finding)

    return result
