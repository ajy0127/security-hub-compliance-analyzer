import logging

# =========================================================================
# Utility Functions for SecurityHub SOC2 Analyzer
# =========================================================================
# This module provides common utility functions used throughout the application
# for formatting, extracting and processing security findings data.
# =========================================================================

# Configure logging
logger = logging.getLogger()


def format_datetime(dt):
    """
    Format a datetime object into ISO 8601 format used by SecurityHub API.
    
    Args:
        dt (datetime): A datetime object to format
        
    Returns:
        str: The formatted datetime string in ISO 8601 format with microseconds
    """
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def get_resource_id(finding):
    """
    Extract the affected resource ID from a SecurityHub finding.
    
    Args:
        finding (dict): A SecurityHub finding dictionary
        
    Returns:
        str: The resource ID if found, or "Unknown" if not found
    """
    if "Resources" in finding and finding["Resources"]:
        return finding["Resources"][0].get("Id", "Unknown")
    return "Unknown"


def get_account_id(finding):
    """
    Extract the AWS account ID from a SecurityHub finding.
    
    Args:
        finding (dict): A SecurityHub finding dictionary
        
    Returns:
        str: The AWS account ID if found, or "Unknown" if not found
    """
    return finding.get("AwsAccountId", "Unknown")


def get_region(finding):
    """
    Extract the AWS region from a SecurityHub finding.
    
    Args:
        finding (dict): A SecurityHub finding dictionary
        
    Returns:
        str: The AWS region if found, or "Unknown" if not found
    """
    return finding.get("Region", "Unknown")


def truncate_text(text, max_length=200):
    """
    Truncate a text string to a specified maximum length with ellipsis.
    
    This is useful for displaying long descriptions in reports and emails
    without overwhelming the display.
    
    Args:
        text (str): The text to truncate
        max_length (int, optional): Maximum length before truncation. Defaults to 200.
        
    Returns:
        str: Truncated text with ellipsis if needed, or original text if shorter than max_length
    """
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."


def format_severity(severity):
    """
    Format a severity value for consistent display.
    
    Handles both string severity values and severity dictionary objects
    from SecurityHub findings.
    
    Args:
        severity (str or dict): A severity value, either as a string or as a 
                               dictionary with a 'Label' key
        
    Returns:
        str: The formatted severity label, or "UNKNOWN" if not found
    """
    if isinstance(severity, dict):
        return severity.get("Label", "UNKNOWN")
    return severity or "UNKNOWN"


def group_by_severity(findings):
    """
    Group a list of findings by their severity level.
    
    This is useful for generating reports that organize findings by severity,
    making it easier to prioritize the most critical issues.
    
    Args:
        findings (list): A list of SecurityHub finding dictionaries
        
    Returns:
        dict: A dictionary where keys are severity levels (CRITICAL, HIGH, etc.)
              and values are lists of findings with that severity
    """
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
    """
    Group a list of findings by their associated SOC2 controls.

    This provides a compliance-oriented view of findings, showing which
    SOC2 controls are impacted by security issues.

    Args:
        findings (list): A list of SecurityHub finding dictionaries
        soc2_mapper (SOC2Mapper): An instance of SOC2Mapper to map findings to controls

    Returns:
        dict: A dictionary where keys are SOC2 control IDs and values are
              lists of findings associated with that control
    """
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
