"""
SOC 2 Mapper Module

This module handles the mapping of AWS SecurityHub findings to SOC 2 Trust Service Criteria (TSC).
It provides functionality to:
- Map security findings to relevant SOC 2 controls
- Format findings into SOC 2 workpaper format
- Generate CSV data for audit documentation

The mapping logic is based on the configurations in soc2_control_mappings.json, which defines:
- Finding type to SOC 2 control mappings
- Severity to risk level mappings
- Control descriptions
"""

import json
import logging
import os
from pathlib import Path
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class SOC2Mapper:
    def __init__(self):
        """
        Initialize the SOC2Mapper by loading control mappings from JSON configuration.
        The configuration file contains mappings between SecurityHub finding types and SOC 2 controls.
        """
        config_path = (
            Path(__file__).parent.parent.parent
            / "config"
            / "soc2_control_mappings.json"
        )
        try:
            with open(config_path, "r") as f:
                self.mappings = json.load(f)
        except FileNotFoundError:
            logger.error(f"Could not find configuration file at {config_path}")
            raise
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in configuration file at {config_path}")
            raise

    def map_finding_to_controls(self, finding):
        """
        Map a SecurityHub finding to relevant SOC 2 controls based on finding type.

        Args:
            finding (dict): SecurityHub finding object

        Returns:
            dict: Dictionary containing lists of primary and secondary controls that map to the finding
                 Format: {
                     'primary_controls': ['CC6.1', 'CC7.1', ...],
                     'secondary_controls': ['CC8.1', ...]
                 }
        """
        # Handle None or non-dict finding
        if not finding or not isinstance(finding, dict):
            return {"primary_controls": [], "secondary_controls": []}

        finding_type = finding.get("Type", "")
        mapped_controls = {"primary_controls": [], "secondary_controls": []}

        # If empty finding type, return empty mappings
        if not finding_type:
            return mapped_controls

        # First try exact match
        if finding_type in self.mappings["finding_type_mappings"]:
            mapping = self.mappings["finding_type_mappings"][finding_type]
            mapped_controls["primary_controls"].extend(mapping["primary_controls"])
            mapped_controls["secondary_controls"].extend(mapping["secondary_controls"])

        # Look for partial matches in the finding type path
        finding_parts = finding_type.split("/")
        for mapping_type, mapping in self.mappings["finding_type_mappings"].items():
            mapping_parts = mapping_type.split("/")

            # Check if any part of the finding type matches the mapping
            for part in finding_parts:
                if part and part in mapping_parts:  # Skip empty parts
                    # Add controls if not already present
                    for control in mapping["primary_controls"]:
                        if control not in mapped_controls["primary_controls"]:
                            mapped_controls["primary_controls"].append(control)
                    for control in mapping["secondary_controls"]:
                        if control not in mapped_controls["secondary_controls"]:
                            mapped_controls["secondary_controls"].append(control)
                    break

        return mapped_controls

    def get_control_description(self, control_id):
        """
        Get the description text for a SOC 2 control.

        Args:
            control_id (str): SOC 2 control identifier (e.g., 'CC6.1')

        Returns:
            str: Description of the control or default message if not found
        """
        return self.mappings["control_descriptions"].get(
            control_id, "Description not available"
        )

    def map_severity_to_risk(self, severity):
        """
        Map SecurityHub severity levels to SOC 2 risk levels.

        Args:
            severity (str): SecurityHub severity level (e.g., 'CRITICAL', 'HIGH')

        Returns:
            str: Corresponding SOC 2 risk level ('High', 'Medium', 'Low')
        """
        return self.mappings["severity_risk_mapping"].get(severity, "Unknown")

    def format_finding_for_soc2(self, finding):
        """
        Format a SecurityHub finding into SOC 2 workpaper format.
        Creates separate entries for each primary control affected by the finding.

        Args:
            finding (dict): SecurityHub finding object

        Returns:
            list: List of dictionaries, each representing a SOC 2 workpaper entry
        """
        mapped_controls = self.map_finding_to_controls(finding)
        risk_level = self.map_severity_to_risk(finding.get("Severity", "INFORMATIONAL"))

        # Create separate entries for each primary control
        soc2_findings = []
        for control in mapped_controls["primary_controls"]:
            soc2_finding = {
                "Control_ID": control,
                "Control_Description": self.get_control_description(control),
                "SecurityHub_Finding_ID": finding.get("Id", "N/A"),
                "Finding_Title": finding.get("Title", "N/A"),
                "Finding_Description": finding.get("Description", "N/A"),
                "Risk_Level": risk_level,
                "Resource_Affected": finding.get("Resources", [{}])[0].get("Id", "N/A"),
                "Control_Status": (
                    "Fail" if risk_level in ["High", "Medium"] else "Pass"
                ),
                "Remediation_Steps": finding.get("Remediation", {})
                .get("Recommendation", {})
                .get("Text", "No remediation steps provided"),
                "Remediation_Timeline": (
                    "30 days"
                    if risk_level == "High"
                    else "90 days" if risk_level == "Medium" else "180 days"
                ),
                "Evidence_Reference": finding.get("ProductArn", "N/A"),
                "Audit_Impact": (
                    f"This finding affects compliance with {control} and requires immediate attention"
                    if risk_level == "High"
                    else f"This finding affects compliance with {control}"
                ),
                "Test_Procedures": "Review SecurityHub finding and verify remediation",
                "Compensating_Controls": "None identified",
                "Finding_Created_At": finding.get(
                    "CreatedAt", datetime.now().isoformat()
                ),
                "Last_Updated": finding.get("UpdatedAt", datetime.now().isoformat()),
            }
            soc2_findings.append(soc2_finding)

        return soc2_findings

    def generate_csv_data(self, findings):
        """
        Generate CSV data for all findings in SOC 2 workpaper format.

        Args:
            findings (list): List of SecurityHub finding objects

        Returns:
            list: List of dictionaries formatted for CSV export
        """
        csv_data = []
        for finding in findings:
            soc2_findings = self.format_finding_for_soc2(finding)
            csv_data.extend(soc2_findings)

        return csv_data

    def get_csv_headers(self):
        """
        Get the column headers for the SOC 2 workpaper CSV.

        Returns:
            list: List of column header names in the order they should appear
        """
        return [
            "Control_ID",
            "Control_Description",
            "SecurityHub_Finding_ID",
            "Finding_Title",
            "Finding_Description",
            "Risk_Level",
            "Resource_Affected",
            "Control_Status",
            "Remediation_Steps",
            "Remediation_Timeline",
            "Evidence_Reference",
            "Audit_Impact",
            "Test_Procedures",
            "Compensating_Controls",
            "Finding_Created_At",
            "Last_Updated",
        ]
