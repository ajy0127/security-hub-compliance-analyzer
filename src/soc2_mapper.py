import json
import logging
import os
import re
from pathlib import Path

# Configure logging
logger = logging.getLogger()


class SOC2Mapper:
    """Maps AWS SecurityHub findings to their corresponding SOC2 controls."""

    def __init__(self, mappings_file=None):
        """Initialize the SOC2Mapper with control mappings."""
        self.mappings_file = mappings_file or os.path.join(os.path.dirname(__file__), "config", "mappings.json")
        self.mappings = self._load_mappings()

    def _load_mappings(self):
        """Load SOC2 control mappings from a JSON file or use default mappings."""
        try:
            # Try to load mappings from the specified file
            if os.path.exists(self.mappings_file):
                with open(self.mappings_file, "r") as f:
                    return json.load(f)
            else:
                logger.warning(
                    f"Mappings file {self.mappings_file} not found, using default mappings"
                )
                return self._get_default_mappings()
        except Exception as e:
            logger.error(f"Error loading mappings: {str(e)}")
            return self._get_default_mappings()

    def _get_default_mappings(self):
        """Provide default SOC2 control mappings if configuration file is not available."""
        return {
            # Map SecurityHub finding types to SOC2 controls
            "type_mappings": {
                "Software and Configuration Checks": ["CC6.1", "CC6.8", "CC7.1"],
                "Vulnerabilities": ["CC7.1", "CC8.1"],
                "Effects": ["CC7.1", "CC7.2"],
                "Software and Configuration Checks/Industry and Regulatory Standards": ["CC1.3", "CC2.2", "CC2.3"],
                "Sensitive Data Identifications": ["CC6.1", "CC6.5"],
                "Network Reachability": ["CC6.6", "CC6.7"],
                "Unusual Behaviors": ["CC7.2", "CC7.3"],
                "Policy": ["CC1.2", "CC1.3", "CC1.4"],
            },
            # Map keywords in finding titles to SOC2 controls
            "title_mappings": {
                "password": ["CC6.1", "CC6.3"],
                "encryption": ["CC6.1", "CC6.7"],
                "access": ["CC6.1", "CC6.3"],
                "permission": ["CC6.1", "CC6.3"],
                "exposed": ["CC6.1", "CC6.6"],
                "public": ["CC6.1", "CC6.6"],
                "patch": ["CC7.1", "CC8.1"],
                "update": ["CC7.1", "CC8.1"],
                "backup": ["A1.2", "A1.3"],
                "logging": ["CC4.1", "CC4.2"],
                "monitor": ["CC7.2", "CC7.3"],
            },
            # SOC2 control descriptions for context and reporting
            "control_descriptions": {
                "CC1.2": "Management has defined and communicated roles and responsibilities for the design, implementation, operation, and maintenance of controls.",
                "CC1.3": "Management has established procedures to evaluate and determine whether controls are operating effectively.",
                "CC1.4": "Management has implemented a process to identify and address deviations from the established control environment.",
                "CC2.2": "Information security policies include requirements for addressing security objectives.",
                "CC2.3": "Responsibility and accountability for designing, developing, implementing, operating, maintaining, and monitoring controls are assigned to individuals within the entity with appropriate skill levels and authority.",
                "CC4.1": "Management has established policies and procedures to manage and monitor the risks related to vendor and business partner relationships.",
                "CC4.2": "The risk management program includes the use of appropriate vendor due diligence prior to engaging a vendor.",
                "CC6.1": "The entity implements logical access security software, infrastructure, and architectures for authentication and access to the system.",
                "CC6.3": "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles and responsibilities and considering the concepts of least privilege and segregation of duties.",
                "CC6.5": "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.",
                "CC6.6": "The entity implements boundary protection systems and monitoring to prevent unauthorized access to system components.",
                "CC6.7": "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal.",
                "CC6.8": "The entity implements controls to prevent, detect, and correct malicious software on endpoints, servers, and mobile devices.",
                "CC7.1": "The entity's security operations includes vulnerability management, security monitoring, and incident response.",
                "CC7.2": "The entity performs security monitoring activities to detect potential security breaches and vulnerabilities.",
                "CC7.3": "The entity evaluates security events to determine if they could or have resulted in a security incident.",
                "CC8.1": "The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup processes, and recovery infrastructure to meet its objectives.",
                "A1.2": "The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup processes, and recovery infrastructure to meet its availability objectives.",
                "A1.3": "The entity designs, develops, implements, and operates controls to mitigate threats to availability.",
            },
        }

    def map_finding(self, finding):
        """Map an AWS SecurityHub finding to relevant SOC2 controls."""
        # Extract relevant information from the finding
        finding_type = ", ".join(finding.get("Types", ["Unknown"]))
        title = finding.get("Title", "")
        description = finding.get("Description", "")
        severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
        resource_id = self._get_resource_id(finding)

        # Map the finding to the appropriate SOC2 controls
        controls = self._map_to_controls(finding_type, title, description)

        # Create enhanced finding object with SOC2 mapping information
        mapped_finding = {
            "Title": title,
            "Severity": severity,
            "Type": finding_type,
            "ResourceId": resource_id,
            "Description": description[:200] + "..." if len(description) > 200 else description,
            "SOC2Controls": controls,
            "ControlDescriptions": [self.mappings["control_descriptions"].get(control, "") for control in controls],
        }

        return mapped_finding

    def _map_to_controls(self, finding_type, title, description):
        """Map a finding to SOC2 controls based on its type, title, and description."""
        # Use a set to avoid duplicate controls
        controls = set()

        # Map based on finding type
        for type_pattern, type_controls in self.mappings["type_mappings"].items():
            if type_pattern in finding_type:
                controls.update(type_controls)

        # Map based on keywords in finding title
        for title_pattern, title_controls in self.mappings["title_mappings"].items():
            # Use word boundary regex to match whole words only
            if re.search(r"\b" + re.escape(title_pattern) + r"\b", title.lower()):
                controls.update(title_controls)

        # If no controls were mapped, use a default control
        if not controls:
            controls.add("CC7.1")  # Default to security operations control

        # Convert set to sorted list for consistent output
        return list(controls)

    def _get_resource_id(self, finding):
        """Extract the affected resource ID from a SecurityHub finding."""
        # Check if the Resources list exists and has at least one entry
        if "Resources" in finding and finding["Resources"]:
            return finding["Resources"][0].get("Id", "Unknown")
        return "Unknown"
