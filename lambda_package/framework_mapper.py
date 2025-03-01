"""Base framework mapper for AWS SecurityHub compliance framework mappings."""

import json
import logging
import os
import re
from pathlib import Path

# Configure logging
logger = logging.getLogger()


class FrameworkMapper:
    """Base class for mapping AWS SecurityHub findings to compliance framework controls."""

    def __init__(self, framework_id, mappings_file=None):
        """Initialize the FrameworkMapper with framework ID and control mappings.

        Args:
            framework_id (str): The ID of the compliance framework (e.g., 'SOC2', 'NIST800-53')
            mappings_file (str, optional): Path to the mappings JSON file for this framework
        """
        self.framework_id = framework_id
        self.mappings_file = mappings_file
        self.mappings = self._load_mappings()

    def _load_mappings(self):
        """Load framework control mappings from a JSON file or use default mappings."""
        try:
            # Try to load mappings from the specified file
            if self.mappings_file and os.path.exists(self.mappings_file):
                with open(self.mappings_file, "r") as f:
                    return json.load(f)
            else:
                logger.warning(
                    f"Mappings file {self.mappings_file} not found, using default mappings"
                )
                return self._get_default_mappings()
        except Exception as e:
            logger.error(f"Error loading mappings for {self.framework_id}: {str(e)}")
            return self._get_default_mappings()

    def _get_default_mappings(self):
        """Provide default control mappings if configuration file is not available.

        This method should be overridden by subclasses to provide framework-specific defaults.
        """
        return {"type_mappings": {}, "title_mappings": {}, "control_descriptions": {}}

    def get_control_id_attribute(self):
        """Get the attribute name used for storing control IDs in mapped findings.

        Returns:
            str: The attribute name (e.g., 'SOC2Controls', 'NIST800-53Controls')
        """
        return f"{self.framework_id}Controls"

    def map_finding(self, finding):
        """Map an AWS SecurityHub finding to relevant framework controls.

        Args:
            finding (dict): The AWS SecurityHub finding to map

        Returns:
            dict: Enhanced finding object with framework mapping information
        """
        # Extract relevant information from the finding
        finding_type = ", ".join(finding.get("Types", ["Unknown"]))
        title = finding.get("Title", "")
        description = finding.get("Description", "")
        severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
        resource_id = self._get_resource_id(finding)

        # Map the finding to the appropriate controls
        controls = self._map_to_controls(finding_type, title, description)

        # Control ID attribute name (e.g., SOC2Controls, NIST800-53Controls)
        control_attr = self.get_control_id_attribute()

        # Create enhanced finding object with framework mapping information
        mapped_finding = {
            "Title": title,
            "Severity": severity,
            "Type": finding_type,
            "ResourceId": resource_id,
            "Description": (
                description[:200] + "..." if len(description) > 200 else description
            ),
            "FrameworkId": self.framework_id,
            control_attr: controls,
            "ControlDescriptions": [
                self.mappings["control_descriptions"].get(control, "")
                for control in controls
            ],
        }

        return mapped_finding

    def _map_to_controls(self, finding_type, title, description):
        """Map a finding to framework controls based on its type, title, and description.

        Args:
            finding_type (str): Type of the finding
            title (str): Finding title
            description (str): Finding description

        Returns:
            list: Relevant control IDs for this framework
        """
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

        # If no controls were mapped, use a default control if defined
        if not controls and self._get_default_control():
            controls.add(self._get_default_control())

        # Convert set to sorted list for consistent output
        return sorted(list(controls))

    def _get_default_control(self):
        """Get the default control ID for this framework when no mapping is found.

        This method should be overridden by subclasses to provide framework-specific defaults.

        Returns:
            str: Default control ID or None
        """
        return None

    def _get_resource_id(self, finding):
        """Extract the affected resource ID from a SecurityHub finding."""
        # Check if the Resources list exists and has at least one entry
        if "Resources" in finding and finding["Resources"]:
            return finding["Resources"][0].get("Id", "Unknown")
        return "Unknown"
