import json
import logging
import os
import re
from abc import ABC, abstractmethod

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

    def _load_mappings(self, mappings_file=None):
        """Load framework control mappings from a JSON file or use default mappings.

        Args:
            mappings_file (str, optional): Override the instance mappings_file. Defaults to None.

        Returns:
            dict: The loaded mappings or default mappings if file cannot be loaded
        """
        try:
            # Use the provided mappings_file or fall back to the instance variable
            file_path = mappings_file or self.mappings_file

            # Try to load mappings from the specified file
            if file_path and os.path.exists(file_path):
                with open(file_path, "r") as f:
                    return json.load(f)
            else:
                logger.warning(
                    f"Mappings file {file_path} not found, using default mappings"
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

    def map_finding(self, finding):
        """Map a SecurityHub finding to this compliance framework.

        Args:
            finding (dict): The AWS SecurityHub finding to map

        Returns:
            dict: Mapped finding with added control IDs for this framework
        """
        # Create a copy of the finding to avoid modifying the original
        mapped_finding = finding.copy()

        # Extract relevant fields for mapping
        finding_type = " ".join(finding.get("Types", ["Unknown"]))
        title = finding.get("Title", "")
        description = finding.get("Description", "")

        # Map the finding to framework controls
        control_ids = self._map_to_controls(finding_type, title, description)

        # Add control IDs to the mapped finding
        control_attr = self.get_control_id_attribute()
        mapped_finding[control_attr] = control_ids

        # Extract and add resource ID for easier reference
        mapped_finding["ResourceId"] = self._get_resource_id(finding)

        return mapped_finding

    def get_control_id_attribute(self):
        """Get the attribute name used for storing control IDs in mapped findings.

        Returns:
            str: Attribute name for framework control IDs (e.g., 'SOC2Controls')
        """
        return f"{self.framework_id}Controls"
