"""
Custom control mapping for organization-specific requirements.

This module extends the base SOC2Mapper with organization-specific mapping rules,
custom control definitions, and additional risk mapping logic.
"""

import json
import os
import re
from typing import Dict, List, Any, Optional
from pathlib import Path

from src.utils.logging_utils import get_logger
from src.lib.soc2_mapper import SOC2Mapper

# Initialize logger
logger = get_logger(__name__)


class CustomControlMapper(SOC2Mapper):
    """
    Extended mapper for organization-specific control mappings.

    Inherits from the base SOC2Mapper but adds support for:
    1. Organization-specific mapping rules
    2. Custom control definitions
    3. Regex-based finding type matching
    4. Resource-specific control mappings
    """

    def __init__(self, custom_config_path: Optional[str] = None):
        """
        Initialize the custom control mapper.

        Args:
            custom_config_path: Optional path to custom configuration
        """
        # Initialize base SOC2Mapper
        super().__init__(custom_config_path)

        # Load organization-specific config
        org_config_path = os.environ.get(
            "CUSTOM_CONTROL_CONFIG_PATH",
            str(
                Path(__file__).parent.parent.parent / "config" / "custom_controls.json"
            ),
        )

        self.custom_controls = {}
        self.regex_mappings = {}
        self.resource_mappings = {}

        try:
            if Path(org_config_path).exists():
                with open(org_config_path, "r") as f:
                    org_config = json.load(f)

                    # Add custom controls to main mappings
                    if "custom_controls" in org_config:
                        self.custom_controls = org_config["custom_controls"]
                        if "control_descriptions" not in self.mappings:
                            self.mappings["control_descriptions"] = {}

                        # Add custom control descriptions to main control descriptions
                        for control_id, desc in self.custom_controls.items():
                            self.mappings["control_descriptions"][control_id] = desc

                    # Load regex mappings
                    if "regex_mappings" in org_config:
                        self.regex_mappings = org_config["regex_mappings"]

                    # Load resource mappings
                    if "resource_mappings" in org_config:
                        self.resource_mappings = org_config["resource_mappings"]

                    logger.info(
                        "Loaded organization-specific config",
                        custom_controls=len(self.custom_controls),
                        regex_mappings=len(self.regex_mappings),
                        resource_mappings=len(self.resource_mappings),
                    )
        except Exception as e:
            logger.error(f"Error loading organization-specific config: {str(e)}")

    def map_finding_to_controls(self, finding: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Map a finding to controls using extended mapping logic.

        Extends the base implementation with:
        1. Base SOC2 control mapping (exact and partial)
        2. Regex-based mapping
        3. Resource-specific mapping

        Args:
            finding: SecurityHub finding dictionary

        Returns:
            Dictionary with primary and secondary controls
        """
        # First get base SOC2 control mappings
        mapped_controls = super().map_finding_to_controls(finding)

        # Apply regex mappings
        self._apply_regex_mappings(finding, mapped_controls)

        # Apply resource-specific mappings
        self._apply_resource_mappings(finding, mapped_controls)

        # Deduplicate controls
        mapped_controls["primary_controls"] = list(
            set(mapped_controls["primary_controls"])
        )
        mapped_controls["secondary_controls"] = list(
            set(mapped_controls["secondary_controls"])
        )

        # Remove primary controls from secondary list
        mapped_controls["secondary_controls"] = [
            c
            for c in mapped_controls["secondary_controls"]
            if c not in mapped_controls["primary_controls"]
        ]

        return mapped_controls

    def _apply_regex_mappings(
        self, finding: Dict[str, Any], mapped_controls: Dict[str, List[str]]
    ) -> None:
        """
        Apply regex-based mappings to a finding.

        Args:
            finding: SecurityHub finding dictionary
            mapped_controls: Dictionary to update with mapped controls
        """
        finding_type = finding.get("Type", "")
        finding_title = finding.get("Title", "")
        finding_desc = finding.get("Description", "")

        # Skip if any key field is missing
        if not finding_type or not finding_title:
            return

        # Check each regex pattern
        for pattern, mapping in self.regex_mappings.items():
            try:
                # Check if pattern matches finding type, title, or description
                if (
                    re.search(pattern, finding_type, re.IGNORECASE)
                    or re.search(pattern, finding_title, re.IGNORECASE)
                    or (
                        finding_desc and re.search(pattern, finding_desc, re.IGNORECASE)
                    )
                ):

                    # Add mapped controls
                    if "primary_controls" in mapping:
                        mapped_controls["primary_controls"].extend(
                            mapping["primary_controls"]
                        )

                    if "secondary_controls" in mapping:
                        mapped_controls["secondary_controls"].extend(
                            mapping["secondary_controls"]
                        )

                    logger.debug(
                        "Applied regex mapping",
                        pattern=pattern,
                        finding_id=finding.get("Id", "unknown"),
                    )
            except re.error:
                logger.error(f"Invalid regex pattern: {pattern}")

    def _apply_resource_mappings(
        self, finding: Dict[str, Any], mapped_controls: Dict[str, List[str]]
    ) -> None:
        """
        Apply resource-specific mappings to a finding.

        Args:
            finding: SecurityHub finding dictionary
            mapped_controls: Dictionary to update with mapped controls
        """
        resource_type = finding.get("ResourceType", "")

        # Skip if resource type is missing
        if not resource_type:
            return

        # Check for exact resource type match
        if resource_type in self.resource_mappings:
            mapping = self.resource_mappings[resource_type]

            # Add mapped controls
            if "primary_controls" in mapping:
                mapped_controls["primary_controls"].extend(mapping["primary_controls"])

            if "secondary_controls" in mapping:
                mapped_controls["secondary_controls"].extend(
                    mapping["secondary_controls"]
                )

            logger.debug(
                "Applied resource mapping",
                resource_type=resource_type,
                finding_id=finding.get("Id", "unknown"),
            )

    def format_finding_for_soc2(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Format a finding for SOC2 workpaper with custom control support.

        Extends the base implementation to include custom control IDs.

        Args:
            finding: SecurityHub finding dictionary

        Returns:
            List of dictionaries representing SOC2 workpaper entries
        """
        # Use the base implementation
        return super().format_finding_for_soc2(finding)


def get_custom_mapper(custom_config_path: Optional[str] = None) -> CustomControlMapper:
    """
    Get a configured custom control mapper.

    Args:
        custom_config_path: Optional path to custom configuration

    Returns:
        Configured CustomControlMapper
    """
    return CustomControlMapper(custom_config_path)
