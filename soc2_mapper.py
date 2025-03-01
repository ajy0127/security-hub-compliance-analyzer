import json
import logging
import os

from framework_mapper import FrameworkMapper

# Configure logging
logger = logging.getLogger(__name__)

class SOC2Mapper(FrameworkMapper):
    """
    Mapper for SOC2 compliance framework.
    """

    def __init__(self, mappings_file=None):
        """
        Initialize the SOC2 Mapper.
        
        Args:
            mappings_file (str, optional): Path to the mappings file. Defaults to None.
        """
        # Set default mappings file if not provided
        if mappings_file is None:
            mappings_file = os.path.join("mappings", "soc2_mapping.json")
            
        # Initialize parent class with framework_id
        super().__init__(framework_id="SOC2", mappings_file=mappings_file)
        
        # Load mappings from file or use defaults
        self.mappings = self._load_mappings(mappings_file)

    def _get_default_mappings(self):
        """
        Get default mappings for SOC2 controls.
        
        Returns:
            dict: Default mappings for SOC2 controls
        """
        return {
            "type_mappings": {
                "Software and Configuration Checks": ["CC6.1", "CC6.3", "CC6.6"],
                "Effects": ["CC7.1", "CC7.2"],
                "Sensitive Data Identifications": ["CC6.1", "CC6.5"],
                "Data Protection": ["CC6.1", "CC6.5", "CC6.7"],
                "Industry and Regulatory Standards": ["CC2.2", "CC2.3"],
            },
            "title_mappings": {
                "encryption": ["CC6.1", "CC6.7"],
                "access": ["CC6.1", "CC6.3"],
                "permission": ["CC6.1", "CC6.3"],
                "exposed": ["CC6.1", "CC6.6"],
                "public": ["CC6.1", "CC6.6"],
                "password": ["CC6.1", "CC6.3"],
                "key": ["CC6.1", "CC6.7"],
                "vulnerability": ["CC7.1", "CC7.2"],
                "patch": ["CC7.1", "CC7.2"],
                "backup": ["A1.2"],
                "logging": ["CC4.1", "CC4.2"],
                "monitor": ["CC4.1", "CC4.2"],
                "network": ["CC6.6", "CC6.7"],
                "firewall": ["CC6.6", "CC6.7"],
                "security group": ["CC6.6"],
                "certificate": ["CC6.7"],
                "compliance": ["CC2.2", "CC2.3"],
            },
            "control_descriptions": {
                "CC2.2": "The entity's security policies include provisions for addressing security risks, security breaches, and other incidents.",
                "CC2.3": "The entity's security policies include provisions for evaluating the design and operating effectiveness of security controls.",
                "CC4.1": "The entity monitors its system and collects information about potential security breaches and other incidents.",
                "CC4.2": "The entity analyzes the information collected to identify potential security breaches and other incidents.",
                "CC6.1": "The entity implements logical access security measures to protect against unauthorized access to system resources.",
                "CC6.3": "The entity authorizes, designs, develops, implements, operates, approves, maintains, and monitors environmental protections, software, data, and physical access to meet the entity's objectives.",
                "CC6.5": "The entity discontinues logical and physical protections over physical assets only after the ability to read or recover data and software from those assets has been diminished and is no longer required to meet the entity's objectives.",
                "CC6.6": "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
                "CC6.7": "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal to meet the entity's objectives.",
                "CC7.1": "The entity develops security requirements for new information systems and changes to existing information systems to meet the entity's objectives.",
                "CC7.2": "The entity develops detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities.",
                "A1.2": "The entity authorizes, designs, develops, implements, operates, approves, maintains, and monitors backup processes to meet the entity's objectives.",
            },
        }

    def _get_default_control(self):
        """
        Get the default control ID for SOC2.
        
        Returns:
            str: Default control ID
        """
        return "CC6.1"

    def get_control_id_attribute(self):
        """
        Get the attribute name for control IDs in mapped findings.
        
        Returns:
            str: Attribute name for control IDs
        """
        return "SOC2Controls"

    def map_finding(self, finding):
        """
        Map a Security Hub finding to SOC2 controls.
        
        Args:
            finding (dict): Security Hub finding
            
        Returns:
            dict: Mapped finding with SOC2 controls
        """
        # Extract details from finding
        title = finding.get("Title", "")
        description = finding.get("Description", "")
        severity = finding.get("Severity", {}).get("Label", "INFORMATIONAL")
        finding_type = ""
        
        # Extract finding type from Types array if available
        if "Types" in finding and finding["Types"]:
            finding_type = finding["Types"][0]
        
        # Get resource ID
        resource_id = self._get_resource_id(finding)
        
        # Create mapped finding
        mapped_finding = {
            "Title": title,
            "Description": description,
            "Severity": severity,
            "Type": finding_type,
            "ResourceId": resource_id,
            "SOC2Controls": [],
        }
        
        # Map to controls based on type
        controls = set()
        
        # Check type mappings
        for type_pattern, type_controls in self.mappings["type_mappings"].items():
            if type_pattern in finding_type:
                controls.update(type_controls)
        
        # Check title mappings
        for title_pattern, title_controls in self.mappings["title_mappings"].items():
            if title_pattern.lower() in title.lower() or title_pattern.lower() in description.lower():
                controls.update(title_controls)
        
        # If no controls matched, use default
        if not controls:
            controls.add(self._get_default_control())
        
        # Add controls to mapped finding
        mapped_finding["SOC2Controls"] = sorted(list(controls))
        
        return mapped_finding 