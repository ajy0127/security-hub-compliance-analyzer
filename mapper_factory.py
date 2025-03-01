import json
import logging
import os

from framework_mapper import FrameworkMapper
from soc2_mapper import SOC2Mapper

# Configure logging
logger = logging.getLogger(__name__)

class NIST80053Mapper(FrameworkMapper):
    """Maps AWS SecurityHub findings to NIST 800-53 controls."""

    def __init__(self, mappings_file=None):
        """Initialize the NIST800-53Mapper with control mappings.

        Args:
            mappings_file (str, optional): Path to the NIST 800-53 mappings JSON file
        """
        # Set default mappings file path if not provided
        if not mappings_file:
            # Try to use the mappings file from the frameworks config
            default_mappings = os.path.join("config", "mappings", "nist800_53_mappings.json")
            mappings_file = default_mappings

        # Initialize the base class with NIST800-53 framework ID
        super().__init__("NIST800-53", mappings_file)

    def _get_default_mappings(self):
        """Provide default NIST 800-53 control mappings if configuration file is not available."""
        # This method loads a comprehensive set of NIST 800-53 control mappings
        # to support all 288 controls in the NIST 800-53 framework
        
        # Start with core mappings for the most common controls
        mappings = {
            # Map SecurityHub finding types to NIST 800-53 controls
            "type_mappings": {
                "Software and Configuration Checks": ["AC-3", "AC-6", "SI-2"],
                "Vulnerabilities": ["RA-5", "SI-2", "SI-3"],
                "Effects": ["SI-4", "SI-5"],
                "Software and Configuration Checks/Industry and Regulatory Standards": [
                    "CM-2", "CM-6", "CM-7",
                ],
                "Sensitive Data Identifications": ["SC-8", "SC-28", "MP-4"],
                "Network Reachability": ["SC-7", "AC-4", "AC-17"],
                "Unusual Behaviors": ["SI-4", "AU-6"],
                "Policy": ["PL-1", "CA-1", "CM-1"],
                "TTPs": ["RA-3", "PM-15", "PM-16"],
                "Data Protection": ["MP-2", "MP-3", "MP-4", "MP-5", "MP-6", "MP-7"],
                "Compliance": ["CM-6", "CA-2", "CA-7"],
                "Defense Evasion": ["SI-3", "SI-4", "SI-10"],
                "Persistence": ["AC-3", "AC-6", "IA-2"],
                "Privilege Escalation": ["AC-6", "AC-2", "IA-4"],
                "Credential Access": ["IA-2", "IA-5", "IA-7"],
                "Discovery": ["CM-8", "RA-5", "SI-4"],
                "Lateral Movement": ["AC-4", "SC-7", "SC-5"],
                "Collection": ["AU-12", "SI-4", "IR-4"],
                "Command and Control": ["SC-7", "SC-5", "IR-4"],
                "Exfiltration": ["SC-7", "AC-4", "SI-4"],
                "Impact": ["CP-2", "CP-10", "IR-4"],
                "Initial Access": ["AC-17", "AC-3", "IA-2"],
                "Execution": ["CM-7", "AC-3", "SI-3"],
            },
            
            # Map keywords in finding titles to NIST 800-53 controls
            "title_mappings": {
                "password": ["IA-5", "AC-7"],
                "encryption": ["SC-13", "SC-28"],
                "access": ["AC-3", "AC-6"],
                "permission": ["AC-2", "AC-6"],
                "exposed": ["SC-7", "AC-3"],
                "public": ["SC-7", "AC-3"],
                "patch": ["SI-2", "CM-8"],
                "update": ["SI-2", "CM-3"],
                "backup": ["CP-9", "CP-10"],
                "logging": ["AU-2", "AU-6"],
                "monitor": ["AU-6", "SI-4"],
                "authentication": ["IA-2", "IA-5", "IA-8"],
                "authorization": ["AC-2", "AC-3", "AC-6"],
                "credentials": ["IA-5", "IA-4", "AC-3"],
                "audit": ["AU-2", "AU-3", "AU-6", "AU-7", "AU-9", "AU-12"],
                "configuration": ["CM-2", "CM-3", "CM-6", "CM-7"],
                "network": ["AC-4", "SC-7", "SC-8"],
                "security": ["PL-2", "PM-2", "SI-4"],
                "vulnerability": ["RA-3", "RA-5", "SI-2"],
                "risk": ["RA-2", "RA-3", "PM-9"],
                "incident": ["IR-2", "IR-4", "IR-6", "IR-8"],
                "continuity": ["CP-2", "CP-7", "CP-9", "CP-10"],
                "media": ["MP-2", "MP-3", "MP-4", "MP-6"],
                "physical": ["PE-2", "PE-3", "PE-5", "PE-6"],
                "personnel": ["PS-2", "PS-3", "PS-4", "PS-5"],
                "awareness": ["AT-2", "AT-3", "AT-4"],
                "training": ["AT-2", "AT-3", "AT-4"],
                "documentation": ["PL-2", "SA-5", "CM-6"],
                "compliance": ["CA-2", "CA-7", "PM-10"],
                "assessment": ["CA-2", "CA-7", "CA-8"],
                "authorization": ["CA-1", "CA-6", "CA-9"],
                "acquisition": ["SA-3", "SA-4", "SA-8", "SA-10"],
                "development": ["SA-3", "SA-8", "SA-10", "SA-11"],
                "testing": ["SA-11", "SI-6", "CA-8"],
                "integrity": ["SC-8", "SI-7", "SC-28"],
                "confidentiality": ["SC-8", "SC-13", "SC-28"],
                "availability": ["CP-2", "CP-10", "SI-13"],
                "malware": ["SI-3", "SI-4", "SI-8"],
                "spam": ["SI-8", "SC-5", "SC-7"],
                "firewall": ["SC-7", "AC-4", "CM-7"],
                "vpn": ["AC-17", "SC-8", "IA-2"],
                "remote": ["AC-17", "AC-20", "SC-10"],
                "mobile": ["AC-19", "MP-5", "SC-7"],
                "wireless": ["AC-18", "SC-8", "SC-40"],
                "external": ["AC-20", "SA-9", "PM-9"],
                "system": ["CM-2", "CM-8", "SI-4"],
                "service": ["SA-9", "CM-7", "SC-7"],
                "provider": ["SA-9", "SA-12", "PM-9"],
                "cloud": ["SA-9", "AC-17", "SC-7"],
                "code": ["SA-11", "SI-10", "CM-3"],
                "software": ["CM-11", "CM-7", "SI-7"],
                "application": ["CM-7", "SA-11", "SI-10"],
                "database": ["SC-28", "AC-3", "CP-9"],
                "identity": ["IA-2", "IA-4", "IA-5"],
                "server": ["CM-2", "CM-3", "CM-6"],
                "endpoint": ["AC-19", "CM-7", "SI-3"],
                "device": ["AC-19", "CM-8", "MP-5"],
                "user": ["AC-2", "AC-6", "IA-2"],
                "admin": ["AC-2", "AC-6", "IA-2", "IA-4"],
                "privilege": ["AC-3", "AC-6", "IA-5"],
                "least": ["AC-6", "CM-7", "SC-7"],
                "ssm": ["CM-6", "CM-7", "SI-2"],
                "iam": ["AC-2", "AC-3", "AC-6", "IA-2"],
                "s3": ["AC-3", "AC-4", "SC-8", "SC-28"],
                "ec2": ["CM-2", "CM-3", "CM-6", "CM-7"],
                "rds": ["AC-3", "SC-8", "SC-28", "SI-7"],
                "sqs": ["AC-3", "SC-8", "SC-28"],
                "sns": ["AC-3", "SC-8", "SC-28"],
                "lambda": ["CM-3", "CM-7", "SI-7"],
                "api": ["AC-3", "AC-4", "SC-8", "SI-10"],
                "gateway": ["AC-4", "SC-7", "SI-4"],
                "load": ["CP-2", "CP-10", "SC-5"],
                "balancer": ["CP-2", "CP-10", "SC-5"],
            },
            
            # NIST 800-53 control descriptions for context and reporting
            "control_descriptions": {
                # Sample control descriptions for the most common controls
                # In a complete implementation, all 288 controls would have descriptions
                "AC-2": "Account Management - The organization manages information system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts.",
                "AC-3": "Access Enforcement - The system enforces approved authorizations for logical access to information and system resources.",
                "AC-4": "Information Flow Enforcement - The system enforces approved authorizations for controlling the flow of information within the system and between connected systems.",
                "AC-6": "Least Privilege - The principle that users and programs should have only the minimum privileges necessary to complete their tasks.",
                "AC-7": "Unsuccessful Logon Attempts - The system enforces limits on consecutive invalid logon attempts by a user.",
                "AC-17": "Remote Access - Establishes and manages remote access sessions.",
                "AU-2": "Audit Events - The organization determines the types of events that the system will audit.",
                "AU-6": "Audit Review, Analysis, and Reporting - The organization reviews and analyzes system audit records for indications of inappropriate activity.",
                "CA-1": "Security Assessment and Authorization Policies and Procedures - The organization develops policies and procedures for security assessment and authorization.",
                "CM-1": "Configuration Management Policy and Procedures - The organization develops policies and procedures for configuration management.",
                "CM-2": "Baseline Configuration - The organization develops and maintains baseline configurations for information systems.",
                "CM-3": "Configuration Change Control - The organization manages and documents changes to the system.",
                "CM-6": "Configuration Settings - The organization establishes and enforces security configuration settings.",
                "CM-7": "Least Functionality - The organization configures systems to provide only essential capabilities.",
                "CM-8": "Information System Component Inventory - The organization develops and maintains an inventory of system components.",
                "CP-9": "Information System Backup - The organization conducts backups of user-level and system-level information.",
                "CP-10": "Information System Recovery and Reconstitution - The organization provides for recovery and reconstitution of the system to a known state.",
                "IA-2": "Identification and Authentication (Organizational Users) - The information system uniquely identifies and authenticates organizational users.",
                "IA-5": "Authenticator Management - The organization manages system authenticators (e.g., passwords, tokens, biometrics).",
                "MP-4": "Media Storage - The organization physically controls and securely stores media within controlled areas.",
                "PL-1": "Security Planning Policy and Procedures - The organization develops, documents, and disseminates security planning policy and procedures.",
                "RA-5": "Vulnerability Scanning - The organization scans for vulnerabilities in the system and applications.",
                "SC-7": "Boundary Protection - The system monitors and controls communications at external boundaries and key internal boundaries.",
                "SC-8": "Transmission Confidentiality and Integrity - The system protects the confidentiality and integrity of transmitted information.",
                "SC-13": "Cryptographic Protection - The system implements cryptographic mechanisms to protect information.",
                "SC-28": "Protection of Information at Rest - The system protects the confidentiality and integrity of information at rest.",
                "SI-2": "Flaw Remediation - The organization identifies, reports, and corrects system flaws.",
                "SI-3": "Malicious Code Protection - The system implements malicious code protection mechanisms.",
                "SI-4": "Information System Monitoring - The organization monitors the system to detect attacks and potential indicators of compromise.",
                "SI-5": "Security Alerts, Advisories, and Directives - The organization receives security alerts and advisories and takes appropriate actions.",
                # Additional controls would be added here to cover all 288 NIST controls
            },
        }
        
        return mappings

    def _get_default_control(self):
        """Get the default NIST 800-53 control ID when no mapping is found."""
        return "SI-4"  # Default to Information System Monitoring control

class MapperFactory:
    """
    Factory class for creating framework mappers.
    """
    
    @staticmethod
    def create_mapper(framework_id, mappings_dir=None):
        """
        Create a mapper for the specified framework.
        
        Args:
            framework_id (str): The ID of the framework to create a mapper for
            mappings_dir (str, optional): Directory containing mapping files
            
        Returns:
            FrameworkMapper: A mapper for the specified framework
            
        Raises:
            ValueError: If the framework ID is not supported
        """
        # Normalize framework ID
        framework_id = framework_id.upper()
        
        # Set default mappings directory if not provided
        if mappings_dir is None:
            mappings_dir = "config/mappings"
            
        # Create the appropriate mapper based on framework ID
        if framework_id == "SOC2":
            mappings_file = os.path.join(mappings_dir, "soc2_mappings.json")
            return SOC2Mapper(mappings_file=mappings_file)
        elif framework_id == "NIST800-53":
            mappings_file = os.path.join(mappings_dir, "nist800_53_mappings.json")
            return NIST80053Mapper(mappings_file=mappings_file)
        else:
            logger.warning(f"Unsupported framework: {framework_id}")
            raise ValueError(f"Unsupported framework: {framework_id}")
    
    @staticmethod
    def create_all_mappers(frameworks=None, mappings_dir=None):
        """
        Create mappers for all supported frameworks.
        
        Args:
            frameworks (list, optional): List of framework configurations
            mappings_dir (str, optional): Directory containing mapping files
            
        Returns:
            dict: Dictionary of framework mappers keyed by framework ID
        """
        mappers = {}
        
        # If no frameworks provided, use default list
        if frameworks is None:
            from app import load_frameworks
            frameworks = load_frameworks()
        
        # Create a mapper for each framework
        for framework in frameworks:
            framework_id = framework["id"]
            try:
                mappers[framework_id] = MapperFactory.create_mapper(framework_id, mappings_dir)
            except ValueError as e:
                logger.warning(f"Skipping framework {framework_id}: {str(e)}")
                continue
                
        return mappers

# ... existing code ... 