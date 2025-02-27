"""NIST 800-53 framework mapper for AWS SecurityHub compliance framework mappings."""

import os
from pathlib import Path

from src.framework_mapper import FrameworkMapper


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
            default_mappings = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "config",
                "mappings",
                "nist800_53_mappings.json"
            )
            mappings_file = default_mappings

        # Initialize the base class with NIST800-53 framework ID
        super().__init__("NIST800-53", mappings_file)

    def _get_default_mappings(self):
        """Provide default NIST 800-53 control mappings if configuration file is not available."""
        return {
            # Map SecurityHub finding types to NIST 800-53 controls
            "type_mappings": {
                "Software and Configuration Checks": ["AC-3", "AC-6", "SI-2"],
                "Vulnerabilities": ["RA-5", "SI-2", "SI-3"],
                "Effects": ["SI-4", "SI-5"],
                "Software and Configuration Checks/Industry and Regulatory Standards": ["CM-2", "CM-6", "CM-7"],
                "Sensitive Data Identifications": ["SC-8", "SC-28", "MP-4"],
                "Network Reachability": ["SC-7", "AC-4", "AC-17"],
                "Unusual Behaviors": ["SI-4", "AU-6"],
                "Policy": ["PL-1", "CA-1", "CM-1"]
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
                "monitor": ["AU-6", "SI-4"]
            },
            # NIST 800-53 control descriptions for context and reporting
            "control_descriptions": {
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
                "SI-5": "Security Alerts, Advisories, and Directives - The organization receives security alerts and advisories and takes appropriate actions."
            },
        }

    def _get_default_control(self):
        """Get the default NIST 800-53 control ID when no mapping is found."""
        return "SI-4"  # Default to Information System Monitoring control