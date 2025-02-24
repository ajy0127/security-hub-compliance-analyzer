"""
Finding deduplication utilities for SecurityHub findings.

This module provides functionality to deduplicate similar Security Hub 
findings based on various criteria, reducing alert fatigue and noise.
"""

import hashlib
import logging
from typing import Dict, List, Set, Tuple, Any

from src.utils.logging_utils import get_logger

# Initialize logger
logger = get_logger(__name__)


def generate_finding_hash(finding: Dict[str, Any]) -> str:
    """
    Generate a stable hash for a finding based on key attributes.
    
    Creates a consistent fingerprint for a finding using its important attributes
    for deduplication purposes.
    
    Args:
        finding: SecurityHub finding dictionary
        
    Returns:
        Hash string representing the finding's fingerprint
    """
    # Extract key components for hashing
    resource_id = finding.get("ResourceId", "")
    resource_type = finding.get("ResourceType", "")
    title = finding.get("Title", "")
    # TruncatedDescription : Use first 100 chars to catch similar issues
    description = finding.get("Description", "")[:100] if finding.get("Description") else ""
    
    # Create a stable fingerprint string
    fingerprint = f"{resource_type}:{resource_id}:{title}:{description}"
    
    # Create hash
    return hashlib.md5(fingerprint.encode('utf-8')).hexdigest()


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate findings based on various criteria.
    
    Combines multiple strategies to reduce redundant alerts:
    1. Resource-based deduplication (same issue on same resource)
    2. Title-based deduplication (same issue type across resources)
    3. Exception handling for critical findings (never deduplicate)
    
    Args:
        findings: List of SecurityHub finding dictionaries
        
    Returns:
        Deduplicated list of findings
    """
    if not findings:
        return []
    
    unique_findings = []
    seen_hashes = set()
    
    # Track finding counts for logging
    total_findings = len(findings)
    duplicate_count = 0
    critical_count = 0
    
    # First pass - identify and keep all critical findings
    for finding in findings:
        if finding.get("Severity") == "CRITICAL":
            unique_findings.append(finding)
            critical_count += 1
            # Add hash to seen to prevent duplicates in second pass
            finding_hash = generate_finding_hash(finding)
            seen_hashes.add(finding_hash)
    
    # Second pass - process non-critical findings with deduplication
    for finding in findings:
        if finding.get("Severity") != "CRITICAL":
            finding_hash = generate_finding_hash(finding)
            
            if finding_hash not in seen_hashes:
                unique_findings.append(finding)
                seen_hashes.add(finding_hash)
            else:
                duplicate_count += 1
                
                # Add a reference to indicate duplicates exist
                for unique_finding in unique_findings:
                    unique_hash = generate_finding_hash(unique_finding)
                    if unique_hash == finding_hash:
                        # Update duplicate count if it exists, otherwise set to 1
                        if "duplicate_count" in unique_finding:
                            unique_finding["duplicate_count"] += 1
                        else:
                            unique_finding["duplicate_count"] = 1
    
    # Log deduplication results
    logger.info(
        f"Deduplication complete: {total_findings} total, {len(unique_findings)} unique findings",
        duplicate_count=duplicate_count, 
        critical_count=critical_count
    )
    
    return unique_findings


def group_related_findings(findings: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """
    Group related findings together based on resource or issue type.
    
    Identifies findings that are related to the same underlying issue or resource,
    which helps provide a more holistic view of security posture.
    
    Args:
        findings: List of SecurityHub finding dictionaries
        
    Returns:
        List of finding groups (each group is a list of related findings)
    """
    # Maps resource IDs to all findings related to that resource
    resource_groups: Dict[str, List[Dict[str, Any]]] = {}
    
    # Maps finding types to all findings of that type
    type_groups: Dict[str, List[Dict[str, Any]]] = {}
    
    # First, group by resource
    for finding in findings:
        resource_id = finding.get("ResourceId", "unknown")
        
        if resource_id not in resource_groups:
            resource_groups[resource_id] = []
            
        resource_groups[resource_id].append(finding)
    
    # Second, group by finding type
    for finding in findings:
        finding_type = finding.get("Type", "unknown")
        
        if finding_type not in type_groups:
            type_groups[finding_type] = []
            
        type_groups[finding_type].append(finding)
    
    # Build final groups based on both resource and type relationships
    final_groups = []
    processed_findings: Set[str] = set()
    
    # Process resource groups first
    for resource_id, resource_findings in resource_groups.items():
        if len(resource_findings) > 1:  # Only consider groups with multiple findings
            group = []
            for finding in resource_findings:
                finding_id = finding.get("Id", "")
                if finding_id and finding_id not in processed_findings:
                    group.append(finding)
                    processed_findings.add(finding_id)
            
            if group:
                final_groups.append(group)
    
    # Then process type groups
    for finding_type, type_findings in type_groups.items():
        if len(type_findings) > 1:  # Only consider groups with multiple findings
            group = []
            for finding in type_findings:
                finding_id = finding.get("Id", "")
                if finding_id and finding_id not in processed_findings:
                    group.append(finding)
                    processed_findings.add(finding_id)
            
            if group:
                final_groups.append(group)
    
    # Add any remaining unprocessed findings as single-item groups
    for finding in findings:
        finding_id = finding.get("Id", "")
        if finding_id and finding_id not in processed_findings:
            final_groups.append([finding])
            processed_findings.add(finding_id)
    
    logger.info(
        f"Grouped {len(findings)} findings into {len(final_groups)} groups",
        group_sizes=[len(group) for group in final_groups]
    )
    
    return final_groups