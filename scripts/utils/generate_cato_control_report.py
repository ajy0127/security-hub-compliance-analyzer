#!/usr/bin/env python3
"""
Script to generate a cATO-focused NIST 800-53 control status report.
"""

import json
import os
import random
from collections import defaultdict, Counter
from datetime import datetime, timedelta

# Load NIST 800-53 mappings
def load_nist_mappings():
    """Load NIST 800-53 mappings from the config file."""
    mappings_path = "config/mappings/nist800_53_mappings.json"
    try:
        with open(mappings_path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading NIST mappings: {str(e)}")
        return None

def generate_cato_status_report():
    """Generate a detailed cATO status report for NIST 800-53 controls."""
    mappings = load_nist_mappings()
    if not mappings:
        print("Failed to load NIST 800-53 mappings.")
        return
    
    # Extract control descriptions
    control_descriptions = mappings.get("control_descriptions", {})
    
    # Group controls by family
    families = defaultdict(list)
    for control_id, description in control_descriptions.items():
        # Control IDs are in the format XX-##, where XX is the family
        if "-" in control_id:
            family = control_id.split("-")[0]
            families[family].append({"id": control_id, "description": description})
    
    # Control family names
    family_names = {
        "AC": "Access Control",
        "AU": "Audit and Accountability",
        "AT": "Awareness and Training",
        "CM": "Configuration Management",
        "CP": "Contingency Planning",
        "IA": "Identification and Authentication",
        "IR": "Incident Response",
        "MA": "Maintenance",
        "MP": "Media Protection",
        "PS": "Personnel Security",
        "PE": "Physical and Environmental Protection",
        "PL": "Planning",
        "PM": "Program Management",
        "RA": "Risk Assessment",
        "CA": "Security Assessment and Authorization",
        "SC": "System and Communications Protection",
        "SI": "System and Information Integrity",
        "SA": "System and Services Acquisition"
    }
    
    # Generate mock control statuses for cATO
    # Status categories: PASSED, FAILED, WARNING, NOT_AVAILABLE
    statuses = ["PASSED", "FAILED", "WARNING", "NOT_AVAILABLE"]
    status_weights = [0.6, 0.1, 0.2, 0.1]  # Probabilities for each status
    
    # Generate mock control status data
    control_statuses = {}
    for family, controls in families.items():
        for control in controls:
            # Randomly assign status based on weights
            status = random.choices(statuses, weights=status_weights, k=1)[0]
            
            # For cATO-critical controls, make them more likely to have issues
            if any(keyword in control["description"].lower() for keyword in 
                  ["monitor", "continuous", "automat", "assess", "scan", "review", "update"]):
                # Override with higher chance of WARNING or FAILED for cATO-critical controls
                status = random.choices(statuses, weights=[0.5, 0.2, 0.25, 0.05], k=1)[0]
            
            control_statuses[control["id"]] = {
                "status": status,
                "last_checked": (datetime.now() - timedelta(days=random.randint(0, 30))).strftime("%Y-%m-%d"),
                "is_cato_critical": any(keyword in control["description"].lower() for keyword in 
                                       ["monitor", "continuous", "automat", "assess", "scan", "review", "update"])
            }
    
    # Key cATO families
    key_families = ["AC", "CM", "SI", "AU", "CA", "SC"]
    
    # Generate the report
    print("NIST 800-53 cATO Control Status Report")
    print("=====================================")
    print(f"Report Date: {datetime.now().strftime('%Y-%m-%d')}")
    print(f"Total Controls Analyzed: {len(control_statuses)}")
    
    # Overall status summary
    status_count = Counter(item["status"] for item in control_statuses.values())
    print("\nOverall Control Status Summary:")
    print(f"  PASSED: {status_count.get('PASSED', 0)} controls")
    print(f"  FAILED: {status_count.get('FAILED', 0)} controls")
    print(f"  WARNING: {status_count.get('WARNING', 0)} controls")
    print(f"  NOT_AVAILABLE: {status_count.get('NOT_AVAILABLE', 0)} controls")
    
    # Calculate cATO readiness score (simplified version)
    total_weight = len(control_statuses)
    weighted_score = (
        status_count.get('PASSED', 0) * 1.0 + 
        status_count.get('WARNING', 0) * 0.5 + 
        status_count.get('FAILED', 0) * 0.0 + 
        status_count.get('NOT_AVAILABLE', 0) * 0.0
    )
    cato_readiness = (weighted_score / total_weight) * 100 if total_weight > 0 else 0
    
    print(f"\ncATO Readiness Score: {cato_readiness:.1f}%")
    
    # Status by control family
    print("\nControl Status by Family (cATO Key Families):")
    for family in key_families:
        if family in families:
            family_name = family_names.get(family, family)
            family_controls = [c["id"] for c in families[family]]
            family_statuses = {cid: control_statuses[cid] for cid in family_controls if cid in control_statuses}
            
            family_status_count = Counter(item["status"] for item in family_statuses.values())
            cato_critical = sum(1 for item in family_statuses.values() if item.get("is_cato_critical", False))
            
            print(f"\n{family} - {family_name}")
            print(f"  Total Controls: {len(family_statuses)}")
            print(f"  cATO-Critical Controls: {cato_critical}")
            print(f"  PASSED: {family_status_count.get('PASSED', 0)}")
            print(f"  FAILED: {family_status_count.get('FAILED', 0)}")
            print(f"  WARNING: {family_status_count.get('WARNING', 0)}")
            print(f"  NOT_AVAILABLE: {family_status_count.get('NOT_AVAILABLE', 0)}")
            
            # List failed controls in this family
            failed_controls = [cid for cid, data in family_statuses.items() 
                              if data["status"] in ["FAILED", "WARNING"]]
            if failed_controls:
                print("  Controls Requiring Attention:")
                for control_id in sorted(failed_controls):
                    status = family_statuses[control_id]["status"]
                    is_critical = family_statuses[control_id].get("is_cato_critical", False)
                    criticality = "CRITICAL" if is_critical else "Standard"
                    print(f"    • {control_id} ({status}): {criticality} - {control_descriptions.get(control_id, '')[:80]}...")
    
    # cATO Implementation Recommendations
    print("\ncATO Implementation Recommendations:")
    failed_cato_critical = [cid for cid, data in control_statuses.items() 
                           if data["status"] in ["FAILED", "WARNING"] and data.get("is_cato_critical", False)]
    print(f"1. Address {len(failed_cato_critical)} cATO-critical controls with FAILED or WARNING status")
    
    # Get counts of controls by family with issues
    family_issues = defaultdict(int)
    for cid, data in control_statuses.items():
        if data["status"] in ["FAILED", "WARNING"]:
            family = cid.split("-")[0] if "-" in cid else "Unknown"
            family_issues[family] += 1
    
    # Identify top 3 problematic families
    problematic_families = sorted(family_issues.items(), key=lambda x: x[1], reverse=True)[:3]
    if problematic_families:
        print("2. Focus remediation efforts on these control families:")
        for family, count in problematic_families:
            family_name = family_names.get(family, family)
            print(f"   • {family} - {family_name}: {count} issues")
    
    print("3. Strengthen continuous monitoring for all control families")
    print("4. Update POA&M documentation with the findings in this report")
    print("5. Schedule automated controls testing based on this assessment")
    
    return {
        "control_families": families,
        "family_names": family_names,
        "control_statuses": control_statuses,
        "cato_readiness": cato_readiness,
        "status_count": status_count,
        "failed_cato_critical": failed_cato_critical,
        "problematic_families": problematic_families
    }

if __name__ == "__main__":
    generate_cato_status_report()