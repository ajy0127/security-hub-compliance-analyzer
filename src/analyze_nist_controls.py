#!/usr/bin/env python3
"""
Script to analyze NIST 800-53 controls and their organization by control family.
"""

import json
import os
import re
from collections import defaultdict


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


def analyze_control_families():
    """Analyze NIST 800-53 controls by family."""
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
        "SA": "System and Services Acquisition",
    }

    # Print control families and counts
    print("NIST 800-53 Control Families Analysis")
    print("====================================")

    # Sort families by control count (descending)
    sorted_families = sorted(families.items(), key=lambda x: len(x[1]), reverse=True)

    # Print statistics
    total_controls = sum(len(controls) for _, controls in sorted_families)
    print(f"Total Controls: {total_controls}")
    print(f"Control Families: {len(sorted_families)}")
    print("\nControl Distribution by Family:")
    print("-------------------------------")

    for family, controls in sorted_families:
        family_name = family_names.get(family, f"Unknown Family ({family})")
        print(f"{family} - {family_name}: {len(controls)} controls")

        # Print the first 3 controls as examples
        for i, control in enumerate(sorted(controls, key=lambda x: x["id"])):
            if i < 3:  # Only show 3 examples per family
                print(f"  • {control['id']}: {control['description'][:100]}...")
        print()

    # Analysis for cATO groupings
    print("\nContinuous ATO (cATO) Key Control Families:")
    print("------------------------------------------")
    key_families = ["AC", "CM", "SI", "AU", "CA", "SC"]
    for family in key_families:
        if family in families:
            family_name = family_names.get(family, f"Unknown Family ({family})")
            controls = families[family]
            print(f"{family} - {family_name}: {len(controls)} controls")
            print(
                f"  cATO Relevance: High - Critical for maintaining ongoing authorization"
            )

            # Print a few example controls critical for cATO
            cato_critical = []
            for control in controls:
                # Look for keywords indicative of continuous monitoring/assessment
                if any(
                    keyword in control["description"].lower()
                    for keyword in [
                        "monitor",
                        "continuous",
                        "automat",
                        "assess",
                        "scan",
                        "review",
                        "update",
                    ]
                ):
                    cato_critical.append(control)

            print(f"  cATO-Critical Controls: {len(cato_critical)} of {len(controls)}")
            for i, control in enumerate(sorted(cato_critical, key=lambda x: x["id"])):
                if i < 2:  # Show just 2 examples
                    print(f"  • {control['id']}: {control['description'][:100]}...")
            print()


if __name__ == "__main__":
    analyze_control_families()
