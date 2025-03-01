#!/usr/bin/env python3
"""
=============================================================================
Test script for NIST 800-53 control status functions

This script:
1. Tests the get_nist_control_status function to retrieve control data
2. Tests the generate_nist_cato_report function to create formatted reports
3. Saves the results to files for inspection

Usage:
    ./test_nist_control_functions.py --controls   # Test control retrieval
    ./test_nist_control_functions.py --report     # Test report generation
    ./test_nist_control_functions.py --all        # Test both functions
=============================================================================
"""

import json
import argparse
from src.app import get_nist_control_status, generate_nist_cato_report


def test_get_control_status():
    """Test the get_nist_control_status function."""
    print("Testing get_nist_control_status function...\n")

    try:
        controls = get_nist_control_status()

        if not controls:
            print("No NIST 800-53 controls found or enabled.")
            return

        print(f"Retrieved {len(controls)} NIST 800-53 controls")

        # Print sample of controls (first 5)
        print("\nSample controls:")
        for i, (control_id, control) in enumerate(list(controls.items())[:5]):
            print(f"\nControl {i+1}: {control_id}")
            print(f"  Title: {control.get('title', 'No title')}")
            print(f"  Status: {control.get('status', 'UNKNOWN')}")
            print(f"  Severity: {control.get('severity', 'MEDIUM')}")
            if control.get("disabled", False):
                print("  NOTE: This control is disabled")

        # Save full results to file
        with open("nist_controls.json", "w") as f:
            json.dump(controls, f, indent=2)
        print("\nFull control list saved to nist_controls.json")

        return controls

    except Exception as e:
        print(f"Error testing get_nist_control_status: {str(e)}")
        return None


def test_generate_report(controls=None):
    """Test the generate_nist_cato_report function."""
    print("\nTesting generate_nist_cato_report function...\n")

    try:
        # Get report and statistics
        report_text, stats, control_families = generate_nist_cato_report()

        if not report_text or not stats or not control_families:
            print("Failed to generate NIST 800-53 cATO report.")
            return

        # Print the report
        print(report_text)

        # Print statistics
        print("\nStatistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

        # Print sample of control families
        print("\nControl Families:")
        for i, (family_id, family) in enumerate(list(control_families.items())[:3]):
            print(f"\n  Family: {family_id}")
            print(f"    Controls: {family.get('total', 0)}")
            print(f"    Passed: {family.get('passed', 0)}")
            print(f"    Failed: {family.get('failed', 0)}")
            print(f"    Compliance: {family.get('compliance_percentage', 0):.1f}%")

        # Save results to files
        with open("nist_report.md", "w") as f:
            f.write(report_text)

        with open("nist_stats.json", "w") as f:
            json.dump(stats, f, indent=2)

        with open("nist_families.json", "w") as f:
            # Need to convert the control lists to serializable format
            serializable_families = {}
            for family_id, family in control_families.items():
                serializable_family = family.copy()
                if "controls" in serializable_family:
                    # Only include IDs for serialization
                    serializable_family["control_ids"] = [
                        c.get("id", "unknown") for c in serializable_family["controls"]
                    ]
                    del serializable_family["controls"]
                serializable_families[family_id] = serializable_family

            json.dump(serializable_families, f, indent=2)

        print("\nFiles saved:")
        print("  - nist_report.md - The formatted report text")
        print("  - nist_stats.json - The statistics dictionary")
        print("  - nist_families.json - The control families data")

    except Exception as e:
        print(f"Error testing generate_nist_cato_report: {str(e)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Test NIST 800-53 control status functions"
    )
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument(
        "--controls", action="store_true", help="Test get_nist_control_status"
    )
    parser.add_argument(
        "--report", action="store_true", help="Test generate_nist_cato_report"
    )

    args = parser.parse_args()

    # Default to running all tests if no specific test is specified
    if not (args.controls or args.report):
        args.all = True

    print("NIST 800-53 Control Status Function Tests")
    print("========================================\n")

    controls = None
    if args.all or args.controls:
        controls = test_get_control_status()

    if args.all or args.report:
        test_generate_report(controls)
