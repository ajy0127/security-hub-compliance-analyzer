#!/usr/bin/env python3
"""
Local test script for NIST 800-53 email generation.
"""

import json
import os

import boto3

from src.app import generate_nist_cato_report, get_nist_control_status, send_email


def test_email_generation(recipient_email):
    """Generate and send a test NIST 800-53 cATO report email."""
    print(f"Generating NIST 800-53 cATO report for email to {recipient_email}")

    # Set the environment variable for sender email
    os.environ["SENDER_EMAIL"] = recipient_email

    try:
        # Get control status data
        print("Getting NIST 800-53 control status...")
        controls = get_nist_control_status()
        print(f"Retrieved {len(controls)} controls")

        # Generate the report
        print("Generating cATO report...")
        report_text, stats, control_families = generate_nist_cato_report()

        # Print report summary
        print(f"\nReport Statistics:")
        print(f"Total Controls: {stats.get('total', 0)}")
        print(f"Passed: {stats.get('passed', 0)}")
        print(f"Failed: {stats.get('failed', 0)}")
        print(f"Unknown: {stats.get('unknown', 0)}")
        print(f"Compliance %: {stats.get('compliance_percentage', 0):.1f}%")

        print(f"\nControl Families: {len(control_families)}")

        # Set up analyses and findings structure
        framework_id = "NIST800-53"
        analyses = {framework_id: report_text}
        findings = {framework_id: []}  # Empty list as placeholder

        # Set up stats dictionary in the format expected by send_email
        email_stats = {
            framework_id: {
                "total": stats.get("total", 0),
                "critical": stats.get("critical", 0),
                "high": stats.get("high", 0),
                "medium": stats.get("medium", 0),
                "low": stats.get("low", 0),
                # Add cATO specific stats
                "passed": stats.get("passed", 0),
                "failed": stats.get("failed", 0),
                "unknown": stats.get("unknown", 0),
                "not_applicable": stats.get("not_applicable", 0),
                "compliance_percentage": stats.get("compliance_percentage", 0),
            }
        }

        # Set up a minimal mappers dictionary
        mappers = {}

        # Send the email
        print("Sending email...")
        success = send_email(
            recipient_email=recipient_email,
            findings=findings,
            analyses=analyses,
            stats=email_stats,
            mappers=mappers,
            nist_control_families=control_families,
        )

        if success:
            print(f"Email sent successfully to {recipient_email}")
        else:
            print(f"Failed to send email to {recipient_email}")

    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Test NIST 800-53 email generation locally"
    )
    parser.add_argument(
        "--email", required=True, help="Email address to send the report to"
    )

    args = parser.parse_args()

    test_email_generation(args.email)
