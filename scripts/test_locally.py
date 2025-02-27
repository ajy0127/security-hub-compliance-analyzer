#!/usr/bin/env python3
"""Test Script for AWS SecurityHub SOC2 Compliance Analyzer locally."""

import argparse
import json
import os
import sys
from datetime import datetime

# Set default environment variables for testing
os.environ["SENDER_EMAIL"] = "your-verified-email@example.com"
os.environ["RECIPIENT_EMAIL"] = "your-email@example.com"
os.environ["BEDROCK_MODEL_ID"] = "anthropic.claude-3-sonnet"
os.environ["FINDINGS_HOURS"] = "24"

# Get the project root and add to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

# Import the Lambda handler function
try:
    from src.app import lambda_handler
except ImportError:
    print("Error: Could not import lambda_handler from src/app.py")
    print(
        "Make sure the project structure is correct and this script is in the scripts directory."
    )
    sys.exit(1)


def load_test_event(event_type=None, custom_path=None):
    """Load a test event from a file or create one based on the specified type."""
    # If a custom path is provided, load from that file
    if custom_path:
        try:
            with open(custom_path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: Custom event file {custom_path} not found")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Error: Custom event file {custom_path} is not valid JSON")
            sys.exit(1)

    # If a specific event type is requested, create that event
    if event_type:
        if event_type == "test_email":
            return {"test_email": True}
        elif event_type == "report_24h":
            return {}  # Default is 24 hours
        elif event_type == "report_7d":
            return {"hours": 168}  # 7 days * 24 hours
        elif event_type == "report_soc2":
            return {"framework": "SOC2"}
        elif event_type == "report_nist":
            return {"framework": "NIST800-53"}
        elif event_type == "report_all":
            return {"framework": "all", "combined_analysis": True}

    # Otherwise, try to load from the default location
    default_path = os.path.join(project_root, "examples", "test-event.json")
    try:
        with open(default_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: {default_path} not found, using default test email event")
        return {"test_email": True}
    except json.JSONDecodeError:
        print(f"Error: {default_path} is not valid JSON")
        sys.exit(1)


def setup_environment(sender_email=None, recipient_email=None, interactive=True):
    """Set up environment variables for testing."""
    # Update environment variables if provided via arguments
    if sender_email:
        os.environ["SENDER_EMAIL"] = sender_email
    if recipient_email:
        os.environ["RECIPIENT_EMAIL"] = recipient_email

    # Print current environment configuration
    print("\nCurrent environment configuration:")
    print(f"  SENDER_EMAIL: {os.environ.get('SENDER_EMAIL')}")
    print(f"  RECIPIENT_EMAIL: {os.environ.get('RECIPIENT_EMAIL')}")
    print(f"  BEDROCK_MODEL_ID: {os.environ.get('BEDROCK_MODEL_ID')}")
    print(f"  FINDINGS_HOURS: {os.environ.get('FINDINGS_HOURS')}")

    # Check if default values are being used and warn user
    if os.environ.get("SENDER_EMAIL") == "your-verified-email@example.com":
        print("\nWARNING: Using default SENDER_EMAIL.")
        print("This email must be verified in Amazon SES for the test to work.")

    if os.environ.get("RECIPIENT_EMAIL") == "your-email@example.com":
        print("\nWARNING: Using default RECIPIENT_EMAIL.")
        print("This email must be verified in Amazon SES for the test to work.")

    # If in interactive mode, offer to update environment variables
    sender_default = os.environ.get("SENDER_EMAIL") == "your-verified-email@example.com"
    recipient_default = os.environ.get("RECIPIENT_EMAIL") == "your-email@example.com"
    if interactive and (sender_default or recipient_default):
        if (
            input(
                "\nWould you like to update the email environment variables? (y/n): "
            ).lower()
            == "y"
        ):
            sender = input("Enter sender email (must be verified in SES): ")
            recipient = input("Enter recipient email (must be verified in SES): ")

            if sender:
                os.environ["SENDER_EMAIL"] = sender
            if recipient:
                os.environ["RECIPIENT_EMAIL"] = recipient

            print("\nUpdated environment configuration:")
            print(f"  SENDER_EMAIL: {os.environ.get('SENDER_EMAIL')}")
            print(f"  RECIPIENT_EMAIL: {os.environ.get('RECIPIENT_EMAIL')}")


def main():
    """Run the Lambda handler with a test event."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Test AWS SecurityHub SOC2 Compliance Analyzer locally"
    )
    parser.add_argument(
        "--event-type",
        choices=["test_email", "report_24h", "report_7d", "report_soc2", "report_nist", "report_all"],
        help="Type of test event to create",
    )
    parser.add_argument(
        "--event-file", help="Path to a JSON file containing a custom test event"
    )
    parser.add_argument(
        "--sender", help="Sender email address (must be verified in SES)"
    )
    parser.add_argument(
        "--recipient", help="Recipient email address (must be verified in SES)"
    )
    parser.add_argument(
        "--non-interactive", action="store_true", help="Run without interactive prompts"
    )
    args = parser.parse_args()

    # Print header information
    print("=" * 80)
    print(f"AWS SecurityHub Multi-Framework Compliance Analyzer - Local Test")
    print(f"Started at {datetime.now().isoformat()}")
    print("=" * 80)

    # Setup environment variables
    setup_environment(
        sender_email=args.sender,
        recipient_email=args.recipient,
        interactive=not args.non_interactive,
    )

    # Load test event
    event = load_test_event(args.event_type, args.event_file)
    print(f"\nTest event: {json.dumps(event, indent=2)}")

    # Ask for confirmation if in interactive mode
    if not args.non_interactive:
        if input("\nReady to run the test? (y/n): ").lower() != "y":
            print("Test cancelled")
            return

    # Run the Lambda handler
    print("\nRunning Lambda handler...")
    try:
        result = lambda_handler(event, {})
        print(f"\nResult: {json.dumps(result, indent=2)}")
        print("\nTest completed successfully!")
    except Exception as e:
        print(f"\nError: {str(e)}")
        import traceback

        traceback.print_exc()
        print("\nTest failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
