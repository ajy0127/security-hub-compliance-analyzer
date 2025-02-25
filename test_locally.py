#!/usr/bin/env python3
"""
Test script for running the SecurityHub SOC 2 Email Reporter locally.
This script simulates the Lambda environment and calls the handler function.
"""

import json
import os
import sys
from datetime import datetime

# Set environment variables for testing
os.environ['SENDER_EMAIL'] = 'your-verified-email@example.com'
os.environ['RECIPIENT_EMAIL'] = 'your-email@example.com'
os.environ['BEDROCK_MODEL_ID'] = 'anthropic.claude-3-sonnet'
os.environ['FINDINGS_HOURS'] = '24'

# Import the Lambda handler
try:
    from app import lambda_handler
except ImportError:
    print("Error: Could not import lambda_handler from app.py")
    print("Make sure you're running this script from the project root directory.")
    sys.exit(1)

def load_test_event():
    """Load test event from test-event.json or create a default one."""
    try:
        with open('test-event.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("Warning: test-event.json not found, using default test event")
        return {"test_email": True}
    except json.JSONDecodeError:
        print("Error: test-event.json is not valid JSON")
        sys.exit(1)

def main():
    """Run the Lambda handler with a test event."""
    print(f"Starting local test at {datetime.now().isoformat()}")
    print("Environment variables:")
    print(f"  SENDER_EMAIL: {os.environ.get('SENDER_EMAIL')}")
    print(f"  RECIPIENT_EMAIL: {os.environ.get('RECIPIENT_EMAIL')}")
    print(f"  BEDROCK_MODEL_ID: {os.environ.get('BEDROCK_MODEL_ID')}")
    print(f"  FINDINGS_HOURS: {os.environ.get('FINDINGS_HOURS')}")
    
    # Check if environment variables are set
    if os.environ.get('SENDER_EMAIL') == 'your-verified-email@example.com':
        print("\nWARNING: You need to update the SENDER_EMAIL in this script!")
        print("The email must be verified in Amazon SES.")
    
    if os.environ.get('RECIPIENT_EMAIL') == 'your-email@example.com':
        print("\nWARNING: You need to update the RECIPIENT_EMAIL in this script!")
    
    # Load test event
    event = load_test_event()
    print(f"\nTest event: {json.dumps(event, indent=2)}")
    
    # Ask for confirmation
    if input("\nReady to run the test? (y/n): ").lower() != 'y':
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

if __name__ == "__main__":
    main() 