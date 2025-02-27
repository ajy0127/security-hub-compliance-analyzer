#!/usr/bin/env python3
"""Simple test script for running the analyzer directly."""

import os
import sys
import json
from datetime import datetime

# Set path to include project root
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(project_root)

# Set default environment variables for testing
os.environ["SENDER_EMAIL"] = "your-verified-email@example.com"
os.environ["RECIPIENT_EMAIL"] = "your-email@example.com"
os.environ["BEDROCK_MODEL_ID"] = "anthropic.claude-3-sonnet"
os.environ["FINDINGS_HOURS"] = "24"
os.environ["DEFAULT_FRAMEWORK"] = "all"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"  # Set a default AWS region

# Create a test event for multi-framework analysis
test_event = {
    "framework": "all",
    "combined_analysis": True,
    "hours": 24,
    "email": "your-verified-email@example.com"
}

print("=" * 80)
print(f"AWS SecurityHub Multi-Framework Compliance Analyzer - Test Run")
print(f"Started at {datetime.now().isoformat()}")
print("=" * 80)

print("Testing with event:", json.dumps(test_event, indent=2))
print("\nEnvironment variables:")
print(f"  SENDER_EMAIL: {os.environ.get('SENDER_EMAIL')}")
print(f"  RECIPIENT_EMAIL: {os.environ.get('RECIPIENT_EMAIL')}")
print(f"  BEDROCK_MODEL_ID: {os.environ.get('BEDROCK_MODEL_ID')}")
print(f"  FINDINGS_HOURS: {os.environ.get('FINDINGS_HOURS')}")
print(f"  DEFAULT_FRAMEWORK: {os.environ.get('DEFAULT_FRAMEWORK')}")

try:
    # Import lambda_handler after setting up environment
    from src.app import lambda_handler
    
    # Call the lambda handler
    print("\nInvoking Lambda handler...")
    result = lambda_handler(test_event, {})
    print("\nResult:", json.dumps(result, indent=2))
    print("\nTest completed successfully!")
    
except Exception as e:
    import traceback
    print(f"\nError: {str(e)}")
    traceback.print_exc()
    print("\nTest failed!")
    sys.exit(1)