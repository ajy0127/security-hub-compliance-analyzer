"""
Test script to run the NIST 800-53 email functionality locally.
"""

import json
import os
from src.app import lambda_handler

# Set environment variables needed for the function
os.environ["SENDER_EMAIL"] = "your-verified-email@example.com"
os.environ["RECIPIENT_EMAIL"] = "your-verified-email@example.com"
os.environ["BEDROCK_MODEL_ID"] = "anthropic.claude-3-sonnet"  # Use your model of choice

# Create a NIST 800-53 specific event
event = {
    "framework": "NIST800-53",  # Specify NIST 800-53 framework
    "hours": 24,  # Look for findings from the last 24 hours
    "email": os.environ["RECIPIENT_EMAIL"],  # Use the same email for sending/receiving
    "generate_csv": True,  # Generate CSV files for findings
    "combined_analysis": False,  # We only want NIST-specific analysis
}

# Call the Lambda handler function
response = lambda_handler(event, None)

# Print the response
print(json.dumps(response, indent=2))

# Save the response to a file for reference
with open("nist_response.json", "w") as f:
    json.dump(response, f, indent=2)

print(f"Test completed. Response saved to nist_response.json")
