#!/usr/bin/env python3
"""
Directly invoke the Lambda function to send a NIST 800-53 report.
"""

import boto3
import json
import argparse


def invoke_lambda(profile_name, email, framework="NIST800-53"):
    """Directly invoke the Lambda function."""

    # Create a session with the specified profile
    session = boto3.Session(profile_name=profile_name)

    # Create Lambda client
    lambda_client = session.client("lambda")

    # Lambda function name
    function_name = "security-hub-compliance-analyzer-SecurityHubAnalyzer"

    # Create payload
    payload = {"email": email, "framework": framework, "hours": 24}

    print(f"Invoking Lambda function {function_name}")
    print(f"Payload: {json.dumps(payload, indent=2)}")

    # Invoke Lambda
    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload),
        )

        # Read the response
        response_payload = json.loads(response["Payload"].read().decode("utf-8"))

        print(f"Lambda execution status: {response['StatusCode']}")
        print(f"Response: {json.dumps(response_payload, indent=2)}")

        # Save response to file
        with open("direct_lambda_response.json", "w") as f:
            json.dump(response_payload, f, indent=2)

        print("Response saved to direct_lambda_response.json")

        return response_payload

    except Exception as e:
        print(f"Error invoking Lambda: {str(e)}")
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Directly invoke Lambda to send email report"
    )
    parser.add_argument("--profile", default="sandbox", help="AWS profile name to use")
    parser.add_argument(
        "--email", required=True, help="Email address to send the report to"
    )
    parser.add_argument(
        "--framework",
        default="NIST800-53",
        help="Framework to analyze (SOC2, NIST800-53, or 'all')",
    )

    args = parser.parse_args()

    invoke_lambda(args.profile, args.email, args.framework)
