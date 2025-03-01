#!/usr/bin/env python3
"""
Script to invoke the SecurityHub Compliance Analyzer Lambda with a specific AWS profile.
"""

import json
import boto3
import argparse
import os

def invoke_lambda(profile_name, email, hours=24, framework="NIST800-53"):
    """
    Invoke the Lambda function with the provided parameters using a specific AWS profile.
    """
    # Create a session with the specified profile
    session = boto3.Session(profile_name=profile_name)
    
    # Create Lambda client using the session
    lambda_client = session.client('lambda')
    
    # Check environment for Lambda function name
    lambda_function_name = os.environ.get("LAMBDA_FUNCTION_NAME", "SecurityHubComplianceAnalyzer")
    
    # Prepare payload
    payload = {
        "email": email,
        "framework": framework,
        "hours": int(hours),
        "generate_csv": True,
        "combined_analysis": False
    }
    
    print(f"Invoking Lambda function '{lambda_function_name}' with profile '{profile_name}'")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    # Invoke Lambda function
    try:
        response = lambda_client.invoke(
            FunctionName=lambda_function_name,
            InvocationType='RequestResponse',  # Synchronous invocation
            Payload=json.dumps(payload)
        )
        
        # Parse and print response
        response_payload = json.loads(response['Payload'].read().decode('utf-8'))
        print("\nLambda Response:")
        print(json.dumps(response_payload, indent=2))
        
        # Save the response to a file
        with open("lambda_response.json", "w") as f:
            json.dump(response_payload, f, indent=2)
        print(f"Response saved to lambda_response.json")
        
        return response_payload
        
    except Exception as e:
        print(f"Error invoking Lambda function: {str(e)}")
        return {"statusCode": 500, "body": f"Error: {str(e)}"}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Invoke SecurityHub Compliance Analyzer Lambda")
    parser.add_argument("--profile", required=True, help="AWS profile name to use")
    parser.add_argument("--email", required=True, help="Email address to send the report to")
    parser.add_argument("--hours", default=24, type=int, help="Number of hours to look back for findings")
    parser.add_argument("--framework", default="NIST800-53", help="Compliance framework to analyze")
    
    args = parser.parse_args()
    
    invoke_lambda(args.profile, args.email, args.hours, args.framework)