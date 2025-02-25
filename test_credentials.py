#!/usr/bin/env python3
"""
Test AWS credentials to verify they work correctly.
"""

import argparse
import sys

import boto3


def test_credentials(profile=None):
    """Test AWS credentials by listing S3 buckets."""
    print(f"Testing AWS credentials" + (f" using profile: {profile}" if profile else ""))

    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        sts = session.client("sts")

        # Get caller identity to verify credentials
        identity = sts.get_caller_identity()
        print(f"AWS Identity: {identity['UserId']} (Account: {identity['Account']})")
        print(f"AWS ARN: {identity['Arn']}")

        # Try listing a simple resource
        s3 = session.client("s3")
        response = s3.list_buckets()

        # Print bucket names
        print("\nAvailable S3 buckets:")
        if len(response["Buckets"]) > 0:
            for bucket in response["Buckets"]:
                print(f"- {bucket['Name']}")
        else:
            print("No S3 buckets found in this account.")

        print("\nCredentials are working correctly!")
        return True

    except Exception as e:
        print(f"\nError testing credentials: {str(e)}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test AWS credentials")
    parser.add_argument("--profile", help="AWS profile name to use")
    args = parser.parse_args()

    success = test_credentials(args.profile)
    sys.exit(0 if success else 1)