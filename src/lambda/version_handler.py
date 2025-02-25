"""
Lambda function for managing function versioning.

This handler is used as a CloudFormation custom resource to provide
consistent version tracking for the SecurityHub Analyzer Lambda function.
"""

import json
import logging
import os
import time
import boto3
import traceback
from botocore.exceptions import ClientError
from . import cfnresponse  # Use relative import

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Add retry mechanism for operations
def retry_operation(operation, max_attempts=5, initial_delay=1, backoff_factor=2):
    """
    Retry an operation with exponential backoff.
    
    Args:
        operation: Function to retry
        max_attempts: Maximum number of retry attempts
        initial_delay: Initial delay between retries in seconds
        backoff_factor: Factor to increase delay with each retry
        
    Returns:
        Result of the operation if successful
        
    Raises:
        Last exception encountered if all retries fail
    """
    last_exception = None
    delay = initial_delay
    
    for attempt in range(max_attempts):
        try:
            return operation()
        except Exception as e:
            last_exception = e
            if attempt == max_attempts - 1:
                # This was the last attempt
                raise
            
            logger.warning(f"Operation failed (attempt {attempt+1}/{max_attempts}): {str(e)}")
            logger.warning(f"Retrying in {delay} seconds...")
            time.sleep(delay)
            delay *= backoff_factor
    
    # If we get here, all retries failed
    if last_exception:
        raise last_exception
    raise Exception("All retry attempts failed")


def lambda_handler(event, context):
    """
    Custom resource handler for managing Lambda versions.

    Creates a new version of the specified Lambda function and returns
    the version identifier, allowing for version tracking in environment variables.

    Args:
        event: CloudFormation custom resource event
        context: Lambda context object

    Returns:
        None: Sends response to CloudFormation via cfnresponse module
    """
    # Get the function name from environment variables
    function_name = os.environ.get("FUNCTION_NAME")

    if not function_name:
        error_msg = "FUNCTION_NAME environment variable is not set"
        logger.error(error_msg)
        cfnresponse.send(event, context, cfnresponse.FAILED, {"Error": error_msg})
        return

    logger.info(f"Received event: {json.dumps(event)}")

    request_type = event["RequestType"]

    try:
        if request_type == "Create" or request_type == "Update":
            # Initialize boto3 client
            lambda_client = boto3.client("lambda")

            # Create a new function version with retry
            logger.info(f"Publishing new version for function: {function_name}")
            
            # Add a small delay to ensure log group is fully created
            logger.info("Waiting briefly for log group availability...")
            time.sleep(3)
            
            # Use retry for publish_version operation
            response = retry_operation(
                lambda: lambda_client.publish_version(
                    FunctionName=function_name,
                    Description=f"Version created at {time.time()}",
                )
            )

            version = response.get("Version")

            # Get function configuration to verify the version exists, with retry
            retry_operation(
                lambda: lambda_client.get_function_configuration(
                    FunctionName=function_name, Qualifier=version
                )
            )

            logger.info(f"Successfully published version {version} for {function_name}")

            # Send success response with version
            cfnresponse.send(
                event,
                context,
                cfnresponse.SUCCESS,
                {"Version": version},
                physicalResourceId=f"{function_name}:{version}",
            )

        elif request_type == "Delete":
            # Nothing to do for delete, as Lambda versions can't be deleted
            logger.info(f"Delete request for {function_name}, no action needed")
            cfnresponse.send(
                event,
                context,
                cfnresponse.SUCCESS,
                {"Message": "No action needed for Delete"},
            )

    except Exception as e:
        error_msg = str(e)
        stack_trace = traceback.format_exc()
        logger.error(f"Error: {error_msg}")
        logger.error(f"Stack trace: {stack_trace}")
        
        # More detailed error information for debugging
        error_info = {
            "Error": error_msg,
            "StackTrace": stack_trace,
            "FunctionName": function_name,
            "RequestType": request_type
        }
        
        cfnresponse.send(event, context, cfnresponse.FAILED, error_info)
