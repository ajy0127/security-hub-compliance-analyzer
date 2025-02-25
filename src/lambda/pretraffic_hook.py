"""
Pre-traffic hook for Lambda deployment.

This function is invoked by AWS CodeDeploy before traffic is shifted to the new Lambda version.
It performs validation to ensure the new version is working properly.
"""

import json
import logging
import os
import time
import traceback
import boto3
from botocore.exceptions import ClientError

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
    Pre-traffic hook handler for Lambda deployment.

    Args:
        event: CodeDeploy event with DeploymentId and LifecycleEventHookExecutionId
        context: Lambda context object

    Returns:
        str: Success or failure status
    """
    logger.info(f"Received event: {json.dumps(event)}")

    # Get the function name from environment variables
    function_name = os.environ.get("FUNCTION_NAME")

    # Get deployment details
    deployment_id = event.get("DeploymentId")
    lifecycle_event_hook_execution_id = event.get("LifecycleEventHookExecutionId")

    if not function_name or not deployment_id or not lifecycle_event_hook_execution_id:
        logger.error("Missing required configuration or event parameters")
        put_lifecycle_event_status(
            deployment_id, lifecycle_event_hook_execution_id, "Failed"
        )
        return "Configuration error"

    try:
        # Get the Lambda client
        lambda_client = boto3.client("lambda")

        # Create a test event
        test_event = {
            "test_email": True,
            # This won't send an actual email because it's a dry-run
            "recipient_email": "test@example.com",
        }

        # Add a small delay to ensure log group is fully created
        logger.info("Waiting briefly for log group availability...")
        time.sleep(3)
            
        # Invoke the function in dry-run mode with retry logic
        logger.info(f"Invoking {function_name} for validation")
        response = retry_operation(
            lambda: lambda_client.invoke(
                FunctionName=function_name,
                InvocationType="DryRun",
                Payload=json.dumps(test_event),
            )
        )

        # Check the response status code
        status_code = response.get("StatusCode")
        logger.info(f"Invocation status code: {status_code}")

        if status_code == 204:  # DryRun successful
            logger.info(f"Pre-traffic validation succeeded for {function_name}")
            put_lifecycle_event_status(
                deployment_id, lifecycle_event_hook_execution_id, "Succeeded"
            )
            return "Validation successful"
        else:
            logger.error(
                f"Pre-traffic validation failed: unexpected status code {status_code}"
            )
            put_lifecycle_event_status(
                deployment_id, lifecycle_event_hook_execution_id, "Failed"
            )
            return "Validation failed"

    except Exception as e:
        error_msg = str(e)
        stack_trace = traceback.format_exc()
        logger.error(f"Error during pre-traffic validation: {error_msg}")
        logger.error(f"Stack trace: {stack_trace}")
        
        # More detailed error information for debugging and reporting
        try:
            put_lifecycle_event_status(
                deployment_id, lifecycle_event_hook_execution_id, "Failed"
            )
        except Exception as hook_error:
            logger.error(f"Failed to update hook status after error: {str(hook_error)}")
        
        return f"Validation error: {error_msg}"


def put_lifecycle_event_status(deployment_id, hook_id, status):
    """
    Update the status of the CodeDeploy lifecycle event.

    Args:
        deployment_id: CodeDeploy deployment ID
        hook_id: Lifecycle event hook execution ID
        status: Status to report ('Succeeded' or 'Failed')
    """
    try:
        codedeploy = boto3.client("codedeploy")
        # Use retry for CodeDeploy status update
        retry_operation(
            lambda: codedeploy.put_lifecycle_event_hook_execution_status(
                deploymentId=deployment_id,
                lifecycleEventHookExecutionId=hook_id,
                status=status,
            )
        )
        logger.info(f"Reported hook status {status} for deployment {deployment_id}")
    except Exception as e:
        error_msg = str(e)
        stack_trace = traceback.format_exc()
        logger.error(f"Error reporting hook status: {error_msg}")
        logger.error(f"Stack trace: {stack_trace}")
