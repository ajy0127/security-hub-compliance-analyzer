"""
Pre-traffic hook for Lambda deployment.

This function is invoked by AWS CodeDeploy before traffic is shifted to the new Lambda version.
It performs validation to ensure the new version is working properly.
"""

import json
import logging
import os
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

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
    function_name = os.environ.get('FUNCTION_NAME')
    
    # Get deployment details
    deployment_id = event.get('DeploymentId')
    lifecycle_event_hook_execution_id = event.get('LifecycleEventHookExecutionId')
    
    if not function_name or not deployment_id or not lifecycle_event_hook_execution_id:
        logger.error("Missing required configuration or event parameters")
        put_lifecycle_event_status(deployment_id, lifecycle_event_hook_execution_id, 'Failed')
        return "Configuration error"
    
    try:
        # Get the Lambda client
        lambda_client = boto3.client('lambda')
        
        # Create a test event
        test_event = {
            "test_email": True,
            "recipient_email": "test@example.com"  # This won't send an actual email because it's a dry-run
        }
        
        # Invoke the function in dry-run mode so no email is actually sent
        logger.info(f"Invoking {function_name} for validation")
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='DryRun',
            Payload=json.dumps(test_event)
        )
        
        # Check the response status code
        status_code = response.get('StatusCode')
        logger.info(f"Invocation status code: {status_code}")
        
        if status_code == 204:  # DryRun successful
            logger.info(f"Pre-traffic validation succeeded for {function_name}")
            put_lifecycle_event_status(deployment_id, lifecycle_event_hook_execution_id, 'Succeeded')
            return "Validation successful"
        else:
            logger.error(f"Pre-traffic validation failed: unexpected status code {status_code}")
            put_lifecycle_event_status(deployment_id, lifecycle_event_hook_execution_id, 'Failed')
            return "Validation failed"
        
    except Exception as e:
        logger.error(f"Error during pre-traffic validation: {str(e)}", exc_info=True)
        put_lifecycle_event_status(deployment_id, lifecycle_event_hook_execution_id, 'Failed')
        return f"Validation error: {str(e)}"

def put_lifecycle_event_status(deployment_id, hook_id, status):
    """
    Update the status of the CodeDeploy lifecycle event.
    
    Args:
        deployment_id: CodeDeploy deployment ID
        hook_id: Lifecycle event hook execution ID
        status: Status to report ('Succeeded' or 'Failed')
    """
    try:
        codedeploy = boto3.client('codedeploy')
        codedeploy.put_lifecycle_event_hook_execution_status(
            deploymentId=deployment_id,
            lifecycleEventHookExecutionId=hook_id,
            status=status
        )
        logger.info(f"Reported hook status {status} for deployment {deployment_id}")
    except Exception as e:
        logger.error(f"Error reporting hook status: {str(e)}", exc_info=True)