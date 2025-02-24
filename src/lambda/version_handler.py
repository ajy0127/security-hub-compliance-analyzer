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
import cfnresponse

logger = logging.getLogger()
logger.setLevel(logging.INFO)

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
    function_name = os.environ.get('FUNCTION_NAME')
    
    if not function_name:
        error_msg = "FUNCTION_NAME environment variable is not set"
        logger.error(error_msg)
        cfnresponse.send(event, context, cfnresponse.FAILED, {"Error": error_msg})
        return
    
    logger.info(f"Received event: {json.dumps(event)}")
    
    request_type = event['RequestType']
    
    try:
        if request_type == 'Create' or request_type == 'Update':
            # Initialize boto3 client
            lambda_client = boto3.client('lambda')
            
            # Create a new function version
            logger.info(f"Publishing new version for function: {function_name}")
            response = lambda_client.publish_version(
                FunctionName=function_name,
                Description=f"Version created at {time.time()}"
            )
            
            version = response.get('Version')
            
            # Get function configuration to verify
            config = lambda_client.get_function_configuration(
                FunctionName=function_name,
                Qualifier=version
            )
            
            logger.info(f"Successfully published version {version} for {function_name}")
            
            # Send success response with version
            cfnresponse.send(
                event, 
                context, 
                cfnresponse.SUCCESS, 
                {"Version": version},
                physicalResourceId=f"{function_name}:{version}"
            )
            
        elif request_type == 'Delete':
            # Nothing to do for delete, as Lambda versions can't be deleted
            logger.info(f"Delete request for {function_name}, no action needed")
            cfnresponse.send(
                event, 
                context, 
                cfnresponse.SUCCESS, 
                {"Message": "No action needed for Delete"}
            )
        
    except Exception as e:
        logger.error(f"Error: {str(e)}", exc_info=True)
        cfnresponse.send(event, context, cfnresponse.FAILED, {"Error": str(e)})