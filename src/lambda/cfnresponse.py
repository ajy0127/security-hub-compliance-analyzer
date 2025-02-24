"""
CloudFormation response module.

This module provides functionality for responding to AWS CloudFormation custom resources.
"""

import json
import logging
import urllib.request

# Define response constants
SUCCESS = "SUCCESS"
FAILED = "FAILED"

logger = logging.getLogger(__name__)


def send(event, context, response_status, response_data, physical_resource_id=None):
    """
    Send a response to CloudFormation regarding the success or failure of a custom resource.
    
    Args:
        event (dict): The event dict containing request data
        context (LambdaContext): The context object for the Lambda function
        response_status (str): Status of the response, either SUCCESS or FAILED
        response_data (dict): Data to send back to CloudFormation
        physical_resource_id (str, optional): Physical resource ID of the custom resource
            
    Returns:
        None
    """
    response_url = event['ResponseURL']
    logger.info(f"Sending response to {response_url}")

    # If physical_resource_id was not provided, use the Lambda function ARN
    if not physical_resource_id:
        physical_resource_id = context.log_stream_name

    response_body = {
        'Status': response_status,
        'Reason': f'See details in CloudWatch Log: {context.log_stream_name}',
        'PhysicalResourceId': physical_resource_id,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': response_data
    }

    json_response = json.dumps(response_body)
    logger.info(f"Response body: {json_response}")

    headers = {
        'Content-Type': 'application/json',
        'Content-Length': str(len(json_response))
    }

    try:
        # Create the request
        req = urllib.request.Request(response_url, 
                                     data=json_response.encode('utf-8'),
                                     headers=headers,
                                     method='PUT')
        
        # Send the request
        with urllib.request.urlopen(req) as response:
            logger.info(f"Status code: {response.getcode()}")
            
        logger.info("CloudFormation response sent successfully")
        
    except Exception as e:
        logger.error(f"Failed to send CloudFormation response: {str(e)}", exc_info=True)