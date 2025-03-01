import argparse
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

import boto3
import botocore.session
from botocore.stub import Stubber

from mapper_factory import MapperFactory

def cli_handler():
    # ... existing code ...
    
    # Fix f-string placeholders
    print(f"Analyzing findings from the last {hours} hours...")
    print(f"Found {len(findings)} findings")
    print(f"Generating report for {framework_id}...")
    print(f"Report saved to {output_file}")
    print(f"Email sent to {recipient_email}")

# ... existing code ... 