#!/usr/bin/env python3
"""
Send a direct email using AWS SES without going through the Lambda function.
"""

import argparse
import json
import os
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import boto3


def send_direct_email(profile_name, sender_email, recipient_email):
    """Send a direct test email using AWS SES."""
    # Create a session with the specified profile
    session = boto3.Session(profile_name=profile_name)

    # Create SES client
    ses = session.client("ses")

    # Create message container
    msg = MIMEMultipart("mixed")
    msg["Subject"] = "AWS SecurityHub NIST 800-53 Test Email (Direct)"
    msg["From"] = sender_email
    msg["To"] = recipient_email

    # Create HTML content
    html_content = f"""<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #232f3e; }}
        .box {{ background-color: #f8f8f8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>AWS SecurityHub NIST 800-53 Test Email (Direct)</h1>

    <div class="box">
        <h2>Direct SES Test</h2>
        <p>This is a direct test email sent via SES, bypassing the Lambda function.</p>
        <p>Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>
    </div>
    
    <p>If you're receiving this email, it confirms that AWS SES is properly configured and can deliver emails to your address.</p>
</body>
</html>"""

    # Attach HTML part
    html_part = MIMEText(html_content, "html")
    msg.attach(html_part)

    # Send email
    try:
        response = ses.send_raw_email(
            Source=sender_email,
            Destinations=[recipient_email],
            RawMessage={"Data": msg.as_string()},
        )
        print(f"Email sent successfully: {response}")
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send direct email via AWS SES")
    parser.add_argument("--profile", default="sandbox", help="AWS profile name to use")
    parser.add_argument("--sender", required=True, help="Verified sender email address")
    parser.add_argument("--recipient", required=True, help="Recipient email address")

    args = parser.parse_args()

    send_direct_email(args.profile, args.sender, args.recipient)
