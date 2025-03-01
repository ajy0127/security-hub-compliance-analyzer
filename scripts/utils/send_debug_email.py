#!/usr/bin/env python3
"""
=============================================================================
Send the debug NIST 800-53 cATO HTML email directly using boto3 SES

This script:
1. Reads the debug_email.html file created by debug_email_output.py
2. Sends it as an email using Amazon SES
3. Provides a direct way to test email delivery of complex HTML

Usage:
./send_debug_email.py --sender your-verified@email.com --recipient recipient@example.com

Requirements:
- debug_email.html must exist (run debug_email_output.py first)
- Both sender and recipient must be verified in SES if in sandbox mode
=============================================================================
"""

import argparse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import boto3


def send_html_email(profile_name, sender_email, recipient_email):
    """Send the debug HTML email directly."""
    print(
        f"Sending HTML email from {sender_email} to {recipient_email} using profile {profile_name}"
    )

    # Read the HTML content
    try:
        with open("debug_email.html", "r") as f:
            html_content = f.read()
    except FileNotFoundError:
        print("Error: debug_email.html not found. Run debug_email_output.py first.")
        return False

    # Create a session with the specified profile
    session = boto3.Session(profile_name=profile_name)

    # Create SES client
    ses = session.client("ses")

    # Create message container
    msg = MIMEMultipart("mixed")
    msg["Subject"] = "Test Agency Weekly cATO Update - 2025-02-28"
    msg["From"] = sender_email
    msg["To"] = recipient_email

    # Create HTML part
    html_part = MIMEText(html_content, "html", "utf-8")
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
    parser = argparse.ArgumentParser(description="Send debug HTML email")
    parser.add_argument("--profile", default="sandbox", help="AWS profile to use")
    parser.add_argument("--sender", required=True, help="Verified sender email address")
    parser.add_argument("--recipient", required=True, help="Recipient email address")

    args = parser.parse_args()

    # Generate debug HTML if not already done
    try:
        with open("debug_email.html", "r") as f:
            pass
    except FileNotFoundError:
        print("Generating debug HTML email content first...")
        from debug_email_output import debug_email_html

        debug_email_html()

    # Send the email
    send_html_email(args.profile, args.sender, args.recipient)
