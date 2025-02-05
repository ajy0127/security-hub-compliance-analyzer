import boto3
from datetime import datetime, timedelta
import json
import logging
import csv
import io
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SENDER_EMAIL = os.environ['SENDER_EMAIL']
RECIPIENT_EMAIL = os.environ['RECIPIENT_EMAIL']
BEDROCK_MODEL_ID = os.environ['BEDROCK_MODEL_ID']
FINDINGS_HOURS = int(os.environ['FINDINGS_HOURS'])

def summarize_findings(findings):
    # Separate CRITICAL and HIGH severity findings
    critical_findings = [f for f in findings if f['Severity'] == 'CRITICAL']
    high_findings = [f for f in findings if f['Severity'] == 'HIGH']

    # Take all CRITICAL findings and limit HIGH severity to 10
    max_high_findings = 10
    high_findings_truncated = high_findings[:max_high_findings]

    # Combine CRITICAL and limited HIGH findings
    selected_findings = critical_findings + high_findings_truncated

    logger.info(f"Analyzing {len(critical_findings)} critical and {min(len(high_findings), max_high_findings)} high severity findings")

    # Create a more detailed representation of findings including Resource ARN
    summary_findings = [{
        'AccountId': f['AccountId'],
        'Title': f['Title'],
        'Severity': f['Severity'],
        'ResourceType': f['ResourceType'],
        'ResourceId': f['ResourceId'],
        'ResourceArn': f.get('ResourceArn', 'N/A'),  # Change to Resource ARN here
        'Description': f['Description'][:200] + '...' if len(f['Description']) > 200 else f['Description']
    } for f in selected_findings]

    bedrock = boto3.client('bedrock-runtime')
    prompt = f"""Human: Analyze the following security findings: {json.dumps(summary_findings, indent=2)} 
Please provide a comprehensive security analysis with the following structure:
1. Critical Findings Overview:
   - List each critical finding with its Account ID, affected resource type, ID, and ARN
   - Explain the potential impact and risk level
2. High Severity Issues:
   - Summarize key high severity findings with Account IDs and affected resources
   - Identify common patterns or recurring issues
3. Resource Impact Analysis:
   - Group findings by resource types
   - Highlight which accounts and resources are most affected
4. Recommended Actions:
   - Prioritized list of remediation steps
   - Account-specific recommendations where applicable

Please ensure the summary is clear and actionable, with specific references to affected accounts and resources. A:"""

    try:
        response = bedrock.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps({
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 2000,
                "temperature": 0.5,
                "top_p": 1,
            })
        )
        summary = json.loads(response['body'].read())['content'][0]['text']
        
        # Add a note about the findings breakdown
        summary_note = f"\n\nAnalysis includes all {len(critical_findings)} critical findings"
        if len(high_findings) > max_high_findings:
            summary_note += f" and {max_high_findings} out of {len(high_findings)} high severity findings"
        else:
            summary_note += f" and all {len(high_findings)} high severity findings"
        
        summary += summary_note
        logger.info("Successfully generated summary")
        return summary.strip()
    
    except Exception as e:
        logger.error(f"Error calling Anthropic Claude 3 Sonnet model: {str(e)}")
        return None

def get_findings_summary(formatted_findings):
    summary = {}
    for finding in formatted_findings:
        account_id = finding['AccountId']
        severity = finding['Severity']
        if account_id not in summary:
            summary[account_id] = {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'total': 0
            }
        summary[account_id][severity] += 1
        summary[account_id]['total'] += 1
    return summary

def format_summary_html(summary):
    total_critical = sum(acc['CRITICAL'] for acc in summary.values())
    total_high = sum(acc['HIGH'] for acc in summary.values())
    total_medium = sum(acc['MEDIUM'] for acc in summary.values())
    total_findings = sum(acc['total'] for acc in summary.values())
    
    html = "<h2 style='color: #333; margin-bottom: 20px;'>Security Hub Findings Summary</h2>"
    html += "<table border='1' style='border-collapse: collapse; width: 70%; margin-left: 0; margin-bottom: 30px;'>"
    html += """
        <tr style='background-color: #f2f2f2;'>
            <th style='padding: 10px; text-align: left;'>Account ID</th>
            <th style='padding: 10px; text-align: left; color: #ff0000;'>Critical</th>
            <th style='padding: 10px; text-align: left; color: #ff6600;'>High</th>
            <th style='padding: 10px; text-align: left; color: #ffcc00;'>Medium</th>
            <th style='padding: 10px; text-align: left;'>Total</th>
        </tr>"""
    
    for account_id, counts in sorted(summary.items()):
        html += f"""
            <tr>
                <td style='padding: 8px;'>{account_id}</td>
                <td style='padding: 8px;'>{counts['CRITICAL']}</td>
                <td style='padding: 8px;'>{counts['HIGH']}</td>
                <td style='padding: 8px;'>{counts['MEDIUM']}</td>
                <td style='padding: 8px;'>{counts['total']}</td>
            </tr>"""
    
    html += f"""
        <tr style='background-color: #f2f2f2; font-weight: bold;'>
            <td style='padding: 10px;'>Total</td>
            <td style='padding: 10px;'>{total_critical}</td>
            <td style='padding: 10px;'>{total_high}</td>
            <td style='padding: 10px;'>{total_medium}</td>
            <td style='padding: 10px;'>{total_findings}</td>
        </tr></table>"""
    return html

def format_summary_text(summary):
    text = "Security Hub Findings Summary\n\n"
    for account_id, counts in sorted(summary.items()):
        text += f"Account {account_id}:\n"
        text += f"Critical: {counts['CRITICAL']}\n"
        text += f"High: {counts['HIGH']}\n"
        text += f"Medium: {counts['MEDIUM']}\n"
        text += f"Total: {counts['total']}\n\n"
    return text

def send_email_with_attachment(sender, recipient, subject, body_text, body_html, csv_content=None, file_name=None):
    ses = boto3.client('ses')
    msg = MIMEMultipart('mixed')
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient

    msg_body = MIMEMultipart('alternative')
    textpart = MIMEText(body_text.encode('utf-8'), 'plain', 'utf-8')
    htmlpart = MIMEText(body_html.encode('utf-8'), 'html', 'utf-8')
    msg_body.attach(textpart)
    msg_body.attach(htmlpart)
    msg.attach(msg_body)

    if csv_content:
        att = MIMEApplication(csv_content.encode('utf-8'))
        att.add_header('Content-Disposition', 'attachment', filename=file_name)
        msg.attach(att)

    try:
        response = ses.send_raw_email(
            Source=sender,
            Destinations=[recipient],
            RawMessage={'Data': msg.as_string()}
        )
        logger.info(f"Email sent! Message ID: {response['MessageId']}")
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
        raise

def lambda_handler(event, context):
    logger.info("Starting SecurityHub findings collection")
    
    securityhub = boto3.client('securityhub')
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=FINDINGS_HOURS)
    
    filters = {
        'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
        'ComplianceStatus': [{'Value': 'FAILED', 'Comparison': 'EQUALS'}],
        'SeverityLabel': [
            {'Value': 'CRITICAL', 'Comparison': 'EQUALS'},
            {'Value': 'HIGH', 'Comparison': 'EQUALS'},
            {'Value': 'MEDIUM', 'Comparison': 'EQUALS'}
        ],
        'UpdatedAt': [
            {
                'Start': start_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'End': end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
            }
        ]
    }

    try:
        paginator = securityhub.get_paginator('get_findings')
        findings_iterator = paginator.paginate(Filters=filters)
        
        all_findings = []
        for page in findings_iterator:
            all_findings.extend(page['Findings'])
        
        total_findings = len(all_findings)
        logger.info(f"Retrieved {total_findings} findings")
        
        if total_findings == 0:
            logger.info("No findings found")
            email_subject = f"SecurityHub Findings Summary - {datetime.now().strftime('%Y-%m-%d')}"
            email_body_text = "No critical, high, or medium severity findings with FAILED compliance status were found in the specified time period."
            email_body_html = f"<html><body><p>{email_body_text}</p></body></html>"
            
            send_email_with_attachment(
                SENDER_EMAIL,
                RECIPIENT_EMAIL,
                email_subject,
                email_body_text,
                email_body_html
            )
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'findings_count': 0,
                    'summary': 'No findings found'
                })
            }
        
        formatted_findings = []
        for finding in all_findings:
            formatted_finding = {
                'AccountId': finding.get('AwsAccountId', 'N/A'),
                'Title': finding.get('Title', 'N/A'),
                'Description': finding.get('Description', 'N/A'),
                'Severity': finding.get('Severity', {}).get('Label', 'N/A'),
                'ResourceType': finding.get('Resources', [{}])[0].get('Type', 'N/A'),
                'ResourceId': finding.get('Resources', [{}])[0].get('Id', 'N/A'),
                'ComplianceStatus': finding.get('Compliance', {}).get('Status', 'N/A'),
                'RecordState': finding.get('RecordState', 'N/A'),
                'LastObservedAt': finding.get('LastObservedAt', 'N/A')
            }
            formatted_findings.append(formatted_finding)

        findings_summary = get_findings_summary(formatted_findings)
        summary_html = format_summary_html(findings_summary)
        summary_text = format_summary_text(findings_summary)
        ai_summary = summarize_findings(formatted_findings)

        csv_buffer = io.StringIO()
        csv_writer = csv.DictWriter(csv_buffer, fieldnames=formatted_findings[0].keys())
        csv_writer.writeheader()
        csv_writer.writerows(formatted_findings)
        csv_content = csv_buffer.getvalue()

        email_subject = f"SecurityHub Findings Summary - {datetime.now().strftime('%Y-%m-%d')}"
        file_name = f'securityhub_findings_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

        email_body_text = f"""
        SecurityHub Findings Summary
        {summary_text}
        AI-Generated Security Hub Findings Summary (All Critical and Top 10 High Severity):
        {ai_summary}
        Please find the detailed findings in the attached CSV file. Please review all recommendations carefully before implementation.
        """

        email_body_html = f"""
        <html>
        <body style='font-family: Arial, sans-serif; max-width: 1000px; margin: 20px auto; color: #333; background-color: #f5f5f5; padding: 20px;'>
            <div style='background-color: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                {summary_html}
            </div>
            
            <div style='background-color: white; margin-top: 30px; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                <div style='border-bottom: 3px solid #3498db; margin-bottom: 20px;'>
                    <h3 style='color: #2c3e50; margin: 0; padding-bottom: 10px; display: flex; align-items: center;'>
                        <span style='background-color: #3498db; color: white; padding: 5px 10px; border-radius: 4px; margin-right: 10px;'>AI</span>
                        Security Hub Findings Analysis
                        <span style='font-size: 0.8em; font-weight: normal; color: #666; margin-left: 10px;'>
                            (All Critical and Top 10 High Severity)
                        </span>
                    </h3>
                </div>

                <div style='background-color: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 4px solid #3498db; margin-bottom: 20px;'>
                    <div style='white-space: normal; line-height: 1.2; font-size: 14px;'>
                        {ai_summary.replace('1. Critical Findings Overview:', '<strong>1. Critical Findings Overview:</strong>')
                                .replace('1.  Critical Findings Overview:', '<strong>1. Critical Findings Overview:</strong>')
                                .replace('2. High Severity Issues:', '<br><br><strong>2. High Severity Issues:</strong>')
                                .replace('3. Resource Impact Analysis:', '<br><br><strong>3. Resource Impact Analysis:</strong>')
                                .replace('4. Recommended Actions:', '<br><br><strong>4. Recommended Actions:</strong>')
                                .replace('**Account ID:', 'Account ID:')
                                .replace('**', '')
                                .replace(chr(10), '<br>')
                                .replace('Overview:<br>', 'Overview:<br><br>')
                                .replace('Issues:<br>', 'Issues:<br><br>')
                                .replace('Analysis:<br>', 'Analysis:<br><br>')
                                .replace('Actions:<br>', 'Actions:<br><br>')
                                .replace('<br><br><br>', '<br><br>')
                                .replace('.<br>', '.<br><br>')
                                .replace('.<br><br><br>', '.<br><br>')
                                }
                    </div>
                </div>

                <div style='display: flex; gap: 20px; margin-top: 25px; padding-top: 20px; border-top: 1px solid #eee;'>
                    <div style='background-color: #f8f9fa; padding: 15px; border-radius: 6px; flex: 1;'>
                        <p style='margin: 0; color: #666;'>
                            <span style='color: #3498db; font-size: 1.2em; margin-right: 8px;'></span>
                            <strong>Detailed Findings:</strong> Available in the attached CSV file
                        </p>
                    </div>
                    <div style='background-color: #f8f9fa; padding: 15px; border-radius: 6px; flex: 1;'>
                        <p style='margin: 0; color: #666;'>
                            <span style='color: #3498db; font-size: 1.2em; margin-right: 8px;'></span>
                            <strong>Analysis:</strong> Generated using Amazon Bedrock
                        </p>
                    </div>
                </div>

                <div style='margin-top: 20px; padding: 15px; background-color: #fff8dc; border-radius: 6px; border: 1px solid #ffd700;'>
                    <p style='margin: 0; font-size: 0.9em; color: #666;'>
                        <strong style='color: #333;'>Note:</strong> This AI-generated analysis includes all critical findings and up to 10 high severity findings for optimal analysis depth.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

        send_email_with_attachment(
            SENDER_EMAIL,
            RECIPIENT_EMAIL,
            email_subject,
            email_body_text,
            email_body_html,
            csv_content,
            file_name
        )

        return {
            'statusCode': 200,
            'body': json.dumps({
                'findings_count': total_findings,
                'summary': ai_summary
            }, default=str)
        }

    except Exception as e:
        logger.error(f"Error processing findings: {str(e)}")
        raise
