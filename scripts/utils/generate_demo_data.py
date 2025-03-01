import boto3
import json
import csv
import io
import datetime
import random


def lambda_handler(event, context):
    """Generate sample NIST 800-53 control data for QuickSight dashboard."""
    s3 = boto3.client("s3")
    data_bucket = "securityhub-cato-dashboard-120569644581"

    try:
        # Get current timestamp for this data point
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        date_str = datetime.datetime.now().strftime("%Y-%m-%d")

        # Generate sample control data
        controls = {}
        control_families = {
            "AC": "Access Control",
            "AU": "Audit and Accountability",
            "AT": "Awareness and Training",
            "CM": "Configuration Management",
            "IA": "Identification and Authentication",
            "IR": "Incident Response",
            "MA": "Maintenance",
            "MP": "Media Protection",
            "PS": "Personnel Security",
            "PE": "Physical Protection",
            "PL": "Planning",
            "RA": "Risk Assessment",
            "CA": "Security Assessment",
            "SC": "System and Communications",
            "SI": "System and Information Integrity",
        }

        # Generate control data
        for family, family_name in control_families.items():
            # Create 5-10 controls per family
            for i in range(random.randint(5, 10)):
                control_id = f"{family}-{i+1}"
                status = random.choices(
                    ["PASSED", "FAILED", "NOT_APPLICABLE", "UNKNOWN"],
                    weights=[0.6, 0.2, 0.1, 0.1],
                    k=1,
                )[0]

                severity = random.choices(
                    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    weights=[0.1, 0.3, 0.4, 0.2],
                    k=1,
                )[0]

                controls[control_id] = {
                    "id": f"NIST.800-53.r5-{control_id}",
                    "title": f"{family_name} Control {i+1}",
                    "description": f"This is a sample description for {control_id}",
                    "status": status,
                    "severity": severity,
                    "disabled": False,
                    "related_requirements": [],
                }

        # Prepare CSV data for QuickSight
        control_rows = []
        control_family_rows = []
        control_history_rows = []
        family_stats = {}

        # Process each control
        for control_id, control in controls.items():
            # Determine control family
            family = control_id.split("-")[0]

            # Add to control rows
            status = control.get("status", "UNKNOWN")
            severity = control.get("severity", "MEDIUM")

            control_rows.append(
                {
                    "control_id": control_id,
                    "title": control.get("title", ""),
                    "status": status,
                    "family": family,
                    "severity": severity,
                    "date": date_str,
                    "timestamp": timestamp,
                }
            )

            # Update family statistics
            if family not in family_stats:
                family_stats[family] = {
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                    "not_applicable": 0,
                    "unknown": 0,
                }

            family_stats[family]["total"] += 1

            if status == "PASSED":
                family_stats[family]["passed"] += 1
            elif status == "FAILED":
                family_stats[family]["failed"] += 1
            elif status == "NOT_APPLICABLE":
                family_stats[family]["not_applicable"] += 1
            else:
                family_stats[family]["unknown"] += 1

            # Add to control history
            control_history_rows.append(
                {
                    "control_id": control_id,
                    "status": status,
                    "date": date_str,
                    "timestamp": timestamp,
                }
            )

        # Create family statistics rows
        for family, stats in family_stats.items():
            compliance_pct = 0
            if stats["total"] > 0:
                compliance_pct = (stats["passed"] / stats["total"]) * 100

            control_family_rows.append(
                {
                    "family": family,
                    "total": stats["total"],
                    "passed": stats["passed"],
                    "failed": stats["failed"],
                    "not_applicable": stats["not_applicable"],
                    "unknown": stats["unknown"],
                    "compliance_percentage": compliance_pct,
                    "date": date_str,
                    "timestamp": timestamp,
                }
            )

        # Export control details to CSV
        control_csv = io.StringIO()
        if control_rows:
            writer = csv.DictWriter(control_csv, fieldnames=control_rows[0].keys())
            writer.writeheader()
            writer.writerows(control_rows)

            # Upload to S3
            s3.put_object(
                Bucket=data_bucket,
                Key=f"control_details/{date_str}/controls_{timestamp}.csv",
                Body=control_csv.getvalue(),
            )

            # Also update latest file
            s3.put_object(
                Bucket=data_bucket,
                Key="control_details/latest.csv",
                Body=control_csv.getvalue(),
            )

        # Export control family stats to CSV
        family_csv = io.StringIO()
        if control_family_rows:
            writer = csv.DictWriter(
                family_csv, fieldnames=control_family_rows[0].keys()
            )
            writer.writeheader()
            writer.writerows(control_family_rows)

            # Upload to S3
            s3.put_object(
                Bucket=data_bucket,
                Key=f"control_families/{date_str}/families_{timestamp}.csv",
                Body=family_csv.getvalue(),
            )

            # Also update latest file
            s3.put_object(
                Bucket=data_bucket,
                Key="control_families/latest.csv",
                Body=family_csv.getvalue(),
            )

        # Create a simple history file
        history_csv = io.StringIO()
        writer = csv.DictWriter(history_csv, fieldnames=control_history_rows[0].keys())
        writer.writeheader()
        writer.writerows(control_history_rows)

        # Upload history file
        s3.put_object(
            Bucket=data_bucket,
            Key="control_history/history.csv",
            Body=history_csv.getvalue(),
        )

        return {
            "statusCode": 200,
            "body": json.dumps(
                f"Successfully exported {len(control_rows)} sample controls to S3"
            ),
        }

    except Exception as e:
        print(f"Error generating sample data: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps(f"Error generating sample data: {str(e)}"),
        }
