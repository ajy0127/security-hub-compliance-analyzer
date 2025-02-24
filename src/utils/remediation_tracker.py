"""
Remediation tracking utilities for SecurityHub findings.

This module provides functionality to track remediation progress for SecurityHub
findings over time, allowing for visibility into which findings have been fixed,
which are still pending, and which are new since the last report.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import boto3

from src.utils.logging_utils import get_logger

# Initialize logger
logger = get_logger(__name__)


class RemediationTracker:
    """
    Tracks the remediation status of findings across multiple reports.

    Uses DynamoDB to persist finding status between Lambda invocations,
    allowing for tracking of fixed findings, new findings, and remediation
    timelines.
    """

    def __init__(self, table_name: str = "SecurityHubRemediationTracker"):
        """
        Initialize the remediation tracker.

        Args:
            table_name: DynamoDB table name for storing finding status
        """
        self.table_name = table_name
        self.dynamodb = boto3.resource("dynamodb")
        self.table = self.dynamodb.Table(table_name)

        # Ensure table exists, create if needed
        self._ensure_table_exists()

    def _ensure_table_exists(self) -> None:
        """
        Ensure the DynamoDB table exists, create it if it doesn't.
        """
        try:
            # Check if table exists
            self.dynamodb.meta.client.describe_table(TableName=self.table_name)
            logger.info(f"DynamoDB table {self.table_name} exists")
        except self.dynamodb.meta.client.exceptions.ResourceNotFoundException:
            logger.info(f"Creating DynamoDB table {self.table_name}")

            # Create table
            self.table = self.dynamodb.create_table(
                TableName=self.table_name,
                KeySchema=[{"AttributeName": "finding_id", "KeyType": "HASH"}],
                AttributeDefinitions=[
                    {"AttributeName": "finding_id", "AttributeType": "S"}
                ],
                ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            )

            # Wait for table creation
            self.table.wait_until_exists()
            logger.info(f"DynamoDB table {self.table_name} created successfully")

    def get_prior_finding_status(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the prior status of a finding.

        Args:
            finding_id: SecurityHub finding ID

        Returns:
            Dictionary containing prior status, or None if finding was not seen before
        """
        try:
            response = self.table.get_item(Key={"finding_id": finding_id})
            return response.get("Item", None)
        except Exception as e:
            logger.error(
                f"Error retrieving finding status: {str(e)}", finding_id=finding_id
            )
            return None

    def update_finding_status(self, finding: Dict[str, Any]) -> None:
        """
        Update the status of a finding.

        Args:
            finding: SecurityHub finding dictionary
        """
        finding_id = finding.get("Id")
        if not finding_id:
            logger.error("Cannot update status for finding without ID")
            return

        try:
            # Get current timestamp
            now = datetime.now(timezone.utc).isoformat()

            # Prepare item
            item = {
                "finding_id": finding_id,
                "last_seen": now,
                "first_seen": finding.get("CreatedAt", now),
                "current_status": finding.get("RecordState", "ACTIVE"),
                "severity": finding.get("Severity", "UNKNOWN"),
                "resource_id": finding.get("ResourceId", "UNKNOWN"),
                "title": finding.get("Title", "UNKNOWN"),
                "account_id": finding.get("AccountId", "UNKNOWN"),
                "control_id": finding.get("SOC2_Controls", {}).get("Primary", []),
                "last_updated": now,
            }

            # Add any existing remediation notes
            prior_status = self.get_prior_finding_status(finding_id)
            if prior_status:
                item["first_seen"] = prior_status.get("first_seen", item["first_seen"])

                # Preserve remediation notes
                if "remediation_notes" in prior_status:
                    item["remediation_notes"] = prior_status["remediation_notes"]

                # Track number of times seen
                item["times_seen"] = prior_status.get("times_seen", 0) + 1

                # Calculate days open
                first_seen_date = datetime.fromisoformat(
                    item["first_seen"].replace("Z", "+00:00")
                )
                now_date = datetime.fromisoformat(now.replace("Z", "+00:00"))
                days_open = (now_date - first_seen_date).days
                item["days_open"] = days_open
            else:
                # New finding
                item["times_seen"] = 1
                item["days_open"] = 0

            # Store in DynamoDB
            self.table.put_item(Item=item)
            logger.info(
                "Updated status for finding",
                finding_id=finding_id,
                status=item["current_status"],
                days_open=item["days_open"],
            )

        except Exception as e:
            logger.error(
                f"Error updating finding status: {str(e)}", finding_id=finding_id
            )

    def mark_as_remediated(self, finding_id: str, notes: Optional[str] = None) -> None:
        """
        Mark a finding as remediated.

        Args:
            finding_id: SecurityHub finding ID
            notes: Optional remediation notes
        """
        try:
            # Get current item
            prior_status = self.get_prior_finding_status(finding_id)
            if not prior_status:
                logger.warning(
                    "Cannot mark unknown finding as remediated", finding_id=finding_id
                )
                return

            # Update status
            now = datetime.now(timezone.utc).isoformat()
            updates: Dict[str, Any] = {
                "current_status": "REMEDIATED",
                "remediated_at": now,
                "last_updated": now,
            }

            if notes:
                updates["remediation_notes"] = notes

            # Calculate remediation time
            first_seen_date = datetime.fromisoformat(
                prior_status["first_seen"].replace("Z", "+00:00")
            )
            now_date = datetime.fromisoformat(now.replace("Z", "+00:00"))
            remediation_days = (now_date - first_seen_date).days
            updates["remediation_days"] = remediation_days

            # Update in DynamoDB
            update_expr = "SET " + ", ".join([f"#{k} = :{k}" for k in updates.keys()])
            attr_names = {f"#{k}": k for k in updates.keys()}
            attr_values = {f":{k}": v for k, v in updates.items()}

            self.table.update_item(
                Key={"finding_id": finding_id},
                UpdateExpression=update_expr,
                ExpressionAttributeNames=attr_names,
                ExpressionAttributeValues=attr_values,
            )

            logger.info(
                "Marked finding as remediated",
                finding_id=finding_id,
                remediation_days=remediation_days,
            )

        except Exception as e:
            logger.error(
                f"Error marking finding as remediated: {str(e)}", finding_id=finding_id
            )

    def get_remediation_status(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get remediation status for a list of findings.

        Analyzes findings to determine:
        - Which findings are new (not seen before)
        - Which findings have been remediated (not in current list but seen before)
        - Ongoing findings and their age

        Args:
            findings: List of SecurityHub finding dictionaries

        Returns:
            Dictionary containing remediation statistics
        """
        # Extract finding IDs
        current_finding_ids = {f.get("Id") for f in findings if f.get("Id")}

        # Scan DynamoDB for all findings we've tracked
        all_tracked_items = self._scan_all_items()
        tracked_finding_ids = {item["finding_id"] for item in all_tracked_items}

        # Identify new findings
        new_finding_ids = current_finding_ids - tracked_finding_ids
        new_findings = [f for f in findings if f.get("Id") in new_finding_ids]

        # Identify remediated findings
        remediated_finding_ids = {
            item["finding_id"]
            for item in all_tracked_items
            if item["current_status"] != "REMEDIATED"
            and item["finding_id"] not in current_finding_ids
        }

        # Calculate ongoing findings
        ongoing_finding_ids = current_finding_ids & tracked_finding_ids
        ongoing_findings = [f for f in findings if f.get("Id") in ongoing_finding_ids]

        # Calculate age statistics
        age_stats: Dict[str, Dict[str, Any]] = {}
        for item in all_tracked_items:
            if item["finding_id"] in ongoing_finding_ids:
                days_open = int(item.get("days_open", 0))  # Ensure it's an integer
                severity = item.get("severity", "UNKNOWN")

                if severity not in age_stats:
                    age_stats[severity] = {
                        "count": 0,
                        "avg_days": 0.0,  # Using float for average
                        "max_days": 0,
                        "findings": [],
                    }

                age_stats[severity]["count"] += 1
                age_stats[severity]["avg_days"] = (
                    float(
                        (
                            age_stats[severity]["avg_days"]
                            * (age_stats[severity]["count"] - 1)
                            + days_open
                        )
                    )
                    / age_stats[severity]["count"]
                )
                age_stats[severity]["max_days"] = max(
                    age_stats[severity]["max_days"], days_open
                )
                age_stats[severity]["findings"].append(
                    {
                        "id": item["finding_id"],
                        "title": item.get("title", "Unknown"),
                        "days_open": days_open,
                    }
                )

        # Automatically mark findings as remediated if they're not in the current list
        for finding_id in remediated_finding_ids:
            self.mark_as_remediated(
                finding_id, "Automatically marked as remediated - no longer found"
            )

        # Update status for all current findings
        for finding in findings:
            self.update_finding_status(finding)

        # Return remediation statistics
        return {
            "new_findings": {
                "count": len(new_findings),
                "findings": [
                    {"id": f.get("Id"), "title": f.get("Title")} for f in new_findings
                ],
            },
            "remediated_findings": {
                "count": len(remediated_finding_ids),
                "findings": [{"id": fid} for fid in remediated_finding_ids],
            },
            "ongoing_findings": {
                "count": len(ongoing_findings),
                "findings": [
                    {"id": f.get("Id"), "title": f.get("Title")}
                    for f in ongoing_findings
                ],
            },
            "age_statistics": age_stats,
            "total_active": len(findings),
            "total_remediated": len(remediated_finding_ids),
            "remediation_rate": len(remediated_finding_ids)
            / max(1, len(findings) + len(remediated_finding_ids)),
        }

    def get_finding_history(self, finding_id: str) -> Dict[str, Any]:
        """
        Get the complete history of a finding.

        Args:
            finding_id: SecurityHub finding ID

        Returns:
            Dictionary containing finding history
        """
        item = self.get_prior_finding_status(finding_id)
        if not item:
            return {
                "finding_id": finding_id,
                "status": "UNKNOWN",
                "message": "No history found",
            }

        return item

    def _scan_all_items(self) -> List[Dict[str, Any]]:
        """
        Scan all items in the DynamoDB table.

        Returns:
            List of all items in the table
        """
        try:
            items = []
            last_evaluated_key = None

            while True:
                if last_evaluated_key:
                    response = self.table.scan(ExclusiveStartKey=last_evaluated_key)
                else:
                    response = self.table.scan()

                items.extend(response.get("Items", []))
                last_evaluated_key = response.get("LastEvaluatedKey")

                if not last_evaluated_key:
                    break

            return items
        except Exception as e:
            logger.error(f"Error scanning DynamoDB table: {str(e)}")
            return []


def get_remediation_tracker() -> RemediationTracker:
    """
    Get a configured remediation tracker instance.

    Returns:
        Configured RemediationTracker
    """
    return RemediationTracker()
