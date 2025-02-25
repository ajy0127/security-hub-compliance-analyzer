"""Tests for the lambda_handler and cli_handler functions in app.py."""

import argparse
import io
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, mock_open, patch

import app


class TestAppHandler(unittest.TestCase):
    """Tests for the handler functions."""

    def setUp(self):
        """Set up test fixtures."""
        # Sample findings for testing
        self.sample_findings = [
            {
                "SchemaVersion": "2018-10-08",
                "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.1/finding/12345678-1234-1234-1234-123456789012",
                "Severity": {"Label": "MEDIUM", "Normalized": 40},
                "Title": "IAM root user access key should not exist",
                "Description": "This AWS control checks whether the root user access key is available.",
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": "AWS::::Account:123456789012",
                        "Partition": "aws",
                        "Region": "us-east-1",
                    }
                ],
            }
        ]

        # Sample event for testing
        self.sample_event = {"email": "test@example.com", "hours": 24}

        # Sample test event for testing
        self.sample_test_event = {"test_email": "test@example.com"}

        # Sample stats for testing
        self.sample_stats = {
            "total": 1,
            "critical": 0,
            "high": 0,
            "medium": 1,
            "low": 0,
        }

    @patch("app.SOC2Mapper")
    @patch("app.boto3.client")
    def test_lambda_handler_email_error_paths(
        self, mock_boto3_client, mock_soc2_mapper_class
    ):
        """Test lambda_handler error paths for email configuration."""
        # Mock SOC2Mapper to avoid initialization issues
        mock_soc2_mapper = MagicMock()
        mock_soc2_mapper_class.return_value = mock_soc2_mapper

        # Create mock clients
        mock_boto3_client.return_value = MagicMock()

        # Clear environment variables
        if "RECIPIENT_EMAIL" in os.environ:
            del os.environ["RECIPIENT_EMAIL"]

        # Test case: no recipient email in the event or environment
        result = app.lambda_handler({}, {})
        self.assertEqual(
            result,
            {"statusCode": 500, "body": json.dumps("Recipient email not configured")},
        )

    @patch("app.boto3.client")
    @patch("app.SOC2Mapper")
    @patch("app.get_findings")
    def test_lambda_handler_no_findings(
        self, mock_get_findings, mock_soc2_mapper_class, mock_boto3_client
    ):
        """Test lambda_handler with no findings."""
        # Create mock clients to prevent AWS API calls
        mock_boto3_client.return_value = MagicMock()

        # Configure mocks
        mock_soc2_mapper = MagicMock()
        mock_soc2_mapper_class.return_value = mock_soc2_mapper

        # Configure get_findings to return empty list
        mock_get_findings.return_value = []

        # Set environment variables
        os.environ["RECIPIENT_EMAIL"] = "test@example.com"

        # Call the function
        result = app.lambda_handler(self.sample_event, {})

        # Verify the function returned the expected result
        self.assertEqual(
            result, {"statusCode": 200, "body": json.dumps("No findings to report")}
        )

    @patch("app.argparse.ArgumentParser")
    @patch("app.get_findings")
    @patch("app.analyze_findings")
    @patch("app.generate_csv")
    @patch("app.send_email")
    @patch("app.SOC2Mapper")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_cli_handler_report_command(
        self,
        mock_print,
        mock_input,
        mock_soc2_mapper_class,
        mock_send_email,
        mock_generate_csv,
        mock_analyze_findings,
        mock_get_findings,
        mock_argument_parser,
    ):
        """Test CLI handler with report command."""
        # Configure mocks
        mock_parser = MagicMock()
        mock_argument_parser.return_value = mock_parser

        mock_report_parser = MagicMock()
        mock_test_parser = MagicMock()
        mock_parser.add_subparsers.return_value = MagicMock()
        mock_parser.add_subparsers.return_value.add_parser.side_effect = [
            mock_report_parser,
            mock_test_parser,
        ]

        # Configure args
        mock_args = MagicMock()
        mock_args.command = "report"
        mock_args.email = "test@example.com"
        mock_args.hours = 24
        mock_args.csv = True
        mock_args.csv_path = "/tmp/test.csv"
        mock_parser.parse_args.return_value = mock_args

        # Configure SOC2Mapper
        mock_soc2_mapper = MagicMock()
        mock_soc2_mapper_class.return_value = mock_soc2_mapper

        # Configure findings
        mock_get_findings.return_value = self.sample_findings

        # Configure analysis
        mock_analyze_findings.return_value = ("Sample analysis", self.sample_stats)

        # Configure CSV generation
        mock_generate_csv.return_value = "sample,csv,data"

        # Configure user input for send email
        mock_input.return_value = "y"

        # Configure send_email
        mock_send_email.return_value = True

        # Mock the open function
        m = mock_open()
        with patch("builtins.open", m):
            # Call the function
            app.cli_handler()

            # Verify the file was written
            m.assert_called_once_with("/tmp/test.csv", "w", encoding="utf-8")
            m().write.assert_called_once_with("sample,csv,data")

        # Verify the function called the expected functions
        mock_soc2_mapper_class.assert_called_once()
        mock_get_findings.assert_called_once_with(24)
        mock_analyze_findings.assert_called_once_with(
            self.sample_findings, mock_soc2_mapper
        )
        mock_generate_csv.assert_called_once_with(
            self.sample_findings, mock_soc2_mapper
        )
        mock_send_email.assert_called_once()

        # Verify environment variables were set correctly
        self.assertEqual(os.environ.get("RECIPIENT_EMAIL"), "test@example.com")
        self.assertEqual(os.environ.get("SENDER_EMAIL"), "test@example.com")

    @patch("app.argparse.ArgumentParser")
    @patch("app.send_test_email")
    @patch("app.SOC2Mapper")
    @patch("builtins.print")
    def test_cli_handler_test_email_command(
        self,
        mock_print,
        mock_soc2_mapper_class,
        mock_send_test_email,
        mock_argument_parser,
    ):
        """Test CLI handler with test-email command."""
        # Configure mocks
        mock_parser = MagicMock()
        mock_argument_parser.return_value = mock_parser

        mock_report_parser = MagicMock()
        mock_test_parser = MagicMock()
        mock_parser.add_subparsers.return_value = MagicMock()
        mock_parser.add_subparsers.return_value.add_parser.side_effect = [
            mock_report_parser,
            mock_test_parser,
        ]

        # Configure args
        mock_args = MagicMock()
        mock_args.command = "test-email"
        mock_args.email = "test@example.com"
        mock_parser.parse_args.return_value = mock_args

        # Configure SOC2Mapper
        mock_soc2_mapper = MagicMock()
        mock_soc2_mapper_class.return_value = mock_soc2_mapper

        # Configure send_test_email
        mock_send_test_email.return_value = True

        # Call the function
        app.cli_handler()

        # Verify the function called the expected functions
        mock_soc2_mapper_class.assert_called_once()
        mock_send_test_email.assert_called_once_with("test@example.com")

        # Verify environment variables were set correctly
        self.assertEqual(os.environ.get("RECIPIENT_EMAIL"), "test@example.com")
        self.assertEqual(os.environ.get("SENDER_EMAIL"), "test@example.com")

    @patch("app.argparse.ArgumentParser")
    @patch("app.SOC2Mapper")
    def test_cli_handler_no_command(self, mock_soc2_mapper_class, mock_argument_parser):
        """Test CLI handler with no command."""
        # Configure mocks
        mock_parser = MagicMock()
        mock_argument_parser.return_value = mock_parser

        mock_report_parser = MagicMock()
        mock_test_parser = MagicMock()
        mock_parser.add_subparsers.return_value = MagicMock()
        mock_parser.add_subparsers.return_value.add_parser.side_effect = [
            mock_report_parser,
            mock_test_parser,
        ]

        # Configure args
        mock_args = MagicMock()
        mock_args.command = None
        mock_parser.parse_args.return_value = mock_args

        # Call the function
        app.cli_handler()

        # Verify the function called the expected functions
        mock_parser.print_help.assert_called_once()
        mock_soc2_mapper_class.assert_called_once()

    @patch("app.argparse.ArgumentParser")
    @patch("app.get_findings")
    @patch("app.SOC2Mapper")
    @patch("builtins.print")
    def test_cli_handler_report_no_findings(
        self,
        mock_print,
        mock_soc2_mapper_class,
        mock_get_findings,
        mock_argument_parser,
    ):
        """Test CLI handler with report command but no findings."""
        # Configure mocks
        mock_parser = MagicMock()
        mock_argument_parser.return_value = mock_parser

        mock_report_parser = MagicMock()
        mock_test_parser = MagicMock()
        mock_parser.add_subparsers.return_value = MagicMock()
        mock_parser.add_subparsers.return_value.add_parser.side_effect = [
            mock_report_parser,
            mock_test_parser,
        ]

        # Configure args
        mock_args = MagicMock()
        mock_args.command = "report"
        mock_args.email = "test@example.com"
        mock_args.hours = 24
        mock_args.csv = False
        mock_parser.parse_args.return_value = mock_args

        # Configure SOC2Mapper
        mock_soc2_mapper = MagicMock()
        mock_soc2_mapper_class.return_value = mock_soc2_mapper

        # Configure findings (empty)
        mock_get_findings.return_value = []

        # Call the function
        app.cli_handler()

        # Verify the function called the expected functions
        mock_soc2_mapper_class.assert_called_once()
        mock_get_findings.assert_called_once_with(24)
        mock_print.assert_any_call("No findings found in the specified time period.")


if __name__ == "__main__":
    unittest.main()
