"""Factory pattern for creating framework-specific mappers."""

import logging
import json
import os
from pathlib import Path

# Import all mappers
from src.mappers.soc2_mapper import SOC2Mapper
from src.mappers.nist_mapper import NIST80053Mapper

# Configure logging
logger = logging.getLogger()


class MapperFactory:
    """Factory class for creating framework-specific mapper instances."""

    @staticmethod
    def get_mapper(framework_id, mappings_file=None):
        """Create and return an appropriate framework mapper based on framework ID.

        Args:
            framework_id (str): The compliance framework ID (e.g., 'SOC2', 'NIST800-53')
            mappings_file (str, optional): Override path to mappings file

        Returns:
            FrameworkMapper: An instance of the appropriate framework mapper

        Raises:
            ValueError: If the framework ID is not supported
        """
        # Framework ID should be case-insensitive for flexibility
        framework_id = framework_id.upper()

        if framework_id == "SOC2":
            return SOC2Mapper(mappings_file)
        elif framework_id == "NIST800-53":
            return NIST80053Mapper(mappings_file)
        else:
            error_message = f"Unsupported framework: {framework_id}"
            logger.error(error_message)
            raise ValueError(error_message)

    @staticmethod
    def get_all_mappers():
        """Create and return mapper instances for all supported frameworks.

        Returns:
            dict: Dictionary of framework mappers, keyed by framework ID
        """
        # Get list of supported frameworks from configuration
        frameworks = load_frameworks()

        # Create mappers for each framework
        mappers = {}
        for framework in frameworks:
            try:
                framework_id = framework["id"]
                mappings_file = framework.get("mappings_file")
                mappers[framework_id] = MapperFactory.get_mapper(
                    framework_id, mappings_file
                )
            except Exception as e:
                logger.error(f"Error creating mapper for {framework['id']}: {str(e)}")

        return mappers


def load_frameworks():
    """Load framework configurations from the frameworks.json file.

    Returns:
        list: List of framework configuration dictionaries
    """
    try:
        # Determine the frameworks config file path
        frameworks_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "config",
            "frameworks.json",
        )

        # Load and parse the frameworks configuration
        if os.path.exists(frameworks_file):
            with open(frameworks_file, "r") as f:
                config = json.load(f)
                return config.get("frameworks", [])
        else:
            logger.warning(
                f"Frameworks configuration file not found: {frameworks_file}"
            )
            # Return default frameworks if file not found
            return [
                {
                    "id": "SOC2",
                    "name": "SOC 2",
                    "arn": "arn:aws:securityhub:::standards/aws-soc2",
                    "mappings_file": os.path.join(
                        os.path.dirname(os.path.abspath(__file__)),
                        "..",
                        "config",
                        "mappings",
                        "soc2_mappings.json",
                    ),
                }
            ]
    except Exception as e:
        logger.error(f"Error loading frameworks configuration: {str(e)}")
        # Return SOC2 as fallback
        return [
            {
                "id": "SOC2",
                "name": "SOC 2",
                "arn": "arn:aws:securityhub:::standards/aws-soc2",
                "mappings_file": None,
            }
        ]
