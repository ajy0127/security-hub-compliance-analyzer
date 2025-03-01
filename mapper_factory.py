import json
import logging
import os

from framework_mapper import FrameworkMapper
from soc2_mapper import SOC2Mapper

# Configure logging
logger = logging.getLogger(__name__)

class MapperFactory:
    """
    Factory class for creating framework mappers.
    """
    
    @staticmethod
    def create_mapper(framework_id, mappings_dir=None):
        """
        Create a mapper for the specified framework.
        
        Args:
            framework_id (str): The ID of the framework to create a mapper for
            mappings_dir (str, optional): Directory containing mapping files
            
        Returns:
            FrameworkMapper: A mapper for the specified framework
            
        Raises:
            ValueError: If the framework ID is not supported
        """
        # Normalize framework ID
        framework_id = framework_id.upper()
        
        # Set default mappings directory if not provided
        if mappings_dir is None:
            mappings_dir = "mappings"
            
        # Create the appropriate mapper based on framework ID
        if framework_id == "SOC2":
            mappings_file = os.path.join(mappings_dir, "soc2_mapping.json")
            return SOC2Mapper(mappings_file=mappings_file)
        elif framework_id == "NIST800-53":
            # For future implementation
            # mappings_file = os.path.join(mappings_dir, "nist800_53_mapping.json")
            # return NIST80053Mapper(mappings_file=mappings_file)
            raise ValueError(f"Framework {framework_id} not yet implemented")
        else:
            logger.warning(f"Unsupported framework: {framework_id}")
            raise ValueError(f"Unsupported framework: {framework_id}")
    
    @staticmethod
    def create_all_mappers(frameworks=None, mappings_dir=None):
        """
        Create mappers for all supported frameworks.
        
        Args:
            frameworks (list, optional): List of framework configurations
            mappings_dir (str, optional): Directory containing mapping files
            
        Returns:
            dict: Dictionary of framework mappers keyed by framework ID
        """
        mappers = {}
        
        # If no frameworks provided, use default list
        if frameworks is None:
            from app import load_frameworks
            frameworks = load_frameworks()
        
        # Create a mapper for each framework
        for framework in frameworks:
            framework_id = framework["id"]
            try:
                mappers[framework_id] = MapperFactory.create_mapper(framework_id, mappings_dir)
            except ValueError as e:
                logger.warning(f"Skipping framework {framework_id}: {str(e)}")
                continue
                
        return mappers

# ... existing code ... 