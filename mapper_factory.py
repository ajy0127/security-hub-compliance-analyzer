import json
import logging

from framework_mapper import FrameworkMapper
from soc2_mapper import SOC2Mapper

class MapperFactory:
    """
    Factory class for creating framework mappers.
    """
    
    @staticmethod
    def create_mapper(framework_id):
        """
        Create a mapper for the specified framework.
        
        Args:
            framework_id (str): The ID of the framework to create a mapper for
            
        Returns:
            FrameworkMapper: A mapper for the specified framework
            
        Raises:
            ValueError: If the framework ID is not supported
        """
        if framework_id.upper() == "SOC2":
            return SOC2Mapper()
        else:
            raise ValueError(f"Unsupported framework: {framework_id}")

# ... existing code ... 