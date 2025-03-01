import json
import logging

from framework_mapper import FrameworkMapper

class SOC2Mapper(FrameworkMapper):
    """
    SOC2 Mapper class for mapping AWS Security Hub findings to SOC2 controls.
    """
    
    def __init__(self):
        """Initialize the SOC2 Mapper."""
        super().__init__()
        self.framework_name = "SOC2"
        self.control_mapping = self._load_control_mapping()
        
    def _load_control_mapping(self):
        """
        Load the SOC2 control mapping from the mapping file.
        
        Returns:
            dict: The control mapping
        """
        try:
            with open("mappings/soc2_mapping.json", "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading SOC2 mapping: {e}")
            return {}
    
    def map_finding_to_controls(self, finding):
        """
        Map a Security Hub finding to SOC2 controls.
        
        Args:
            finding (dict): The Security Hub finding
            
        Returns:
            list: List of SOC2 controls that the finding maps to
        """
        controls = []
        
        # Extract the Security Hub control ID from the finding
        if "ProductFields" in finding and "ControlId" in finding["ProductFields"]:
            control_id = finding["ProductFields"]["ControlId"]
            
            # Look up the control ID in the mapping
            if control_id in self.control_mapping:
                controls = self.control_mapping[control_id]
        
        return controls 