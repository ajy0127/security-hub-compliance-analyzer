import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Add the src directory to the path so we can import the modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.mapper_factory import MapperFactory
from src.soc2_mapper import SOC2Mapper
from src.framework_mapper import FrameworkMapper


class TestMapperFactory(unittest.TestCase):
    """Unit tests for MapperFactory class."""

    def setUp(self):
        """Set up test fixtures."""
        # Sample framework configurations for testing
        self.test_frameworks = [
            {
                "id": "SOC2",
                "name": "SOC 2",
                "description": "SOC 2 Security Framework",
                "arn": "arn:aws:securityhub:::ruleset/soc2/v/1.0.0",
            },
            {
                "id": "NIST800-53",
                "name": "NIST 800-53",
                "description": "NIST 800-53 Framework",
                "arn": "arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0",
            },
        ]

    @patch('src.mapper_factory.SOC2Mapper')
    def test_create_mapper_soc2(self, mock_soc2_mapper):
        """Test creating a SOC2 mapper."""
        # Setup mock
        mock_soc2_mapper.return_value = MagicMock(spec=SOC2Mapper)
        
        # Call function
        mapper = MapperFactory.create_mapper("SOC2")
        
        # Verify SOC2Mapper was instantiated with correct parameters
        mock_soc2_mapper.assert_called_with(mappings_file="config/mappings/soc2_mappings.json")
        
        # Verify returned object is the mock
        self.assertEqual(mapper, mock_soc2_mapper.return_value)

    @patch('src.mapper_factory.NIST80053Mapper')
    def test_create_mapper_nist(self, mock_nist_mapper):
        """Test creating a NIST 800-53 mapper."""
        # Setup mock
        mock_nist_mapper.return_value = MagicMock(spec=FrameworkMapper)
        
        # Call function
        mapper = MapperFactory.create_mapper("NIST800-53")
        
        # Verify NIST80053Mapper was instantiated with correct parameters
        mock_nist_mapper.assert_called_with(mappings_file="config/mappings/nist800_53_mappings.json")
        
        # Verify returned object is the mock
        self.assertEqual(mapper, mock_nist_mapper.return_value)

    def test_create_mapper_unsupported(self):
        """Test creating a mapper for an unsupported framework."""
        # Verify ValueError is raised for unsupported framework
        with self.assertRaises(ValueError):
            MapperFactory.create_mapper("UNSUPPORTED_FRAMEWORK")

    @patch('src.mapper_factory.MapperFactory.create_mapper')
    def test_create_all_mappers(self, mock_create_mapper):
        """Test creating all mappers."""
        # Setup mock
        mock_soc2_mapper = MagicMock(spec=SOC2Mapper)
        mock_nist_mapper = MagicMock(spec=FrameworkMapper)
        
        # Configure create_mapper to return different mappers based on framework_id
        def side_effect(framework_id, mappings_dir=None):
            if framework_id == "SOC2":
                return mock_soc2_mapper
            elif framework_id == "NIST800-53":
                return mock_nist_mapper
            else:
                raise ValueError(f"Unsupported framework: {framework_id}")
                
        mock_create_mapper.side_effect = side_effect
        
        # Call function
        mappers = MapperFactory.create_all_mappers(self.test_frameworks)
        
        # Verify create_mapper was called for each framework
        self.assertEqual(mock_create_mapper.call_count, 2)
        
        # Verify returned dictionary contains expected mappers
        self.assertEqual(len(mappers), 2)
        self.assertIn("SOC2", mappers)
        self.assertIn("NIST800-53", mappers)
        self.assertEqual(mappers["SOC2"], mock_soc2_mapper)
        self.assertEqual(mappers["NIST800-53"], mock_nist_mapper)

    # Redesigned test to avoid patching the mapper_factory.load_frameworks function
    def test_create_all_mappers_with_frameworks_arg(self):
        """Test creating all mappers when frameworks are provided explicitly."""
        # Create a real MapperFactory instance
        with patch('src.mapper_factory.SOC2Mapper') as mock_soc2_mapper, \
             patch('src.mapper_factory.NIST80053Mapper') as mock_nist_mapper:
            
            # Setup mocks
            mock_soc2_instance = MagicMock(spec=SOC2Mapper)
            mock_nist_instance = MagicMock(spec=FrameworkMapper)
            mock_soc2_mapper.return_value = mock_soc2_instance
            mock_nist_mapper.return_value = mock_nist_instance
            
            # Call the function with explicit frameworks argument
            mappers = MapperFactory.create_all_mappers(self.test_frameworks)
            
            # Verify mapper classes were instantiated correctly
            mock_soc2_mapper.assert_called_once()
            mock_nist_mapper.assert_called_once()
            
            # Verify returned dictionary contains expected mappers
            self.assertEqual(len(mappers), 2)
            self.assertIn("SOC2", mappers)
            self.assertIn("NIST800-53", mappers)
            self.assertEqual(mappers["SOC2"], mock_soc2_instance)
            self.assertEqual(mappers["NIST800-53"], mock_nist_instance)

    @patch('src.mapper_factory.MapperFactory.create_mapper')
    def test_create_all_mappers_with_error(self, mock_create_mapper):
        """Test creating all mappers when one mapper fails."""
        # Setup mocks
        mock_soc2_mapper = MagicMock(spec=SOC2Mapper)
        
        # Configure create_mapper to return a mapper for SOC2 but raise an error for NIST800-53
        def side_effect(framework_id, mappings_dir=None):
            if framework_id == "SOC2":
                return mock_soc2_mapper
            elif framework_id == "NIST800-53":
                raise ValueError("Unsupported framework")
            else:
                raise ValueError(f"Unsupported framework: {framework_id}")
                
        mock_create_mapper.side_effect = side_effect
        
        # Call function
        mappers = MapperFactory.create_all_mappers(self.test_frameworks)
        
        # Verify create_mapper was called for each framework
        self.assertEqual(mock_create_mapper.call_count, 2)
        
        # Verify returned dictionary contains only the successful mapper
        self.assertEqual(len(mappers), 1)
        self.assertIn("SOC2", mappers)
        self.assertNotIn("NIST800-53", mappers)
        self.assertEqual(mappers["SOC2"], mock_soc2_mapper)


if __name__ == '__main__':
    unittest.main()