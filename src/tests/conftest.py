"""
conftest.py - Configures the test environment to fix import path issues.

This file adjusts the Python path to include the parent directory (src/)
so that modules can be properly imported from the parent directory while
running tests from within the src/tests directory.
"""

import os
import sys
from pathlib import Path

# Get the absolute path to the parent directory (src/)
SRC_DIR = Path(__file__).parent.parent.absolute()

# Add the parent directory to the Python path if it's not already there
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))