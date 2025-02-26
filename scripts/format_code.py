#!/usr/bin/env python3

"""Simple formatting script to fix Black formatting issues."""

import os
import sys
import re

def fix_app_py(file_path):
    """Fix specific formatting issues in app.py."""
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    with open(file_path, 'w') as f:
        inside_multiline_string = False
        leading_spaces = ""
        for line in lines:
            # Check if line starts a multiline string
            if 'f"""' in line and '"""' not in line[line.find('f"""')+4:]:
                inside_multiline_string = True
                leading_spaces = line[:line.find('f"""')]
                f.write(line)
                continue
                
            # Check if line ends a multiline string
            if inside_multiline_string and '"""' in line:
                inside_multiline_string = False
                f.write(line)
                continue
                
            # Handle content inside multiline string
            if inside_multiline_string:
                # Remove leading whitespace
                if line.startswith(leading_spaces + "    "):
                    line = line[len(leading_spaces) + 4:]
                elif line.strip() == "":
                    line = "\n"
                f.write(line)
            else:
                # Outside multiline string, just write as is
                f.write(line)

def fix_argparse_arguments(file_path):
    """Fix argparse argument definitions to be on a single line."""
    with open(file_path, 'r') as f:
        content = f.read()
        
    # Pattern to make argparse definitions one line
    pattern = r'\.add_argument\(\s*\n\s+([^,]+),\s*\n\s+([^)]+)\s*\)'
    fixed_content = re.sub(pattern, r'.add_argument(\1, \2)', content)
    
    with open(file_path, 'w') as f:
        f.write(fixed_content)

def fix_mapper_py(file_path):
    """Fix specific formatting issues in soc2_mapper.py."""
    with open(file_path, 'r') as f:
        content = f.read()
        
    # Fix specific mappings file line continuation
    pattern = r'self\.mappings_file = mappings_file or os\.path\.join\(\s*\n\s+os\.path\.dirname\(__file__\), "config", "mappings\.json"\s*\n\s+\)'
    replacement = r'self.mappings_file = mappings_file or os.path.join(os.path.dirname(__file__), "config", "mappings.json")'
    fixed_content = re.sub(pattern, replacement, content)
    
    # Fix controls list
    pattern = r'"Software and Configuration Checks/Industry and Regulatory Standards": \[\s*\n\s+"CC1\.3",\s*\n\s+"CC2\.2",\s*\n\s+"CC2\.3",\s*\n\s+\],'
    replacement = r'"Software and Configuration Checks/Industry and Regulatory Standards": ["CC1.3", "CC2.2", "CC2.3"],'
    fixed_content = re.sub(pattern, replacement, fixed_content)
    
    # Fix description truncation
    pattern = r'"Description": \(\s*\n\s+description\[:200\] \+ "\.\.\." if len\(description\) > 200 else description\s*\n\s+\),'
    replacement = r'"Description": description[:200] + "..." if len(description) > 200 else description,'
    fixed_content = re.sub(pattern, replacement, fixed_content)
    
    # Fix control descriptions list
    pattern = r'"ControlDescriptions": \[\s*\n\s+self\.mappings\["control_descriptions"\]\.get\(control, ""\)\s*\n\s+for control in controls\s*\n\s+\],'
    replacement = r'"ControlDescriptions": [self.mappings["control_descriptions"].get(control, "") for control in controls],'
    fixed_content = re.sub(pattern, replacement, fixed_content)
    
    with open(file_path, 'w') as f:
        f.write(fixed_content)

def main():
    """Format key files for Black compatibility."""
    print("Formatting files for Black compatibility...")
    
    # Fix app.py
    app_path = os.path.join('src', 'app.py')
    if os.path.exists(app_path):
        print(f"Processing {app_path}...")
        fix_app_py(app_path)
        fix_argparse_arguments(app_path)
    else:
        print(f"Warning: File {app_path} not found")
        
    # Fix soc2_mapper.py
    mapper_path = os.path.join('src', 'soc2_mapper.py')
    if os.path.exists(mapper_path):
        print(f"Processing {mapper_path}...")
        fix_mapper_py(mapper_path)
    else:
        print(f"Warning: File {mapper_path} not found")
        
    # Fix test_locally.py
    test_path = os.path.join('scripts', 'test_locally.py')
    if os.path.exists(test_path):
        print(f"Processing {test_path}...")
        fix_argparse_arguments(test_path)
    else:
        print(f"Warning: File {test_path} not found")
    
    print("Formatting complete!")
    print("Note: This script applies specific formatting fixes for Black compatibility.")

if __name__ == "__main__":
    main()