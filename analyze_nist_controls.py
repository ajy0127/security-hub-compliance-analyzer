import json
import logging

def load_nist_mappings():
    """Load NIST 800-53 control mappings from JSON file."""
    try:
        with open("config/nist_800_53_mappings.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error("NIST 800-53 mappings file not found")
        return None
    except json.JSONDecodeError:
        logging.error("Invalid JSON format in NIST 800-53 mappings file")
        return None

def analyze_control_families():
    """Analyze NIST 800-53 control families and their distribution."""
    mappings = load_nist_mappings()
    if not mappings:
        print("Failed to load NIST 800-53 mappings.")
        return

    # Analyze control families
    control_families = {}
    for control_id, control_info in mappings.get("control_descriptions", {}).items():
        family = control_id.split("-")[0]
        if family not in control_families:
            control_families[family] = []
        control_families[family].append(control_id)
    
    # Calculate statistics
    total_controls = len(mappings.get("control_descriptions", {}))
    avg_controls_per_family = total_controls / len(control_families) if control_families else 0
    
    # Find largest and smallest families
    largest_family = ""
    max_controls = 0
    smallest_family = ""
    min_controls = float('inf')
    
    for family, controls in control_families.items():
        if len(controls) > max_controls:
            max_controls = len(controls)
            largest_family = family
        if len(controls) < min_controls:
            min_controls = len(controls)
            smallest_family = family

    # Fix f-string placeholders
    print(f"Total Controls: {total_controls}")
    print(f"Control Families: {len(control_families)}")
    print(f"Average Controls per Family: {avg_controls_per_family:.2f}")
    print(f"Largest Family: {largest_family} with {max_controls} controls")
    print(f"Smallest Family: {smallest_family} with {min_controls} controls") 