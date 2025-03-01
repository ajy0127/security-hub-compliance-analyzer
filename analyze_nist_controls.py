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

    # ... existing code ...

    # Fix f-string placeholders
    print(f"Total Controls: {total_controls}")
    print(f"Control Families: {len(control_families)}")
    print(f"Average Controls per Family: {avg_controls_per_family:.2f}")
    print(f"Largest Family: {largest_family} with {max_controls} controls")
    print(f"Smallest Family: {smallest_family} with {min_controls} controls") 