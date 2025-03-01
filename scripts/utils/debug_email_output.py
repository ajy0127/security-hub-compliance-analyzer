#!/usr/bin/env python3
"""
=============================================================================
Debug script to generate and test NIST 800-53 cATO email HTML output

This script:
1. Retrieves NIST 800-53 control status directly from Security Hub
2. Generates a comprehensive cATO status report
3. Creates a properly formatted HTML email with control family breakdowns
4. Saves the HTML to a file for review in a web browser

Usage: ./debug_email_output.py
Output: Creates debug_email.html for manual inspection
=============================================================================
"""

import json
import os
from src.app import get_nist_control_status, generate_nist_cato_report


def debug_email_html():
    """Generate and save the email HTML for debugging."""
    print("Debugging email HTML output")

    # Get control status data
    print("Getting NIST 800-53 control status...")
    controls = get_nist_control_status()
    print(f"Retrieved {len(controls)} controls")

    # Generate the report
    print("Generating cATO report...")
    report_text, stats, control_families = generate_nist_cato_report()

    # Print report summary
    print(f"\nReport Statistics:")
    print(f"Total Controls: {stats.get('total', 0)}")
    print(f"Passed: {stats.get('passed', 0)}")
    print(f"Failed: {stats.get('failed', 0)}")
    print(f"Unknown: {stats.get('unknown', 0)}")
    print(f"Compliance %: {stats.get('compliance_percentage', 0):.1f}%")
    print(f"\nControl Families: {len(control_families)}")

    # Framework settings
    framework_id = "NIST800-53"
    framework_name = "NIST 800-53"
    frameworks_to_include = [framework_id]
    subject = f"Test Agency Weekly cATO Update - 2025-02-28"

    # Process analysis for HTML
    analysis = report_text
    formatted_analysis = (
        analysis.replace("# ", "<h1>").replace("## ", "<h2>").replace("### ", "<h3>")
    )
    formatted_analysis = formatted_analysis.replace("\n\n", "</p><p>")
    formatted_analysis = formatted_analysis.replace("**", "<strong>")
    formatted_analysis = formatted_analysis.replace("*", "<em>")

    # Make sure all tags are properly closed
    for tag in ["h1", "h2", "h3", "strong", "em", "p"]:
        count = formatted_analysis.count(f"<{tag}>")
        if count > formatted_analysis.count(f"</{tag}>"):
            formatted_analysis += f"</{tag}>"

    # Determine if we have enhanced cATO stats
    has_cato_stats = "compliance_percentage" in stats

    # Set the cATO readiness percentage
    if has_cato_stats:
        cato_readiness = stats["compliance_percentage"]
    else:
        cato_readiness = max(
            5,
            min(
                95,
                100
                - (
                    stats.get("critical", 0) * 15
                    + stats.get("high", 0) * 10
                    + stats.get("medium", 0) * 5
                )
                / max(1, stats.get("total", 0)),
            ),
        )

    # Create control family chart if we have the data
    control_family_html = ""
    if control_families:
        control_family_html = """
        <div class="cato-section">
            <h3>NIST 800-53 Control Family Status</h3>
            <p>This breakdown shows compliance status by control family:</p>
            <table class="control-family-table">
                <tr>
                    <th>Family</th>
                    <th>Controls</th>
                    <th>Compliance</th>
                    <th>Status</th>
                </tr>
        """

        # Sort control families by compliance percentage (ascending)
        sorted_families = sorted(
            control_families.items(),
            key=lambda x: (
                x[1]["compliance_percentage"] if "compliance_percentage" in x[1] else 0
            ),
        )

        # Add rows for each control family
        for family_id, family in sorted_families:
            if family.get("total", 0) > 0:
                compliance = family.get("compliance_percentage", 0)
                color_class = "critical"
                if compliance >= 80:
                    color_class = "low"
                elif compliance >= 50:
                    color_class = "medium"
                elif compliance >= 30:
                    color_class = "high"

                control_family_html += f"""
                <tr>
                    <td><strong>{family_id}</strong></td>
                    <td>{family.get("total", 0)}</td>
                    <td class="{color_class}">{compliance:.1f}%</td>
                    <td>
                        <div class="mini-meter">
                            <span style="width: {compliance}%"></span>
                        </div>
                    </td>
                </tr>
                """

        control_family_html += """
            </table>
            <p class="meter-label">Control families sorted by compliance level (lowest first)</p>
        </div>
        """

    # Create framework section
    framework_section = f"""
    <div id="{framework_id}-analysis" class="framework-section">
        <h2>Test Agency Continuous Authorization to Operate (cATO) Status Update</h2>
        
        <div class="summary">
            <h3>NIST 800-53 Compliance Summary</h3>
            {"<p><strong>Controls:</strong> " + str(stats.get('total', 0)) + "</p>" if has_cato_stats else ""}
            {"<p><strong class='passed'>Passed:</strong> " + str(stats.get('passed', 0)) + "</p>" if has_cato_stats else ""}
            {"<p><strong class='failed'>Failed:</strong> " + str(stats.get('failed', 0)) + "</p>" if has_cato_stats else ""}
            {"<p><strong>Not Applicable:</strong> " + str(stats.get('not_applicable', 0)) + "</p>" if has_cato_stats else ""}
            {"<p><strong>Unknown:</strong> " + str(stats.get('unknown', 0)) + "</p>" if has_cato_stats else ""}
            {"<hr>" if has_cato_stats else ""}
            <p><strong>Security Findings:</strong> {stats.get('total', 0)}</p>
            <p><strong class="critical">Critical:</strong> {stats.get('critical', 0)}</p>
            <p><strong class="high">High:</strong> {stats.get('high', 0)}</p>
            <p><strong class="medium">Medium:</strong> {stats.get('medium', 0)}</p>
            <p><strong class="low">Low:</strong> {stats.get('low', 0)}</p>
        </div>
        
        <div class="cato-section">
            <h3>Current Implementation Status</h3>
            <p>This section provides a status update on the Test Agency's continuous Authorization to Operate (cATO) implementation based on NIST 800-53 control compliance status.</p>
            <div class="meter">
                <span style="width: {cato_readiness}%">cATO Readiness</span>
            </div>
            <p class="meter-label">Current cATO implementation progress: {cato_readiness:.1f}%</p>
        </div>
        
        {control_family_html}

        <div class="analysis-content">
            <p>{formatted_analysis}</p>
        </div>
        
        <div class="cato-section">
            <h3>Recommended Next Steps for cATO Maturity</h3>
            <ul>
                {"<li class='critical-action'>Address critical control failures immediately to maintain cATO compliance</li>" if stats.get('critical', 0) > 0 else ""}
                {"<li class='high-action'>Remediate high severity issues within 7 days to improve cATO posture</li>" if stats.get('high', 0) > 0 else ""}
                {"<li>Focus on improving compliance in low-performing control families</li>"}
                {"<li>Implement continuous monitoring for AC and CM control families</li>"}
                {"<li>Strengthen automation of security assessments</li>"}
                {"<li>Update System Security Plan (SSP) to reflect current controls implementation</li>"}
            </ul>
        </div>
        
        <div class="cato-section">
            <h3>Immediate Actions Required</h3>
            <p>To support ongoing cATO compliance, please prioritize the following actions:</p>
            <ol>
                {"<li>Resolve all <strong class='critical'>" + str(stats.get('critical', 0)) + "</strong> critical findings within 48 hours</li>" if stats.get('critical', 0) > 0 else ""}
                {"<li>Address all <strong class='high'>" + str(stats.get('high', 0)) + "</strong> high severity findings this week</li>" if stats.get('high', 0) > 0 else ""}
                {"<li>Review and update the Plan of Action & Milestones (POA&M) document</li>"}
                {"<li>Schedule cATO implementation review meeting with the security team</li>"}
                {"<li>Run a verification assessment for the most critical control families</li>"}
            </ol>
        </div>
    </div>
    <hr>
    """

    # Create CSS styles
    styles = """
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; color: #333333; }
        h1, h2, h3 { color: #232f3e; }
        .summary { background-color: #f8f8f8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .critical { color: #d13212; }
        .high { color: #ff9900; }
        .medium { color: #d9b43c; }
        .low { color: #6b6b6b; }
        .passed { color: #2bc253; }
        .failed { color: #d13212; }
        .auditor-perspective { 
            background-color: #f0f7ff; 
            padding: 20px; 
            border-left: 5px solid #0073bb; 
            margin: 20px 0; 
            border-radius: 5px;
            font-style: italic;
        }
        .auditor-perspective h2, .auditor-perspective h3 { 
            color: #0073bb; 
            margin-top: 0;
        }
        .framework-section {
            margin-bottom: 30px;
        }
        hr {
            border: 0;
            height: 1px;
            background-color: #d0d0d0;
            margin: 30px 0;
        }
        .framework-nav {
            background-color: #f0f0f0;
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .framework-nav a {
            margin-right: 15px;
            color: #0073bb;
            text-decoration: none;
            font-weight: bold;
        }
        .framework-nav a:hover {
            text-decoration: underline;
        }
        p { line-height: 1.5; margin-bottom: 1em; }
        a { color: #0073bb; }
        ul, ol { margin-bottom: 1em; padding-left: 20px; }
        li { margin-bottom: 0.5em; }
        
        /* cATO specific styling */
        .cato-section {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            border-left: 4px solid #0073bb;
        }
        .critical-action {
            color: #d13212;
            font-weight: bold;
        }
        .high-action {
            color: #ff9900;
            font-weight: bold;
        }
        
        /* Control family table styling */
        .control-family-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        .control-family-table th {
            background-color: #e0e0e0;
            padding: 8px;
            text-align: left;
            font-weight: bold;
        }
        .control-family-table td {
            padding: 8px;
            border-bottom: 1px solid #ddd;
        }
        .control-family-table tr:hover {
            background-color: #f9f9f9;
        }
        
        /* Progress meters */
        .meter { 
            height: 20px;
            position: relative;
            background: #f3f3f3;
            border-radius: 25px;
            padding: 5px;
            box-shadow: inset 0 -1px 1px rgba(255,255,255,0.3);
            margin: 15px 0;
        }
        .meter > span {
            display: block;
            height: 100%;
            border-top-right-radius: 8px;
            border-bottom-right-radius: 8px;
            border-top-left-radius: 20px;
            border-bottom-left-radius: 20px;
            background-color: #2bc253;
            background-image: linear-gradient(
                center bottom,
                rgb(43,194,83) 37%,
                rgb(84,240,84) 69%
            );
            box-shadow: 
                inset 0 2px 9px  rgba(255,255,255,0.3),
                inset 0 -2px 6px rgba(0,0,0,0.4);
            position: relative;
            overflow: hidden;
            text-align: center;
            color: white;
            font-weight: bold;
            text-shadow: 1px 1px 1px rgba(0,0,0,0.5);
            line-height: 20px;
        }
        .meter-label {
            font-size: 0.8em;
            color: #666;
            text-align: center;
            margin-top: 5px;
        }
        
        /* Mini meters for control family table */
        .mini-meter {
            height: 12px;
            position: relative;
            background: #f3f3f3;
            border-radius: 10px;
            width: 100%;
            box-shadow: inset 0 -1px 1px rgba(255,255,255,0.3);
        }
        .mini-meter > span {
            display: block;
            height: 100%;
            border-radius: 10px;
            background-color: #2bc253;
            background-image: linear-gradient(
                center bottom,
                rgb(43,194,83) 37%,
                rgb(84,240,84) 69%
            );
            box-shadow: inset 0 2px 9px rgba(255,255,255,0.3);
            position: relative;
            overflow: hidden;
        }
    </style>
    """

    # Create full HTML
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    {styles}
</head>
<body>
    <h1>{subject}</h1>
    <p>Report generated on 2025-02-28 14:00:00 UTC</p>
    
    {framework_section}
    
    <p>Detailed CSV reports are attached with all findings mapped to their respective framework controls.</p>
</body>
</html>"""

    # Save HTML to file
    with open("debug_email.html", "w") as f:
        f.write(html_content)

    print("\nHTML output saved to debug_email.html")
    print("Open this file in a web browser to see how the email should look")


if __name__ == "__main__":
    debug_email_html()
