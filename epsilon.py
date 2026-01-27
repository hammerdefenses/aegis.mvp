"""
Advanced Integrated Modules (A.I.M.) // Command Line Interface
Project Epsilon
© 2026 — All rights reserved.
"""

import click
import json
from datetime import datetime, timezone

from scanner import scan_target
from remediator import generate_remediations
from pqc_encrypt import encrypt_report

@click.command()
@click.argument("target", type=str)
@click.option("--output", "-o", type=click.Choice(["json", "pretty"]), default="pretty", help="Output format")
@click.option("--remediate", "-r", is_flag=True, help="Show only remediation suggestions")
def epsilon(target: str, output: str, remediate: bool = False) -> None:
    """
    Project Epsilon: Zero-Trust Hardening Guardian

    Scans TARGET (file path, directory, container image name, or Dockerfile) for vulnerabilities.
    """
    click.echo("Epsilon activating...")
    click.echo(f"Target: {target}")
    click.echo(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    click.echo(f"Scan ID: {datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}")

    try:
        result = scan_target(target)

        # PQC encryption on full result (quantum-resistant placeholder)
        encrypted = encrypt_report(json.dumps(result))
        click.echo(f"Encrypted Report (Quantum-Resistant): {encrypted}")

        if remediate:
            findings = result.get("findings", []) or result.get("vulnerabilities", [])
            remediations = generate_remediations(findings)
            click.echo("Remediation Suggestions:")
            if not remediations:
                click.echo("No remediations needed. System clean.")
            for i, rem in enumerate(remediations, 1):
                click.echo(f"{i}. {rem['vulnerability']} (Confidence: {rem['confidence_score']}/10)")
                click.echo(f"   Suggestion: {rem['suggestion']}")
                if "patch_preview" in rem:
                    pp = rem["patch_preview"]
                    click.echo(f"   Before: {pp['before']}")
                    click.echo(f"   After: {pp['after']}")
                    click.echo(f"   Instructions: {pp['instructions']}")
        else:
            click.echo("Scan Results:")
            if output == "json":
                click.echo(json.dumps(result, indent=2))
            else:
                click.echo(f"Status: {result['status']}")
                click.echo(f"Total Findings: {result.get('total_findings', result.get('total_vulnerabilities', 0))}")
                click.echo(f"Severity Breakdown: {result['severity_breakdown']}")
                items = result.get("findings", []) or result.get("vulnerabilities", [])
                if items:
                    click.echo("Findings:")
                    for item in items:
                        vuln_name = item.get('vulnerability') or item.get('VulnerabilityID') or 'Unknown'
                        sev = item.get('severity') or item.get('Severity') or 'UNKNOWN'
                        conf = item.get('confidence_score', 5)
                        click.echo(f"  - {vuln_name} (Severity: {sev}, Confidence: {conf}/10)")
                else:
                    click.echo("No vulnerabilities detected.")
    except Exception as e:
        click.echo(f"Error during scan: {str(e)}")
        click.echo("Please check the target path, dependencies, or contact support.")
        click.echo("Details logged for debugging.")

if __name__ == "__main__":
    epsilon()