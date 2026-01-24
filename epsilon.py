import click
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

from scanner import scan_target
from remediator import generate_remediations
from pqc_encrypt import encrypt_report

@click.command()
@click.argument("target", type=str)
@click.option("--output", "-o", type=click.Choice(["json", "pretty"]), default="pretty")
@click.option("--remediate", "-r", is_flag=True, help="Show remediation suggestions")
@click.option("--encrypt", is_flag=True, help="Output PQC-encrypted report")
@click.option("--no-cache", is_flag=True, help="Force fresh scan (skip cache)")
@click.option("--verbose", "-v", is_flag=True, help="Detailed output")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
def epsilon(target: str, output: str, remediate: bool, encrypt: bool, 
            no_cache: bool, verbose: bool, quiet: bool) -> None:
    """
    Project Epsilon: Zero-Trust Hardening Guardian

    Scans TARGET (file, directory, container image, or Dockerfile) for vulnerabilities.
    """
    # Validate input
    if not target or not target.strip():
        click.echo("Error: TARGET cannot be empty", err=True)
        sys.exit(1)
    
    # Display header
    scan_time = datetime.now(timezone.utc)
    if not quiet:
        click.echo("Epsilon activating...")
        click.echo(f"Target: {target}")
        if verbose:
            click.echo(f"Timestamp: {scan_time.isoformat()}")
            click.echo(f"Scan ID: {scan_time.strftime('%Y%m%d-%H%M%S')}")
            click.echo(f"Cache: {'disabled' if no_cache else 'enabled'}")

    try:
        result = scan_target(target, use_cache=not no_cache)
        
        # Handle encryption request
        if encrypt:
            encrypted = encrypt_report(json.dumps(result))
            click.echo(encrypted)
            return  # Don't show plaintext

        # Handle remediation view
        if remediate:
            findings = result.get("findings", []) or result.get("vulnerabilities", [])
            remediations = generate_remediations(findings)
            
            if not quiet:
                click.echo("\nRemediation Suggestions:")
            
            if not remediations:
                click.echo("✓ No remediations needed. System clean.")
                sys.exit(0)
            
            for i, rem in enumerate(remediations, 1):
                click.echo(f"\n{i}. {rem['vulnerability']} (Confidence: {rem['confidence_score']}/10)")
                click.echo(f"   Suggestion: {rem['suggestion']}")
                if "patch_preview" in rem:
                    pp = rem["patch_preview"]
                    click.echo(f"   Before: {pp['before']}")
                    click.echo(f"   After:  {pp['after']}")
                    if verbose:
                        click.echo(f"   Instructions: {pp['instructions']}")
        else:
            # Display scan results
            if output == "json":
                click.echo(json.dumps(result, indent=2))
            else:
                if not quiet:
                    click.echo("\nScan Results:")
                click.echo(f"Status: {result['status']}")
                
                total = result.get('total_findings', result.get('total_vulnerabilities', 0))
                click.echo(f"Total Findings: {total}")
                click.echo(f"Severity Breakdown: {result['severity_breakdown']}")
                
                items = result.get("findings", []) or result.get("vulnerabilities", [])
                if items:
                    click.echo("\nFindings:")
                    for item in items:
                        vuln_name = item.get('vulnerability') or item.get('VulnerabilityID') or 'Unknown'
                        sev = item.get('severity') or item.get('Severity') or 'UNKNOWN'
                        conf = item.get('confidence_score', 5)
                        click.echo(f"  - {vuln_name} (Severity: {sev}, Confidence: {conf}/10)")
                else:
                    click.echo("✓ No vulnerabilities detected.")
        
        # Exit with appropriate code
        critical_count = result['severity_breakdown'].get('CRITICAL', 0)
        if critical_count > 0:
            if not quiet:
                click.echo(f"\n⚠ Warning: {critical_count} CRITICAL vulnerabilities found!", err=True)
            sys.exit(1)
    
    except FileNotFoundError:
        click.echo(f"Error: Target not found: {target}", err=True)
        sys.exit(2)
    except ValueError as e:
        click.echo(f"Error: Invalid input: {str(e)}", err=True)
        sys.exit(2)
    except RuntimeError as e:
        click.echo(f"Error: Scan failed: {str(e)}", err=True)
        if verbose:
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(2)
    except Exception as e:
        click.echo(f"Unexpected error: {str(e)}", err=True)
        click.echo(f"Scan ID: {scan_time.strftime('%Y%m%d-%H%M%S')}", err=True)
        if verbose:
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(3)

if __name__ == "__main__":
    epsilon()
