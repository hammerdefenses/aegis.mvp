findings = result.get("findings", [])
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
