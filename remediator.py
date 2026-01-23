"""
Advanced Integrated Modules (A.I.M.) // Remediation Module
Project Epsilon
© 2026 — All rights reserved.
"""

def generate_remediations(findings: list) -> list:
    """
    Generates remediation suggestions for detected findings.
    Returns list of dicts with suggestion, confidence score, patch preview.
    """
    remediations = []

    for finding in findings:
        severity = finding.get("severity", "LOW")
        confidence = finding.get("confidence_score", 5)

        if "hard coded password" in finding["vulnerability"].lower():
            suggestion = "Move sensitive values to environment variables or secure vault."
            patch_preview = {
                "before": "password = 'hardcoded_password'",
                "after": "password = os.getenv('SECRET_PASSWORD')",
                "instructions": "Use os.getenv() to load from environment."
            }
        elif "exec detected" in finding["vulnerability"].lower():
            suggestion = "Replace exec() with ast.literal_eval() for safe literal evaluation."
            patch_preview = {
                "before": "result = exec(user_input)",
                "after": "result = ast.literal_eval(user_input)",
                "instructions": "ast.literal_eval() is safe for literals only."
            }
        else:
            suggestion = "Manual review recommended."
            patch_preview = {"before": "", "after": "", "instructions": "No auto-fix available."}

        remediations.append({
            "vulnerability": finding["vulnerability"],
            "severity": severity,
            "confidence_score": confidence,
            "suggestion": suggestion,
            "patch_preview": patch_preview
        })

    return remediations
