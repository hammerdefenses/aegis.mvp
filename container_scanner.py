"""
Advanced Integrated Modules (A.I.M.) // Container Scanner Module
Project Epsilon
© 2026 — All rights reserved.
"""

import subprocess
import json
import sys
from datetime import datetime, timezone

def scan_container(image_name: str, trivy_path: str = "trivy", timeout_sec: int = 300) -> dict:
    """
    Scans container images or Dockerfiles with real Trivy.
    Returns dict with vulnerabilities, severity breakdown, confidence scores.
    """
    result = {
        "target": image_name,
        "status": "scan_complete",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_vulnerabilities": 0,
        "severity_breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "NEGLIGIBLE": 0},
        "vulnerabilities": []
    }

    # Basic input validation
    if not image_name or len(image_name) > 256 or '\x00' in image_name:
        result["status"] = "invalid_input"
        result["error"] = "Invalid image name"
        return result

    cmd = [trivy_path, "image", "--format", "json", "--quiet", image_name]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        # Log for debugging
        print(f"Trivy command: {' '.join(shlex.quote(arg) for arg in cmd)}", file=sys.stderr)
        print(f"Trivy stdout length: {len(proc.stdout)}", file=sys.stderr)
        print(f"Trivy stderr: {proc.stderr.strip()}", file=sys.stderr)

        if proc.returncode == 0:
            trivy_output = json.loads(proc.stdout)
            if "Results" in trivy_output:
                for res in trivy_output["Results"]:
                    if "Vulnerabilities" in res:
                        for vuln in res["Vulnerabilities"]:
                            result["total_vulnerabilities"] += 1
                            sev = vuln.get("Severity", "UNKNOWN")
                            result["severity_breakdown"][sev] = result["severity_breakdown"].get(sev, 0) + 1
                            result["vulnerabilities"].append({
                                "VulnerabilityID": vuln.get("VulnerabilityID"),
                                "PkgName": vuln.get("PkgName"),
                                "Severity": sev,
                                "confidence_score": 8  # TODO: Derive from CVSS/EPSS
                            })
        else:
            result["status"] = "failed"
            result["error"] = f"Trivy failed (exit {proc.returncode}): {proc.stderr.strip()}"

    except subprocess.TimeoutExpired as e:
        result["status"] = "timeout"
        result["error"] = f"Trivy scan timed out after {timeout_sec}s"
    except json.JSONDecodeError as e:
        result["status"] = "parse_error"
        result["error"] = f"Invalid JSON from Trivy: {e}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Unexpected error: {str(e)}"

    return result
