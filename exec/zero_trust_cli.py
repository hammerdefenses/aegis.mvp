# zero_trust_cli.py
"""
Hammer Defense Industries - Aegis
Zero-Compromise Command-Line Hardening Platform
Real-time prediction, enforcement, and MITRE ATT&CK mapping
"""

import os
import sys
import subprocess
import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("aegis")

# Simple MITRE map (expand as needed)
MITRE_TECHNIQUES = {
    # Execution
    "bash": {"id": "T1059.004", "name": "Unix Shell"},
    "sh": {"id": "T1059.004", "name": "Unix Shell"},
    "python": {"id": "T1059.006", "name": "Python"},
    # Privilege Escalation
    "sudo": {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
    "su": {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
    # Credential Access
    "shadow": {"id": "T1003", "name": "OS Credential Dumping"},
    "passwd": {"id": "T1003", "name": "OS Credential Dumping"},
    # Discovery
    "whoami": {"id": "T1033", "name": "System Owner/User Discovery"},
    # Defense Evasion
    "rm": {"id": "T1070", "name": "Indicator Removal"},
}

def map_to_mitre(command: str) -> List[Dict]:
    """Map command to MITRE ATT&CK techniques."""
    matches = []
    lower_cmd = command.lower().strip()
    for keyword, tech in MITRE_TECHNIQUES.items():
        if keyword in lower_cmd:
            matches.append(tech)
    return matches

class ZeroTrustCLI:
    def __init__(self, user: str = "unknown", device: str = "unknown"):
        self.user = user
        self.device = device
        self.session_token = os.urandom(16).hex()

    def execute(self, command: str) -> Dict[str, Any]:
        timestamp = datetime.now(timezone.utc).isoformat()
        audit_id = hashlib.sha256(f"{command}{self.session_token}{timestamp}".encode()).hexdigest()[:16]

        logger.info(f"[EXEC] Audit ID: {audit_id} | User: {self.user} | Command: {command[:100]}... | Time: {timestamp}")

        # MITRE Mapping
        mitre_matches = map_to_mitre(command)
        mitre_summary = [f"{m['id']} - {m['name']}" for m in mitre_matches]

        # Risk Scoring & Policy Check
        risk_score = 0
        is_blocked = False

        if mitre_matches:
            risk_score = max(40, len(mitre_matches) * 20)
            is_blocked = risk_score > 60  # Only block HIGH/CRITICAL, flag MEDIUM

        normalized = command.lower().strip()
        if "sudo su" in normalized or "su -" in normalized:
            risk_score = max(risk_score, 40)
            is_blocked = True
        elif "cat /etc/shadow" in normalized:
            risk_score = max(risk_score, 80)
            is_blocked = True

        if is_blocked:
            logger.warning(f"[BLOCKED] Audit ID: {audit_id} | Risk: {risk_score}/100 | MITRE: {mitre_summary}")
            briefing = self.generate_briefing(command, risk_score, mitre_matches)
            return {
                "status": "blocked",
                "risk_score": risk_score,
                "mitre_tags": mitre_summary,
                "briefing": briefing,
                "message": "Command blocked by zero-trust policy"
            }

        # Log flagged-but-allowed commands
        if mitre_matches:
            logger.warning(f"[FLAGGED] Audit ID: {audit_id} | Risk: {risk_score}/100 | MITRE: {mitre_summary} | Executing with monitoring")

        # Safe Execution
        env = os.environ.copy()
        timeout = 5 if "sudo" in normalized else 30

        try:
            proc = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env
            )
            output = {
                "status": "success",
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "returncode": proc.returncode,
                "risk_score": risk_score,
                "mitre_tags": mitre_summary
            }
            logger.info(f"[SUCCESS] Audit ID: {audit_id} | Code: {proc.returncode}")
        except subprocess.TimeoutExpired:
            output = {"status": "timeout", "error": "Command timed out"}
            logger.error(f"[TIMEOUT] Audit ID: {audit_id}")
        except Exception as e:
            output = {"status": "error", "error": str(e)}
            logger.error(f"[ERROR] Audit ID: {audit_id} | {str(e)}")

        return output

    def generate_briefing(self, command: str, risk_score: int, mitre_tags: List[Dict]) -> Dict[str, Any]:
        threat_level = "CRITICAL" if risk_score > 70 else "HIGH" if risk_score > 40 else "MEDIUM"
        return {
            "threat_level": threat_level,
            "summary": f"High-risk command attempted: {command}",
            "mitre_mappings": [f"{t['id']} - {t['name']}" for t in mitre_tags],
            "recommendations": [
                "Investigate user activity immediately",
                "Review access logs for this session",
                "Lock account if anomalous pattern continues"
            ],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

if __name__ == "__main__":
    cli = ZeroTrustCLI(user="testuser", device="testdevice")

    if len(sys.argv) < 2:
        print("Usage: python3 zero_trust_cli.py <command>")
        sys.exit(1)

    command = " ".join(sys.argv[1:])
    result = cli.execute(command)
    print(result)
