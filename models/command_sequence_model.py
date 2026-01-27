"""
Command Sequence Model - Behavioral Anomaly Detection
Detects unusual command patterns and sequences using statistical analysis
© 2026 — All rights reserved.
"""

import hashlib
import json
import logging
from collections import Counter, defaultdict
from typing import Dict, List, Any, Set, Tuple
import math

logger = logging.getLogger(__name__)


class CommandSequenceModel:
    """
    Behavioral anomaly detection for command sequences.
    
    Uses statistical analysis to detect unusual command patterns:
    - N-gram analysis of command sequences
    - Frequency-based anomaly scoring
    - Transition probability analysis
    - Time-based pattern recognition
    
    In testing mode, uses simple heuristics. Can be upgraded to:
    - LSTM/RNN for sequence prediction
    - Isolation Forest for anomaly detection
    - One-class SVM for outlier detection
    """
    
    # Anomaly thresholds
    ANOMALY_THRESHOLD = 0.7  # 0-1 scale, higher = more suspicious
    MIN_TRAINING_SAMPLES = 10
    
    def __init__(self, window_size: int = 5):
        """
        Initialize the command sequence model.
        
        Args:
            window_size: Number of recent commands to analyze
        """
        self.window_size = window_size
        self.command_frequency: Counter = Counter()
        self.transition_matrix: Dict[str, Counter] = defaultdict(Counter)
        self.training_sequences: List[List[str]] = []
        self.is_trained = False
        self.total_commands = 0
        
        # Known safe patterns (baseline)
        self.safe_patterns = self._initialize_safe_patterns()
        
        logger.info(f"CommandSequenceModel initialized with window_size={window_size}")
    
    def _initialize_safe_patterns(self) -> Set[str]:
        """Initialize known safe command patterns."""
        return {
            'ls', 'pwd', 'cd', 'cat', 'echo', 'grep', 'find', 'which',
            'whoami', 'date', 'hostname', 'uname', 'df', 'du', 'ps',
            'top', 'free', 'uptime', 'man', 'help', 'clear', 'history',
            'git status', 'git log', 'git diff', 'git branch',
            'python --version', 'node --version', 'npm --version',
        }
    
    def train(self, training_sequences: List[List[str]]) -> None:
        """
        Train the model on historical command sequences.
        
        Args:
            training_sequences: List of command sequence lists
        """
        logger.info(f"Training model on {len(training_sequences)} sequences...")
        
        self.training_sequences = training_sequences
        
        # Build frequency distribution
        for sequence in training_sequences:
            for i, cmd in enumerate(sequence):
                # Normalize command to base form
                base_cmd = self._get_base_command(cmd)
                self.command_frequency[base_cmd] += 1
                self.total_commands += 1
                
                # Build transition matrix (what follows what)
                if i < len(sequence) - 1:
                    next_cmd = self._get_base_command(sequence[i + 1])
                    self.transition_matrix[base_cmd][next_cmd] += 1
        
        self.is_trained = len(self.training_sequences) >= self.MIN_TRAINING_SAMPLES
        
        logger.info(
            f"Model trained: {self.total_commands} commands, "
            f"{len(self.command_frequency)} unique commands"
        )
    
    def evaluate(self, command_sequence: List[str]) -> Dict[str, Any]:
        """
        Evaluate a command sequence for anomalies.
        
        Args:
            command_sequence: List of recent commands (size = window_size)
            
        Returns:
            Dictionary containing:
                - anomaly_score: Float 0-1 (higher = more suspicious)
                - is_anomaly: Boolean flag
                - reasons: List of anomaly indicators
                - details: Additional scoring details
        """
        if len(command_sequence) < self.window_size:
            return {
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "reasons": ["Insufficient command history"],
                "details": {}
            }
        
        # Normalize commands
        normalized_seq = [self._get_base_command(cmd) for cmd in command_sequence]
        
        # Calculate various anomaly scores
        frequency_score = self._calculate_frequency_score(normalized_seq)
        transition_score = self._calculate_transition_score(normalized_seq)
        pattern_score = self._calculate_pattern_score(normalized_seq)
        velocity_score = self._calculate_velocity_score(normalized_seq)
        
        # Weighted combination
        anomaly_score = (
            frequency_score * 0.3 +
            transition_score * 0.3 +
            pattern_score * 0.2 +
            velocity_score * 0.2
        )
        
        # Collect reasons
        reasons = []
        if frequency_score > 0.7:
            reasons.append("Rare command usage detected")
        if transition_score > 0.7:
            reasons.append("Unusual command sequence")
        if pattern_score > 0.7:
            reasons.append("Atypical behavior pattern")
        if velocity_score > 0.7:
            reasons.append("Abnormal command velocity")
        
        is_anomaly = anomaly_score >= self.ANOMALY_THRESHOLD
        
        logger.info(
            f"Anomaly evaluation: score={anomaly_score:.3f}, "
            f"is_anomaly={is_anomaly}"
        )
        
        return {
            "anomaly_score": round(anomaly_score, 3),
            "is_anomaly": is_anomaly,
            "reasons": reasons if reasons else ["Normal behavior"],
            "details": {
                "frequency_score": round(frequency_score, 3),
                "transition_score": round(transition_score, 3),
                "pattern_score": round(pattern_score, 3),
                "velocity_score": round(velocity_score, 3),
            }
        }
    
    def _get_base_command(self, command: str) -> str:
        """
        Extract base command from full command string.
        
        Args:
            command: Full command string
            
        Returns:
            Base command (first word or two)
        """
        # Remove leading/trailing whitespace
        cmd = command.strip()
        
        # Handle pipes and redirects
        if '|' in cmd:
            cmd = cmd.split('|')[0].strip()
        if '>' in cmd:
            cmd = cmd.split('>')[0].strip()
        if '<' in cmd:
            cmd = cmd.split('<')[0].strip()
        
        # Get first 1-2 words (handles "git status", "docker ps", etc.)
        parts = cmd.split()
        if not parts:
            return ""
        
        if len(parts) == 1:
            return parts[0]
        
        # Check if it's a known two-word command
        two_word = f"{parts[0]} {parts[1]}"
        common_two_word = {
            'git', 'docker', 'kubectl', 'npm', 'yarn', 
            'pip', 'conda', 'apt', 'yum', 'systemctl'
        }
        
        if parts[0] in common_two_word:
            return two_word
        
        return parts[0]
    
    def _calculate_frequency_score(self, commands: List[str]) -> float:
        """
        Calculate anomaly score based on command frequency.
        Rare commands get higher scores.
        
        Args:
            commands: List of normalized commands
            
        Returns:
            Anomaly score 0-1
        """
        if not self.is_trained or self.total_commands == 0:
            # In untrained mode, check against safe patterns
            unknown_count = sum(1 for cmd in commands if cmd not in self.safe_patterns)
            return unknown_count / len(commands)
        
        # Calculate rarity based on training data
        rarities = []
        for cmd in commands:
            frequency = self.command_frequency.get(cmd, 0)
            probability = frequency / self.total_commands if self.total_commands > 0 else 0
            
            # Rarity score (inverse of probability)
            if probability == 0:
                rarity = 1.0  # Never seen before
            else:
                rarity = 1.0 - probability
            
            rarities.append(rarity)
        
        # Return average rarity
        return sum(rarities) / len(rarities) if rarities else 0.0
    
    def _calculate_transition_score(self, commands: List[str]) -> float:
        """
        Calculate anomaly score based on command transitions.
        Unusual sequences get higher scores.
        
        Args:
            commands: List of normalized commands
            
        Returns:
            Anomaly score 0-1
        """
        if not self.is_trained or len(commands) < 2:
            return 0.0
        
        # Calculate transition probabilities
        unusual_transitions = 0
        total_transitions = len(commands) - 1
        
        for i in range(len(commands) - 1):
            current = commands[i]
            next_cmd = commands[i + 1]
            
            if current not in self.transition_matrix:
                unusual_transitions += 1
                continue
            
            # Get transition count
            transition_count = self.transition_matrix[current].get(next_cmd, 0)
            total_from_current = sum(self.transition_matrix[current].values())
            
            if total_from_current == 0:
                unusual_transitions += 1
            else:
                transition_prob = transition_count / total_from_current
                if transition_prob < 0.1:  # Less than 10% of the time
                    unusual_transitions += 1
        
        return unusual_transitions / total_transitions if total_transitions > 0 else 0.0
    
    def _calculate_pattern_score(self, commands: List[str]) -> float:
        """
        Calculate anomaly score based on dangerous patterns.
        
        Args:
            commands: List of normalized commands
            
        Returns:
            Anomaly score 0-1
        """
        dangerous_patterns = {
            'rm', 'dd', 'mkfs', 'shred', 'sudo rm', 'sudo dd',
            'curl', 'wget', 'nc', 'netcat', 'ssh', 'scp',
            'chmod', 'chown', 'usermod', 'passwd',
        }
        
        privilege_commands = {'sudo', 'su', 'doas'}
        destructive_commands = {'rm', 'dd', 'mkfs', 'shred'}
        
        score = 0.0
        
        # Check for dangerous patterns
        dangerous_count = sum(1 for cmd in commands if cmd in dangerous_patterns)
        score += (dangerous_count / len(commands)) * 0.5
        
        # Check for privilege escalation followed by destructive command
        for i in range(len(commands) - 1):
            if commands[i] in privilege_commands and commands[i + 1] in destructive_commands:
                score += 0.5
        
        # Check for rapid network operations
        network_commands = {'curl', 'wget', 'nc', 'netcat', 'ssh', 'scp', 'ftp'}
        network_count = sum(1 for cmd in commands if cmd in network_commands)
        if network_count >= 3:
            score += 0.3
        
        return min(score, 1.0)
    
    def _calculate_velocity_score(self, commands: List[str]) -> float:
        """
        Calculate anomaly score based on command velocity/diversity.
        
        Args:
            commands: List of normalized commands
            
        Returns:
            Anomaly score 0-1
        """
        # Check for unusual diversity
        unique_commands = len(set(commands))
        diversity_ratio = unique_commands / len(commands)
        
        # Very high diversity might indicate exploration/reconnaissance
        if diversity_ratio > 0.8:
            return 0.7
        
        # Very low diversity (repeated commands) might be automated
        if diversity_ratio < 0.2:
            return 0.6
        
        # Check for rapid identical commands (possible script/automation)
        for cmd in set(commands):
            count = commands.count(cmd)
            if count >= 3:  # Same command 3+ times in window
                return 0.5
        
        return 0.0
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get model statistics and training info.
        
        Returns:
            Dictionary with model stats
        """
        return {
            "is_trained": self.is_trained,
            "total_commands": self.total_commands,
            "unique_commands": len(self.command_frequency),
            "training_sequences": len(self.training_sequences),
            "window_size": self.window_size,
            "anomaly_threshold": self.ANOMALY_THRESHOLD,
            "top_commands": self.command_frequency.most_common(10),
        }


def _test_sequence_model():
    """Test the CommandSequenceModel with sample data."""
    print("\nTesting CommandSequenceModel:")
    print("=" * 60)
    
    # Create model
    model = CommandSequenceModel(window_size=5)
    
    # Training data (normal user behavior)
    training_data = [
        ["ls -la", "cd project", "git status", "git pull", "python test.py"],
        ["pwd", "ls", "cat README.md", "vim main.py", "python main.py"],
        ["git status", "git add .", "git commit -m 'fix'", "git push", "echo done"],
        ["docker ps", "docker logs app", "docker exec app bash", "exit", "ls"],
        ["cd /home", "ls", "cd user", "pwd", "ls -l"],
    ]
    
    model.train(training_data)
    
    # Test sequences
    test_sequences = [
        ("Normal", ["ls", "cd test", "git status", "python run.py", "echo done"]),
        ("Suspicious", ["sudo su", "rm -rf /tmp", "curl evil.com", "bash", "wget malware"]),
        ("Mixed", ["ls", "sudo rm -rf /tmp", "git status", "python test.py", "echo ok"]),
    ]
    
    for label, sequence in test_sequences:
        print(f"\n[{label}] Sequence: {sequence}")
        result = model.evaluate(sequence)
        print(f"  Anomaly Score: {result['anomaly_score']}")
        print(f"  Is Anomaly: {result['is_anomaly']}")
        print(f"  Reasons: {', '.join(result['reasons'])}")
        print(f"  Details: {result['details']}")
    
    # Print statistics
    print("\nModel Statistics:")
    stats = model.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    _test_sequence_model()
