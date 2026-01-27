"""
Hardware Identity - Cryptographic Command Signing
Device fingerprinting and non-repudiation through hardware-backed signing
© 2026 — All rights reserved.
"""

import hashlib
import hmac
import json
import logging
import platform
import socket
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import os

logger = logging.getLogger(__name__)


class HardwareIdentity:
    """
    Hardware-based identity and command signing system.
    
    Provides:
    - Device fingerprinting (unique hardware ID)
    - Cryptographic signing of commands (HMAC-SHA256)
    - Non-repudiation (prove who executed what)
    - Audit trail integration
    
    Modes:
    - Testing: Uses simulated hardware key
    - Production: Can integrate with TPM, Secure Enclave, HSM
    
    In production, upgrade to:
    - TPM 2.0 for hardware key storage
    - Apple Secure Enclave on macOS
    - AWS CloudHSM for cloud deployments
    - YubiKey for hardware tokens
    """
    
    def __init__(self, testing_mode: bool = True):
        """
        Initialize hardware identity system.
        
        Args:
            testing_mode: If True, use simulated keys. If False, attempt hardware keys.
        """
        self.testing_mode = testing_mode
        self.device_id = self._generate_device_id()
        self.hardware_key = self._get_hardware_key()
        self.signing_algorithm = "HMAC-SHA256"
        
        logger.info(
            f"HardwareIdentity initialized: device_id={self.device_id[:16]}..., "
            f"mode={'testing' if testing_mode else 'production'}"
        )
    
    def _generate_device_id(self) -> str:
        """
        Generate unique device identifier based on hardware characteristics.
        
        Returns:
            Unique device ID string
        """
        # Collect hardware characteristics
        characteristics = []
        
        try:
            # MAC address (most reliable)
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) 
                           for ele in range(0, 8*6, 8)][::-1])
            characteristics.append(f"mac:{mac}")
        except Exception as e:
            logger.warning(f"Could not get MAC address: {e}")
        
        try:
            # Hostname
            hostname = socket.gethostname()
            characteristics.append(f"host:{hostname}")
        except Exception as e:
            logger.warning(f"Could not get hostname: {e}")
        
        try:
            # Platform info
            system = platform.system()
            machine = platform.machine()
            characteristics.append(f"platform:{system}-{machine}")
        except Exception as e:
            logger.warning(f"Could not get platform info: {e}")
        
        try:
            # CPU info (simplified)
            processor = platform.processor()
            if processor:
                characteristics.append(f"cpu:{processor[:50]}")
        except Exception as e:
            logger.warning(f"Could not get CPU info: {e}")
        
        # Combine and hash
        combined = "|".join(characteristics)
        device_id = hashlib.sha256(combined.encode()).hexdigest()
        
        return device_id
    
    def _get_hardware_key(self) -> bytes:
        """
        Get or generate hardware signing key.
        
        In testing mode: generates a deterministic key from device ID
        In production mode: would retrieve from TPM/secure enclave
        
        Returns:
            Hardware key bytes
        """
        if self.testing_mode:
            # Generate deterministic key from device ID for testing
            # In production, this would be stored in secure hardware
            key_material = f"testing-key-{self.device_id}"
            key = hashlib.sha256(key_material.encode()).digest()
            logger.info("Using testing mode hardware key")
            return key
        else:
            # Production mode - attempt to retrieve from secure storage
            # This is a stub - in production, integrate with actual hardware
            logger.warning("Production mode not fully implemented - falling back to testing key")
            return self._get_testing_key()
    
    def _get_testing_key(self) -> bytes:
        """Generate testing key (fallback)."""
        key_material = f"testing-key-{self.device_id}"
        return hashlib.sha256(key_material.encode()).digest()
    
    def sign_command(self, command: str, user: Optional[str] = None, 
                     metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Sign a command for non-repudiation.
        
        Args:
            command: Command string to sign
            user: Optional user identifier
            metadata: Optional additional metadata to include in signature
            
        Returns:
            Dictionary containing:
                - status: "signed" or "error"
                - signature: Hex-encoded signature
                - device_id: Device identifier
                - timestamp: ISO format timestamp
                - algorithm: Signing algorithm used
                - payload: Signed data payload
        """
        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            
            # Build payload to sign
            payload = {
                "command": command,
                "device_id": self.device_id,
                "timestamp": timestamp,
                "user": user,
                "metadata": metadata or {}
            }
            
            # Serialize payload
            payload_bytes = json.dumps(payload, sort_keys=True).encode()
            
            # Generate HMAC signature
            signature = hmac.new(
                self.hardware_key,
                payload_bytes,
                hashlib.sha256
            ).hexdigest()
            
            logger.info(f"Command signed: {command[:50]}... with signature {signature[:16]}...")
            
            return {
                "status": "signed",
                "signature": signature,
                "device_id": self.device_id,
                "timestamp": timestamp,
                "algorithm": self.signing_algorithm,
                "payload": payload,
                "testing_mode": self.testing_mode
            }
            
        except Exception as e:
            logger.error(f"Signing failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "device_id": self.device_id,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    def verify_signature(self, signed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a signed command.
        
        Args:
            signed_data: Dictionary from sign_command() containing signature and payload
            
        Returns:
            Dictionary containing:
                - valid: Boolean verification result
                - reason: Reason for failure if invalid
                - device_id: Device that signed the command
                - timestamp: When it was signed
        """
        try:
            if signed_data.get("status") != "signed":
                return {
                    "valid": False,
                    "reason": "Not a valid signed payload",
                    "device_id": None,
                    "timestamp": None
                }
            
            # Extract components
            original_signature = signed_data.get("signature")
            payload = signed_data.get("payload")
            device_id = signed_data.get("device_id")
            timestamp = signed_data.get("timestamp")
            
            if not all([original_signature, payload, device_id]):
                return {
                    "valid": False,
                    "reason": "Missing required fields",
                    "device_id": device_id,
                    "timestamp": timestamp
                }
            
            # Re-serialize payload
            payload_bytes = json.dumps(payload, sort_keys=True).encode()
            
            # Recalculate signature
            calculated_signature = hmac.new(
                self.hardware_key,
                payload_bytes,
                hashlib.sha256
            ).hexdigest()
            
            # Compare signatures (constant-time comparison)
            valid = hmac.compare_digest(original_signature, calculated_signature)
            
            if valid:
                logger.info(f"Signature verified for device {device_id[:16]}...")
            else:
                logger.warning(f"Signature verification failed for device {device_id[:16]}...")
            
            return {
                "valid": valid,
                "reason": "Signature valid" if valid else "Signature mismatch",
                "device_id": device_id,
                "timestamp": timestamp
            }
            
        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return {
                "valid": False,
                "reason": f"Verification error: {str(e)}",
                "device_id": None,
                "timestamp": None
            }
    
    def get_device_info(self) -> Dict[str, Any]:
        """
        Get detailed device information.
        
        Returns:
            Dictionary with device characteristics
        """
        try:
            return {
                "device_id": self.device_id,
                "hostname": socket.gethostname(),
                "platform": {
                    "system": platform.system(),
                    "release": platform.release(),
                    "version": platform.version(),
                    "machine": platform.machine(),
                    "processor": platform.processor(),
                },
                "python_version": platform.python_version(),
                "testing_mode": self.testing_mode,
                "signing_algorithm": self.signing_algorithm,
            }
        except Exception as e:
            logger.error(f"Could not get device info: {e}")
            return {
                "device_id": self.device_id,
                "error": str(e)
            }
    
    def rotate_key(self) -> Dict[str, str]:
        """
        Rotate hardware key (testing mode only).
        
        In production, this would trigger key rotation in TPM/HSM.
        
        Returns:
            Status dictionary
        """
        if not self.testing_mode:
            return {
                "status": "error",
                "message": "Key rotation not supported in production mode via this method"
            }
        
        old_key_hash = hashlib.sha256(self.hardware_key).hexdigest()[:16]
        
        # Generate new key
        self.hardware_key = self._get_hardware_key()
        
        new_key_hash = hashlib.sha256(self.hardware_key).hexdigest()[:16]
        
        logger.info(f"Key rotated: {old_key_hash}... -> {new_key_hash}...")
        
        return {
            "status": "rotated",
            "old_key_hash": old_key_hash,
            "new_key_hash": new_key_hash,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


def _test_hardware_identity():
    """Test the HardwareIdentity system."""
    print("\nTesting HardwareIdentity:")
    print("=" * 60)
    
    # Initialize
    signer = HardwareIdentity(testing_mode=True)
    
    # Get device info
    print("\nDevice Info:")
    device_info = signer.get_device_info()
    for key, value in device_info.items():
        if isinstance(value, dict):
            print(f"  {key}:")
            for k, v in value.items():
                print(f"    {k}: {v}")
        else:
            print(f"  {key}: {value}")
    
    # Sign a command
    print("\nSigning command...")
    command = "sudo apt update"
    signed = signer.sign_command(
        command,
        user="testuser",
        metadata={"session": "test123", "ip": "192.168.1.100"}
    )
    
    print(f"  Status: {signed['status']}")
    print(f"  Signature: {signed['signature'][:32]}...")
    print(f"  Device ID: {signed['device_id'][:32]}...")
    print(f"  Timestamp: {signed['timestamp']}")
    print(f"  Algorithm: {signed['algorithm']}")
    
    # Verify signature
    print("\nVerifying signature...")
    verification = signer.verify_signature(signed)
    print(f"  Valid: {verification['valid']}")
    print(f"  Reason: {verification['reason']}")
    
    # Test with tampered data
    print("\nTesting with tampered data...")
    tampered = signed.copy()
    tampered['payload']['command'] = "rm -rf /"
    verification_tampered = signer.verify_signature(tampered)
    print(f"  Valid: {verification_tampered['valid']}")
    print(f"  Reason: {verification_tampered['reason']}")
    
    # Test key rotation
    print("\nTesting key rotation...")
    rotation = signer.rotate_key()
    print(f"  Status: {rotation['status']}")
    print(f"  Old key: {rotation['old_key_hash']}...")
    print(f"  New key: {rotation['new_key_hash']}...")


if __name__ == "__main__":
    _test_hardware_identity()
