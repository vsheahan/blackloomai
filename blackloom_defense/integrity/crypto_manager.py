"""
BlackLoom Defense - Cryptographic Key Management
Handles RSA key generation, signing, and verification for model integrity
"""

import os
import base64
import json
from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from getpass import getpass
import logging


class CryptoManager:
 """
 Manages cryptographic operations for BlackLoom model integrity verification
 Provides secure key generation, digital signing, and signature verification
 """

 def __init__(self):
 self.logger = logging.getLogger(__name__)

 def generate_key_pair(self,
 key_name: str,
 output_dir: str = ".",
 key_size: int = 2048,
 password: Optional[str] = None) -> Tuple[str, str]:
 """
 Generate a new RSA key pair for model signing

 Args:
 key_name: Name for the key pair files
 output_dir: Directory to save keys
 key_size: RSA key size (default 2048)
 password: Password for private key (prompt if None)

 Returns:
 Tuple of (private_key_path, public_key_path)
 """
 os.makedirs(output_dir, exist_ok=True)

 # Generate RSA key pair
 private_key = rsa.generate_private_key(
 public_exponent=65537,
 key_size=key_size
 )
 public_key = private_key.public_key()

 # Get password for private key encryption
 if password is None:
 password = getpass("Enter password to encrypt private key: ")
 confirm_password = getpass("Confirm password: ")

 if password != confirm_password:
 raise ValueError("Passwords do not match")

 # Save private key (encrypted)
 private_key_path = os.path.join(output_dir, f"{key_name}.pem")
 with open(private_key_path, "wb") as f:
 f.write(private_key.private_bytes(
 encoding=serialization.Encoding.PEM,
 format=serialization.PrivateFormat.PKCS8,
 encryption_algorithm=serialization.BestAvailableEncryption(
 password.encode()
 )
 ))

 # Save public key
 public_key_path = os.path.join(output_dir, f"{key_name}.pub")
 with open(public_key_path, "wb") as f:
 f.write(public_key.public_bytes(
 encoding=serialization.Encoding.PEM,
 format=serialization.PublicFormat.SubjectPublicKeyInfo
 ))

 # Set secure file permissions
 os.chmod(private_key_path, 0o600) # Private key readable only by owner
 os.chmod(public_key_path, 0o644) # Public key readable by all

 self.logger.info(f"Generated RSA key pair: {key_name}")
 return private_key_path, public_key_path

 def load_private_key(self, private_key_path: str, password: Optional[str] = None):
 """
 Load and decrypt a private key

 Args:
 private_key_path: Path to the private key file
 password: Password to decrypt (prompt if None)

 Returns:
 Loaded private key object
 """
 if password is None:
 password = getpass("Enter password for private key: ")

 with open(private_key_path, "rb") as key_file:
 private_key = serialization.load_pem_private_key(
 key_file.read(),
 password=password.encode()
 )

 return private_key

 def load_public_key(self, public_key_path: str):
 """
 Load a public key for verification

 Args:
 public_key_path: Path to the public key file

 Returns:
 Loaded public key object
 """
 with open(public_key_path, "rb") as key_file:
 public_key = serialization.load_pem_public_key(key_file.read())

 return public_key

 def sign_data(self, data: bytes, private_key_path: str, password: Optional[str] = None) -> str:
 """
 Sign data with a private key using PSS padding

 Args:
 data: Data to sign
 private_key_path: Path to private key
 password: Private key password

 Returns:
 Base64-encoded signature
 """
 private_key = self.load_private_key(private_key_path, password)

 signature = private_key.sign(
 data,
 padding.PSS(
 mgf=padding.MGF1(hashes.SHA256()),
 salt_length=padding.PSS.MAX_LENGTH
 ),
 hashes.SHA256()
 )

 return base64.b64encode(signature).decode()

 def verify_signature(self,
 data: bytes,
 signature: str,
 public_key_path: str) -> bool:
 """
 Verify a signature using a public key

 Args:
 data: Original data that was signed
 signature: Base64-encoded signature
 public_key_path: Path to public key

 Returns:
 True if signature is valid, False otherwise
 """
 try:
 public_key = self.load_public_key(public_key_path)
 signature_bytes = base64.b64decode(signature)

 public_key.verify(
 signature_bytes,
 data,
 padding.PSS(
 mgf=padding.MGF1(hashes.SHA256()),
 salt_length=padding.PSS.MAX_LENGTH
 ),
 hashes.SHA256()
 )

 return True

 except InvalidSignature:
 self.logger.warning("Invalid signature detected")
 return False
 except Exception as e:
 self.logger.error(f"Signature verification error: {e}")
 return False

 def create_trusted_keys_file(self, keys_config: dict, output_path: str = "trusted_keys.json"):
 """
 Create a trusted keys configuration file

 Args:
 keys_config: Dictionary of trusted keys with metadata
 output_path: Path to save the trusted keys file
 """
 with open(output_path, 'w') as f:
 json.dump(keys_config, f, indent=4)

 self.logger.info(f"Created trusted keys file: {output_path}")

 def load_trusted_key(self, key_name: str, trusted_keys_path: str = "trusted_keys.json"):
 """
 Load a public key from the trusted keys file

 Args:
 key_name: Name of the trusted key
 trusted_keys_path: Path to trusted keys file

 Returns:
 Public key object or None if not found
 """
 try:
 with open(trusted_keys_path, "r") as f:
 trusted_keys = json.load(f)

 for key_info in trusted_keys.get("keys", []):
 if key_info["name"] == key_name:
 return serialization.load_pem_public_key(
 key_info["key"].encode()
 )

 self.logger.warning(f"Trusted key '{key_name}' not found")
 return None

 except FileNotFoundError:
 self.logger.error(f"Trusted keys file not found: {trusted_keys_path}")
 return None
 except Exception as e:
 self.logger.error(f"Error loading trusted key: {e}")
 return None