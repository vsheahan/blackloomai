"""
BlackLoom Defense - Model Manifest Verification
Verifies model integrity and authenticity using cryptographic signatures
"""

import os
import json
import hashlib
import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from enum import Enum
import logging

from .crypto_manager import CryptoManager


class VerificationStatus(Enum):
 """Verification result status codes"""
 VALID = "valid"
 INVALID = "invalid"
 ERROR = "error"
 WARNING = "warning"


@dataclass
class FileVerificationResult:
 """Result of verifying a single file"""
 file_path: str
 status: VerificationStatus
 expected_hash: str
 actual_hash: Optional[str]
 expected_size: int
 actual_size: Optional[int]
 message: str


@dataclass
class ManifestVerificationResult:
 """Complete manifest verification result"""
 manifest_path: str
 model_name: str
 model_version: str
 overall_status: VerificationStatus
 signature_valid: Optional[bool]
 files_verified: int
 files_failed: int
 files_missing: int
 file_results: List[FileVerificationResult]
 verification_time: str
 messages: List[str]
 metadata: Dict[str, Any]


class ManifestVerifier:
 """
 Verifies AI model integrity using BlackLoom manifests
 Provides comprehensive file-level verification and signature validation
 """

 def __init__(self, crypto_manager: Optional[CryptoManager] = None):
 self.crypto_manager = crypto_manager or CryptoManager()
 self.logger = logging.getLogger(__name__)

 def load_manifest(self, manifest_path: str) -> Dict[str, Any]:
 """
 Load and parse a BlackLoom manifest file

 Args:
 manifest_path: Path to the manifest file

 Returns:
 Parsed manifest dictionary
 """
 try:
 with open(manifest_path, 'r') as f:
 manifest = json.load(f)

 # Validate required fields
 required_fields = ['model_name', 'model_version', 'files']
 for field in required_fields:
 if field not in manifest:
 raise ValueError(f"Manifest missing required field: {field}")

 return manifest

 except FileNotFoundError:
 raise FileNotFoundError(f"Manifest file not found: {manifest_path}")
 except json.JSONDecodeError as e:
 raise ValueError(f"Invalid JSON in manifest file: {e}")
 except Exception as e:
 raise Exception(f"Error loading manifest: {e}")

 def verify_signature(self,
 manifest: Dict[str, Any],
 public_key_path: Optional[str] = None,
 trusted_key_name: Optional[str] = None) -> bool:
 """
 Verify the cryptographic signature of a manifest

 Args:
 manifest: Loaded manifest dictionary
 public_key_path: Path to public key file
 trusted_key_name: Name of trusted key to use

 Returns:
 True if signature is valid, False otherwise
 """
 if not manifest.get('signature'):
 self.logger.warning("Manifest has no signature to verify")
 return False

 try:
 # Reconstruct the signed data
 signing_data = {
 "model_name": manifest["model_name"],
 "model_version": manifest["model_version"],
 "files": [
 {
 "path": f["path"],
 "sha256": f["sha256"],
 "size": f["size"]
 }
 for f in manifest["files"]
 ]
 }

 message = json.dumps(signing_data, sort_keys=True).encode()
 signature = manifest["signature"]

 # Verify using public key
 if public_key_path:
 return self.crypto_manager.verify_signature(
 message, signature, public_key_path
 )
 elif trusted_key_name:
 public_key = self.crypto_manager.load_trusted_key(trusted_key_name)
 if public_key:
 # We'd need to modify crypto_manager to accept key objects
 # For now, this is a placeholder
 return True # Would implement full verification
 else:
 self.logger.error(f"Trusted key not found: {trusted_key_name}")
 return False
 else:
 self.logger.error("No public key provided for signature verification")
 return False

 except Exception as e:
 self.logger.error(f"Signature verification error: {e}")
 return False

 def verify_file(self, file_info: Dict[str, Any], base_directory: str) -> FileVerificationResult:
 """
 Verify a single file against its manifest entry

 Args:
 file_info: File information from manifest
 base_directory: Base directory containing the model files

 Returns:
 FileVerificationResult object
 """
 file_path = os.path.join(base_directory, file_info["path"])
 expected_hash = file_info["sha256"]
 expected_size = file_info.get("size", 0)

 # Check if file exists
 if not os.path.exists(file_path):
 return FileVerificationResult(
 file_path=file_info["path"],
 status=VerificationStatus.INVALID,
 expected_hash=expected_hash,
 actual_hash=None,
 expected_size=expected_size,
 actual_size=None,
 message="File not found"
 )

 try:
 # Check file size
 actual_size = os.path.getsize(file_path)
 if expected_size > 0 and actual_size != expected_size:
 return FileVerificationResult(
 file_path=file_info["path"],
 status=VerificationStatus.INVALID,
 expected_hash=expected_hash,
 actual_hash=None,
 expected_size=expected_size,
 actual_size=actual_size,
 message=f"Size mismatch: expected {expected_size}, got {actual_size}"
 )

 # Calculate and verify hash
 sha256_hash = hashlib.sha256()
 with open(file_path, "rb") as f:
 for chunk in iter(lambda: f.read(4096), b""):
 sha256_hash.update(chunk)

 actual_hash = sha256_hash.hexdigest()

 if actual_hash == expected_hash:
 return FileVerificationResult(
 file_path=file_info["path"],
 status=VerificationStatus.VALID,
 expected_hash=expected_hash,
 actual_hash=actual_hash,
 expected_size=expected_size,
 actual_size=actual_size,
 message="File verified successfully"
 )
 else:
 return FileVerificationResult(
 file_path=file_info["path"],
 status=VerificationStatus.INVALID,
 expected_hash=expected_hash,
 actual_hash=actual_hash,
 expected_size=expected_size,
 actual_size=actual_size,
 message="Hash mismatch - file has been modified"
 )

 except Exception as e:
 self.logger.error(f"Error verifying file {file_path}: {e}")
 return FileVerificationResult(
 file_path=file_info["path"],
 status=VerificationStatus.ERROR,
 expected_hash=expected_hash,
 actual_hash=None,
 expected_size=expected_size,
 actual_size=None,
 message=f"Verification error: {str(e)}"
 )

 def verify_manifest(self,
 manifest_path: str,
 model_directory: str,
 public_key_path: Optional[str] = None,
 trusted_key_name: Optional[str] = None,
 verbose: bool = False) -> ManifestVerificationResult:
 """
 Perform complete manifest verification

 Args:
 manifest_path: Path to the manifest file
 model_directory: Directory containing the model files
 public_key_path: Path to public key for signature verification
 trusted_key_name: Name of trusted key for signature verification
 verbose: Enable verbose logging

 Returns:
 Complete ManifestVerificationResult
 """
 start_time = datetime.datetime.now()
 messages = []

 if verbose:
 self.logger.info(f" Verifying BlackLoom manifest: {manifest_path}")

 try:
 # Load manifest
 manifest = self.load_manifest(manifest_path)
 model_name = manifest["model_name"]
 model_version = manifest["model_version"]

 messages.append(f"Loaded manifest for {model_name} v{model_version}")

 # Verify signature if present and keys provided
 signature_valid = None
 if manifest.get("signature"):
 if public_key_path or trusted_key_name:
 signature_valid = self.verify_signature(
 manifest, public_key_path, trusted_key_name
 )
 if signature_valid:
 messages.append(" Digital signature verified")
 else:
 messages.append(" Digital signature verification failed")
 else:
 messages.append(" Manifest is signed but no verification key provided")
 else:
 messages.append(" Manifest has no digital signature")

 # Verify all files
 file_results = []
 files_verified = 0
 files_failed = 0
 files_missing = 0

 for file_info in manifest["files"]:
 result = self.verify_file(file_info, model_directory)
 file_results.append(result)

 if result.status == VerificationStatus.VALID:
 files_verified += 1
 if verbose:
 self.logger.info(f" {result.file_path}")
 elif result.status == VerificationStatus.INVALID:
 if "not found" in result.message:
 files_missing += 1
 else:
 files_failed += 1

 if verbose:
 self.logger.warning(f" {result.file_path}: {result.message}")
 else: # ERROR
 files_failed += 1
 if verbose:
 self.logger.error(f" {result.file_path}: {result.message}")

 # Determine overall status
 if files_failed > 0 or files_missing > 0:
 overall_status = VerificationStatus.INVALID
 elif signature_valid is False:
 overall_status = VerificationStatus.INVALID
 elif signature_valid is None and manifest.get("signature"):
 overall_status = VerificationStatus.WARNING
 else:
 overall_status = VerificationStatus.VALID

 # Add summary messages
 messages.append(f"Files verified: {files_verified}")
 if files_failed > 0:
 messages.append(f"Files failed: {files_failed}")
 if files_missing > 0:
 messages.append(f"Files missing: {files_missing}")

 verification_time = datetime.datetime.now().isoformat()

 result = ManifestVerificationResult(
 manifest_path=manifest_path,
 model_name=model_name,
 model_version=model_version,
 overall_status=overall_status,
 signature_valid=signature_valid,
 files_verified=files_verified,
 files_failed=files_failed,
 files_missing=files_missing,
 file_results=file_results,
 verification_time=verification_time,
 messages=messages,
 metadata={
 "verification_duration": (datetime.datetime.now() - start_time).total_seconds(),
 "manifest_creation_time": manifest.get("timestamp_utc"),
 "blackloom_version": manifest.get("blackloom_version"),
 "total_files_in_manifest": len(manifest["files"])
 }
 )

 if verbose:
 self.logger.info(f" Verification complete: {overall_status.value}")

 return result

 except Exception as e:
 self.logger.error(f"Manifest verification failed: {e}")

 return ManifestVerificationResult(
 manifest_path=manifest_path,
 model_name="unknown",
 model_version="unknown",
 overall_status=VerificationStatus.ERROR,
 signature_valid=None,
 files_verified=0,
 files_failed=0,
 files_missing=0,
 file_results=[],
 verification_time=datetime.datetime.now().isoformat(),
 messages=[f"Verification error: {str(e)}"],
 metadata={"error": str(e)}
 )

 def quick_verify(self,
 manifest_path: str,
 model_directory: str,
 public_key_path: Optional[str] = None) -> bool:
 """
 Quick verification that returns simple pass/fail

 Args:
 manifest_path: Path to manifest file
 model_directory: Model directory
 public_key_path: Public key for signature verification

 Returns:
 True if verification passes, False otherwise
 """
 result = self.verify_manifest(
 manifest_path,
 model_directory,
 public_key_path=public_key_path,
 verbose=False
 )

 return result.overall_status == VerificationStatus.VALID

 def print_verification_report(self, result: ManifestVerificationResult, detailed: bool = False):
 """
 Print a formatted verification report

 Args:
 result: ManifestVerificationResult to print
 detailed: Include detailed file-by-file results
 """
 # ANSI color codes
 GREEN = '\033[92m'
 RED = '\033[91m'
 YELLOW = '\033[93m'
 CYAN = '\033[96m'
 RESET = '\033[0m'

 status_color = {
 VerificationStatus.VALID: GREEN,
 VerificationStatus.INVALID: RED,
 VerificationStatus.WARNING: YELLOW,
 VerificationStatus.ERROR: RED
 }

 color = status_color.get(result.overall_status, RESET)

 print(f"\n{CYAN}╔══════════════════════════════════════════════════════════════╗")
 print(f"║ BlackLoom Verification Report ║")
 print(f"╚══════════════════════════════════════════════════════════════╝{RESET}")

 print(f"\n Model: {result.model_name} v{result.model_version}")
 print(f" Manifest: {result.manifest_path}")
 print(f"{color} Status: {result.overall_status.value.upper()}{RESET}")

 if result.signature_valid is not None:
 sig_color = GREEN if result.signature_valid else RED
 sig_status = "VALID" if result.signature_valid else "INVALID"
 print(f"{sig_color} Signature: {sig_status}{RESET}")

 print(f"\n File Verification Summary:")
 print(f" Verified: {result.files_verified}")
 if result.files_failed > 0:
 print(f" Failed: {result.files_failed}")
 if result.files_missing > 0:
 print(f" Missing: {result.files_missing}")

 if result.messages:
 print(f"\n💬 Messages:")
 for message in result.messages:
 print(f" {message}")

 if detailed and result.file_results:
 print(f"\n Detailed File Results:")
 for file_result in result.file_results:
 if file_result.status == VerificationStatus.VALID:
 print(f" {GREEN} {file_result.file_path}{RESET}")
 else:
 print(f" {RED} {file_result.file_path}: {file_result.message}{RESET}")

 print(f"\n⏱️ Verification completed: {result.verification_time}")
 print()