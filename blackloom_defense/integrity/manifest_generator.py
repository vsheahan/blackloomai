"""
BlackLoom Defense - Model Manifest Generation
Creates cryptographically signed manifests for AI model integrity verification
"""

import os
import json
import hashlib
import datetime
from typing import Optional, Dict, List, Set
from dataclasses import dataclass
import logging

from .crypto_manager import CryptoManager


@dataclass
class FileManifest:
 """Represents a file in the model manifest"""
 name: str
 path: str
 sha256: str
 size: int
 modified_time: str


@dataclass
class ModelManifest:
 """Complete model manifest with metadata"""
 model_name: str
 model_version: str
 created_by: str
 organization: str
 timestamp_utc: str
 timestamp_local: str
 blackloom_version: str
 files: List[FileManifest]
 signature: Optional[str] = None
 metadata: Optional[Dict] = None


class ManifestGenerator:
 """
 Generates cryptographically signed manifests for AI models
 Provides complete file-level integrity verification and provenance tracking
 """

 def __init__(self, crypto_manager: Optional[CryptoManager] = None):
 self.crypto_manager = crypto_manager or CryptoManager()
 self.logger = logging.getLogger(__name__)

 # Files and directories to ignore during manifest generation
 self.ignore_dirs: Set[str] = {
 ".git", "__pycache__", ".cache", "keys", ".DS_Store",
 "node_modules", ".venv", "venv", ".env", "logs", "tmp"
 }

 self.ignore_files: Set[str] = {
 ".DS_Store", ".gitignore", ".env", "Thumbs.db",
 "desktop.ini", ".blackloom_manifest.json"
 }

 self.ignore_extensions: Set[str] = {
 ".log", ".tmp", ".swp", ".bak", ".pyc"
 }

 def calculate_file_hash(self, file_path: str) -> str:
 """
 Calculate SHA-256 hash of a file

 Args:
 file_path: Path to the file

 Returns:
 Hexadecimal SHA-256 hash
 """
 sha256_hash = hashlib.sha256()

 try:
 with open(file_path, "rb") as f:
 # Read file in chunks to handle large files efficiently
 for chunk in iter(lambda: f.read(4096), b""):
 sha256_hash.update(chunk)

 return sha256_hash.hexdigest()

 except Exception as e:
 self.logger.error(f"Error hashing file {file_path}: {e}")
 raise

 def should_ignore_file(self, file_path: str, filename: str) -> bool:
 """
 Check if a file should be ignored during manifest generation

 Args:
 file_path: Full path to the file
 filename: Name of the file

 Returns:
 True if file should be ignored
 """
 # Check filename
 if filename in self.ignore_files:
 return True

 # Check file extension
 _, ext = os.path.splitext(filename)
 if ext.lower() in self.ignore_extensions:
 return True

 # Check if it's a hidden file (starts with .)
 if filename.startswith('.') and filename not in {'.env'}:
 return True

 return False

 def scan_directory(self, directory: str, verbose: bool = False) -> List[FileManifest]:
 """
 Scan directory and generate file manifests

 Args:
 directory: Root directory to scan
 verbose: Enable verbose logging

 Returns:
 List of FileManifest objects
 """
 files = []
 directory = os.path.abspath(directory)

 if verbose:
 self.logger.info(f"Scanning directory: {directory}")

 for root, dirs, filenames in os.walk(directory):
 # Filter out ignored directories
 dirs[:] = [d for d in dirs if d not in self.ignore_dirs]

 for filename in filenames:
 file_path = os.path.join(root, filename)

 # Skip ignored files
 if self.should_ignore_file(file_path, filename):
 continue

 try:
 # Get file stats
 stat = os.stat(file_path)
 relative_path = os.path.relpath(file_path, directory)

 if verbose:
 self.logger.info(f" Processing: {relative_path}")

 # Calculate file hash
 file_hash = self.calculate_file_hash(file_path)

 # Create file manifest
 file_manifest = FileManifest(
 name=filename,
 path=relative_path,
 sha256=file_hash,
 size=stat.st_size,
 modified_time=datetime.datetime.fromtimestamp(
 stat.st_mtime
 ).isoformat()
 )

 files.append(file_manifest)

 except Exception as e:
 self.logger.error(f"Error processing file {file_path}: {e}")
 continue

 if verbose:
 self.logger.info(f"Processed {len(files)} files")

 return files

 def generate_manifest(self,
 directory: str,
 model_name: str,
 model_version: str,
 created_by: str,
 organization: str = "BlackLoom AI",
 private_key_path: Optional[str] = None,
 password: Optional[str] = None,
 metadata: Optional[Dict] = None,
 verbose: bool = False) -> ModelManifest:
 """
 Generate a complete model manifest with optional cryptographic signature

 Args:
 directory: Model directory to scan
 model_name: Name of the model
 model_version: Version of the model
 created_by: Person/system creating the manifest
 organization: Organization name
 private_key_path: Path to private key for signing (optional)
 password: Private key password (optional, will prompt)
 metadata: Additional metadata to include
 verbose: Enable verbose logging

 Returns:
 Complete ModelManifest object
 """
 if verbose:
 self.logger.info("Generating BlackLoom model manifest...")

 # Scan directory for files
 files = self.scan_directory(directory, verbose)

 # Create base manifest
 now_utc = datetime.datetime.now(datetime.timezone.utc)
 now_local = datetime.datetime.now()

 manifest = ModelManifest(
 model_name=model_name,
 model_version=model_version,
 created_by=created_by,
 organization=organization,
 timestamp_utc=now_utc.isoformat(),
 timestamp_local=now_local.isoformat(),
 blackloom_version="0.1.0",
 files=files,
 metadata=metadata or {}
 )

 # Add security metadata
 manifest.metadata.update({
 "total_files": len(files),
 "total_size_bytes": sum(f.size for f in files),
 "scan_directory": os.path.abspath(directory),
 "integrity_algorithm": "SHA-256",
 "signature_algorithm": "RSA-PSS" if private_key_path else None
 })

 # Sign manifest if private key provided
 if private_key_path:
 if verbose:
 self.logger.info("Signing manifest with private key...")

 # Create deterministic data for signing
 signing_data = {
 "model_name": manifest.model_name,
 "model_version": manifest.model_version,
 "files": [
 {
 "path": f.path,
 "sha256": f.sha256,
 "size": f.size
 }
 for f in manifest.files
 ]
 }

 message = json.dumps(signing_data, sort_keys=True).encode()

 try:
 signature = self.crypto_manager.sign_data(
 message, private_key_path, password
 )
 manifest.signature = signature

 if verbose:
 self.logger.info(" Manifest successfully signed")

 except Exception as e:
 self.logger.error(f"Failed to sign manifest: {e}")
 raise

 return manifest

 def save_manifest(self,
 manifest: ModelManifest,
 output_path: Optional[str] = None,
 directory: Optional[str] = None) -> str:
 """
 Save manifest to JSON file

 Args:
 manifest: ModelManifest to save
 output_path: Specific output file path
 directory: Directory to save manifest in (auto-generate filename)

 Returns:
 Path to saved manifest file
 """
 if output_path:
 manifest_path = output_path
 elif directory:
 filename = f".blackloom_manifest_{manifest.model_name}_{manifest.model_version}.json"
 manifest_path = os.path.join(directory, filename)
 else:
 filename = f"blackloom_manifest_{manifest.model_name}_{manifest.model_version}.json"
 manifest_path = filename

 # Ensure output directory exists
 os.makedirs(os.path.dirname(manifest_path) or ".", exist_ok=True)

 # Convert to dict for JSON serialization
 manifest_dict = {
 "model_name": manifest.model_name,
 "model_version": manifest.model_version,
 "created_by": manifest.created_by,
 "organization": manifest.organization,
 "timestamp_utc": manifest.timestamp_utc,
 "timestamp_local": manifest.timestamp_local,
 "blackloom_version": manifest.blackloom_version,
 "files": [
 {
 "name": f.name,
 "path": f.path,
 "sha256": f.sha256,
 "size": f.size,
 "modified_time": f.modified_time
 }
 for f in manifest.files
 ],
 "signature": manifest.signature,
 "metadata": manifest.metadata
 }

 with open(manifest_path, 'w') as f:
 json.dump(manifest_dict, f, indent=4, sort_keys=True)

 self.logger.info(f" Manifest saved to: {manifest_path}")
 return manifest_path

 def generate_and_save(self,
 directory: str,
 model_name: str,
 model_version: str,
 created_by: str,
 organization: str = "BlackLoom AI",
 private_key_path: Optional[str] = None,
 password: Optional[str] = None,
 output_path: Optional[str] = None,
 metadata: Optional[Dict] = None,
 verbose: bool = False) -> str:
 """
 Generate and save a model manifest in one operation

 Args:
 directory: Model directory to scan
 model_name: Name of the model
 model_version: Version of the model
 created_by: Person/system creating the manifest
 organization: Organization name
 private_key_path: Path to private key for signing (optional)
 password: Private key password (optional)
 output_path: Output file path (optional, auto-generate if None)
 metadata: Additional metadata
 verbose: Enable verbose logging

 Returns:
 Path to saved manifest file
 """
 manifest = self.generate_manifest(
 directory=directory,
 model_name=model_name,
 model_version=model_version,
 created_by=created_by,
 organization=organization,
 private_key_path=private_key_path,
 password=password,
 metadata=metadata,
 verbose=verbose
 )

 return self.save_manifest(
 manifest,
 output_path=output_path,
 directory=directory if not output_path else None
 )