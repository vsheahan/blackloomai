#!/usr/bin/env python3
"""
BlackLoom Defense - Sensitive Data Cleanup Script
Removes sensitive files and data before committing to version control
"""

import os
import sys
import shutil
import glob
import json
from pathlib import Path


class SensitiveDataCleaner:
 """Clean up sensitive files and data from the BlackLoom Defense repository"""

 def __init__(self, repo_root: str = "."):
 self.repo_root = Path(repo_root).resolve()
 self.removed_files = []
 self.cleaned_files = []

 def clean_all(self, dry_run: bool = False):
 """Clean all sensitive data"""
 print(f" Starting sensitive data cleanup...")
 print(f"Repository root: {self.repo_root}")

 if dry_run:
 print(" DRY RUN MODE - No files will be modified")

 # Clean different types of sensitive data
 self._clean_system_files(dry_run)
 self._clean_python_cache(dry_run)
 self._clean_crypto_keys(dry_run)
 self._clean_model_registry(dry_run)
 self._clean_logs_and_databases(dry_run)
 self._clean_temp_directories(dry_run)

 # Summary
 print(f"\n Cleanup Summary:")
 print(f" Files removed: {len(self.removed_files)}")
 print(f" Files cleaned: {len(self.cleaned_files)}")

 if self.removed_files:
 print(f"\n🗑️ Removed files:")
 for file_path in self.removed_files:
 print(f" - {file_path}")

 if self.cleaned_files:
 print(f"\n✨ Cleaned files:")
 for file_path in self.cleaned_files:
 print(f" - {file_path}")

 print(f"\n Sensitive data cleanup completed!")

 def _clean_system_files(self, dry_run: bool):
 """Remove system-generated files"""
 print("\n Cleaning system files...")

 patterns = [
 "**/.DS_Store",
 "**/Thumbs.db",
 "**/desktop.ini",
 "**/*.tmp",
 "**/*.temp",
 "**/*.swp",
 "**/*.swo"
 ]

 for pattern in patterns:
 for file_path in self.repo_root.glob(pattern):
 self._remove_file(file_path, dry_run, "System file")

 def _clean_python_cache(self, dry_run: bool):
 """Remove Python cache files and directories"""
 print("\n Cleaning Python cache...")

 # __pycache__ directories
 for cache_dir in self.repo_root.glob("**/__pycache__"):
 self._remove_directory(cache_dir, dry_run, "Python cache")

 # .pyc files
 for pyc_file in self.repo_root.glob("**/*.pyc"):
 self._remove_file(pyc_file, dry_run, "Python bytecode")

 # .pyo files
 for pyo_file in self.repo_root.glob("**/*.pyo"):
 self._remove_file(pyo_file, dry_run, "Python optimized bytecode")

 def _clean_crypto_keys(self, dry_run: bool):
 """Remove cryptographic keys and certificates"""
 print("\n Cleaning cryptographic keys...")

 key_patterns = [
 "**/*.key",
 "**/*.pem",
 "**/*.crt",
 "**/*.p12",
 "**/*.pfx",
 "**/private_keys/**",
 "**/certificates/**"
 ]

 for pattern in key_patterns:
 for file_path in self.repo_root.glob(pattern):
 if file_path.is_file():
 self._remove_file(file_path, dry_run, "Cryptographic key")
 elif file_path.is_dir():
 self._remove_directory(file_path, dry_run, "Key directory")

 def _clean_model_registry(self, dry_run: bool):
 """Clean model registry files containing sensitive paths"""
 print("\n Cleaning model registry...")

 registry_files = [
 "models_registry.json",
 "model_registry.json",
 "registered_models.json"
 ]

 for filename in registry_files:
 registry_path = self.repo_root / filename
 if registry_path.exists():
 if dry_run:
 print(f" Would remove: {registry_path} (Model registry)")
 else:
 self._anonymize_registry_file(registry_path)

 def _clean_logs_and_databases(self, dry_run: bool):
 """Remove logs and database files"""
 print("\n Cleaning logs and databases...")

 patterns = [
 "**/*.log",
 "**/*.db",
 "**/*.sqlite",
 "**/*.sqlite3",
 "**/logs/**",
 "**/audit_logs/**"
 ]

 for pattern in patterns:
 for file_path in self.repo_root.glob(pattern):
 if file_path.is_file():
 self._remove_file(file_path, dry_run, "Log/Database file")
 elif file_path.is_dir():
 self._remove_directory(file_path, dry_run, "Log directory")

 def _clean_temp_directories(self, dry_run: bool):
 """Remove temporary directories and files"""
 print("\n Cleaning temporary directories...")

 temp_patterns = [
 "**/tmp/**",
 "**/temp/**",
 "**/cache/**",
 "**/.cache/**",
 "**/uploads/**"
 ]

 for pattern in temp_patterns:
 for path in self.repo_root.glob(pattern):
 if path.is_dir():
 self._remove_directory(path, dry_run, "Temporary directory")
 elif path.is_file():
 self._remove_file(path, dry_run, "Temporary file")

 def _remove_file(self, file_path: Path, dry_run: bool, file_type: str):
 """Remove a single file"""
 if dry_run:
 print(f" Would remove: {file_path} ({file_type})")
 else:
 try:
 file_path.unlink()
 self.removed_files.append(str(file_path.relative_to(self.repo_root)))
 print(f" Removed: {file_path.relative_to(self.repo_root)} ({file_type})")
 except Exception as e:
 print(f" Error removing {file_path}: {e}")

 def _remove_directory(self, dir_path: Path, dry_run: bool, dir_type: str):
 """Remove a directory and all its contents"""
 if dry_run:
 print(f" Would remove: {dir_path}/ ({dir_type})")
 else:
 try:
 shutil.rmtree(dir_path)
 self.removed_files.append(str(dir_path.relative_to(self.repo_root)) + "/")
 print(f" Removed: {dir_path.relative_to(self.repo_root)}/ ({dir_type})")
 except Exception as e:
 print(f" Error removing {dir_path}: {e}")

 def _anonymize_registry_file(self, registry_path: Path):
 """Anonymize sensitive data in registry files instead of removing them"""
 try:
 with open(registry_path, 'r') as f:
 data = json.load(f)

 # Create anonymized version
 anonymized_data = {
 "updated": "ANONYMIZED_TIMESTAMP",
 "models": {}
 }

 # Add example entries without sensitive paths
 if data.get("models"):
 anonymized_data["models"] = {
 "example-model:1.0": {
 "name": "example-model",
 "version": "1.0",
 "path": "/path/to/model/files",
 "manifest_path": "/path/to/manifest.json",
 "public_key_path": "/path/to/public.key",
 "last_verified": None,
 "integrity_status": "unknown",
 "metadata": {
 "note": "This is an example entry. Real registry data has been anonymized."
 }
 }
 }

 # Write anonymized version
 with open(registry_path, 'w') as f:
 json.dump(anonymized_data, f, indent=4)

 self.cleaned_files.append(str(registry_path.relative_to(self.repo_root)))
 print(f" Anonymized: {registry_path.relative_to(self.repo_root)} (Model registry)")

 except Exception as e:
 print(f" Error anonymizing {registry_path}: {e}")

 def create_gitkeep_files(self, dry_run: bool = False):
 """Create .gitkeep files in important empty directories"""
 print("\n Creating .gitkeep files for important directories...")

 important_dirs = [
 "blackloom_defense/logs",
 "blackloom_defense/integrity/audit_logs",
 "models",
 "certificates",
 "private_keys",
 "test_results"
 ]

 for dir_name in important_dirs:
 dir_path = self.repo_root / dir_name
 if not dry_run:
 dir_path.mkdir(parents=True, exist_ok=True)
 gitkeep_path = dir_path / ".gitkeep"
 if not gitkeep_path.exists():
 gitkeep_path.write_text("# This file ensures the directory is tracked in git\n")
 print(f" Created: {gitkeep_path.relative_to(self.repo_root)}")
 else:
 print(f" Would create: {dir_name}/.gitkeep")


def main():
 """Main function"""
 import argparse

 parser = argparse.ArgumentParser(description="Clean sensitive data from BlackLoom Defense repository")
 parser.add_argument("--dry-run", action="store_true", help="Show what would be removed without actually removing")
 parser.add_argument("--create-gitkeep", action="store_true", help="Create .gitkeep files in important directories")
 parser.add_argument("--repo-root", default=".", help="Repository root directory")

 args = parser.parse_args()

 cleaner = SensitiveDataCleaner(args.repo_root)

 try:
 cleaner.clean_all(dry_run=args.dry_run)

 if args.create_gitkeep:
 cleaner.create_gitkeep_files(dry_run=args.dry_run)

 except KeyboardInterrupt:
 print("\n Cleanup interrupted by user")
 sys.exit(1)
 except Exception as e:
 print(f"\n Error during cleanup: {e}")
 sys.exit(1)


if __name__ == "__main__":
 main()