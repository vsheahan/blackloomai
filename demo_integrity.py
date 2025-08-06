#!/usr/bin/env python3
"""
BlackLoom AI - Model Integrity System Demo
Demonstrates the comprehensive model integrity and auditing capabilities
"""

import os
import tempfile
import shutil
from blackloom_defense.integrity import (
 ModelIntegrityManager,
 CryptoManager,
 ManifestGenerator,
 ManifestVerifier
)
from blackloom_defense.integrity.audit_logger import AccessType


def print_banner():
 """Print the BlackLoom AI banner"""
 banner = """
╔══════════════════════════════════════════════════════════════╗
║ BlackLoom AI - Model Integrity Demo ║
║ Comprehensive AI Model Protection & Auditing ║
║ Addresses OWASP ML05 (Model Theft) & ML10 ║
╚══════════════════════════════════════════════════════════════╝
"""
 print(banner)


def print_section(title: str):
 """Print a section header"""
 print(f"\n{'='*70}")
 print(f" {title}")
 print('='*70)


def create_demo_model():
 """Create a demo model directory with sample files"""
 # Create temporary directory for demo model
 model_dir = tempfile.mkdtemp(prefix="blackloom_demo_model_")

 # Create sample model files
 files_to_create = {
 "model.safetensors": b"Mock model weights data " * 100,
 "config.json": b'{"model_type": "transformer", "vocab_size": 32000}',
 "tokenizer.json": b'{"model": {"vocab": {"<pad>": 0, "<s>": 1}}}',
 "README.md": b"# Demo Model\n\nThis is a demo AI model for BlackLoom testing.",
 "requirements.txt": b"torch>=2.0.0\ntransformers>=4.30.0",
 "training_log.txt": b"Epoch 1: Loss 2.45\nEpoch 2: Loss 1.98\nEpoch 3: Loss 1.67"
 }

 for filename, content in files_to_create.items():
 filepath = os.path.join(model_dir, filename)
 os.makedirs(os.path.dirname(filepath), exist_ok=True)
 with open(filepath, 'wb') as f:
 f.write(content)

 print(f" Created demo model at: {model_dir}")
 return model_dir


def demo_key_generation():
 """Demonstrate cryptographic key generation"""
 print_section("CRYPTOGRAPHIC KEY GENERATION")

 print(" Generating RSA key pair for model signing...")

 crypto_manager = CryptoManager()

 # Create temporary directory for keys
 key_dir = tempfile.mkdtemp(prefix="blackloom_demo_keys_")

 try:
 # Generate key pair with demo password
 private_key_path, public_key_path = crypto_manager.generate_key_pair(
 key_name="blackloom-demo",
 output_dir=key_dir,
 key_size=2048,
 password="demo123" # In production, use strong passwords
 )

 print(f" Keys generated successfully:")
 print(f" Private Key: {private_key_path}")
 print(f" 🔓 Public Key: {public_key_path}")

 # Show key file sizes
 private_size = os.path.getsize(private_key_path)
 public_size = os.path.getsize(public_key_path)

 print(f" Private key size: {private_size} bytes")
 print(f" Public key size: {public_size} bytes")

 return private_key_path, public_key_path, key_dir

 except Exception as e:
 print(f" Error generating keys: {e}")
 return None, None, None


def demo_manifest_generation(model_dir, private_key_path):
 """Demonstrate manifest generation"""
 print_section("MODEL MANIFEST GENERATION")

 print(" Generating cryptographically signed model manifest...")

 try:
 generator = ManifestGenerator()

 manifest_path = generator.generate_and_save(
 directory=model_dir,
 model_name="BlackLoom-Demo-Model",
 model_version="1.0",
 created_by="BlackLoom AI Security Team",
 organization="BlackLoom AI",
 private_key_path=private_key_path,
 password="demo123",
 metadata={
 "model_type": "transformer",
 "security_level": "high",
 "demo": True
 },
 verbose=True
 )

 print(f" Manifest generated: {manifest_path}")

 # Display manifest summary
 import json
 with open(manifest_path, 'r') as f:
 manifest = json.load(f)

 print(f"\n Manifest Summary:")
 print(f" Model: {manifest['model_name']} v{manifest['model_version']}")
 print(f" Created by: {manifest['created_by']}")
 print(f" Files tracked: {len(manifest['files'])}")
 print(f" Signed: {'Yes' if manifest.get('signature') else 'No'}")
 print(f" Total size: {sum(f['size'] for f in manifest['files'])} bytes")

 return manifest_path

 except Exception as e:
 print(f" Error generating manifest: {e}")
 return None


def demo_manifest_verification(manifest_path, model_dir, public_key_path):
 """Demonstrate manifest verification"""
 print_section("MODEL INTEGRITY VERIFICATION")

 print(" Verifying model integrity using cryptographic manifest...")

 try:
 verifier = ManifestVerifier()

 result = verifier.verify_manifest(
 manifest_path=manifest_path,
 model_directory=model_dir,
 public_key_path=public_key_path,
 verbose=True
 )

 # Print verification report
 verifier.print_verification_report(result, detailed=True)

 return result.overall_status.value == "valid"

 except Exception as e:
 print(f" Error verifying manifest: {e}")
 return False


def demo_model_tampering(model_dir):
 """Demonstrate detection of model tampering"""
 print_section("MODEL TAMPERING DETECTION")

 print(" Simulating model tampering to test detection...")

 # Tamper with a model file
 config_file = os.path.join(model_dir, "config.json")

 print(f" Original config.json content:")
 with open(config_file, 'r') as f:
 original_content = f.read()
 print(f" {original_content}")

 # Modify the file
 malicious_content = '{"model_type": "malicious", "backdoor": true, "vocab_size": 32000}'
 with open(config_file, 'w') as f:
 f.write(malicious_content)

 print(f"\n Modified config.json content (simulating attack):")
 print(f" {malicious_content}")

 return original_content


def demo_integrity_manager(model_dir, private_key_path, public_key_path):
 """Demonstrate the comprehensive integrity manager"""
 print_section("COMPREHENSIVE INTEGRITY MANAGEMENT")

 print(" Initializing BlackLoom Model Integrity Manager...")

 try:
 # Create temporary audit database
 audit_db = tempfile.mktemp(suffix=".db")

 manager = ModelIntegrityManager(audit_db_path=audit_db)

 # Register the model
 print("\n Registering model for integrity monitoring...")
 model_id = manager.register_model(
 model_name="BlackLoom-Demo-Model",
 model_version="1.0",
 model_path=model_dir,
 created_by="Security Team",
 organization="BlackLoom AI",
 private_key_path=private_key_path,
 public_key_path=public_key_path,
 generate_manifest=True
 )

 print(f" Model registered: {model_id}")

 # Log some access events
 print("\n Logging model access events...")
 for i in range(5):
 event_id = manager.log_model_access(
 model_id=model_id,
 access_type=AccessType.INFERENCE,
 user_id=f"user_{i+1}",
 client_ip=f"192.168.1.{100+i}",
 user_agent="BlackLoom-Client/1.0",
 request_size=1024,
 response_size=2048,
 duration_ms=150.0,
 details={"query_type": "text_generation"}
 )
 print(f" Logged access event: {event_id}")

 # Log a suspicious access pattern
 for i in range(10):
 manager.log_model_access(
 model_id=model_id,
 access_type=AccessType.DOWNLOAD,
 user_id="suspicious_user",
 client_ip="10.0.0.1",
 user_agent="wget/1.0",
 request_size=100,
 response_size=1000000, # Large download
 duration_ms=5000.0,
 details={"suspicious": True}
 )

 # Verify model integrity
 print("\n Verifying model integrity...")
 result = manager.verify_model(model_id, verbose=False)

 if result.overall_status.value == "valid":
 print(" Model integrity verified successfully")
 else:
 print(" Model integrity verification failed")

 # Generate integrity report
 print("\n Generating comprehensive integrity report...")
 report = manager.get_integrity_report(
 model_id=model_id,
 include_access_logs=True,
 hours_back=1
 )

 print(f" Model: {report.model_name} v{report.model_version}")
 print(f" Status: {report.integrity_status.value}")
 print(f" Access Events: {report.access_summary.get('total_accesses', 0)}")
 print(f" Unique Users: {report.access_summary.get('unique_users', 0)}")
 print(f" High Risk Events: {report.access_summary.get('high_risk_events', 0)}")
 print(f" Suspicious Patterns: {len(report.suspicious_patterns)}")

 if report.recommendations:
 print(f"\n Security Recommendations:")
 for rec in report.recommendations:
 print(f" • {rec}")

 # Generate compliance report
 print("\n Generating compliance report...")
 import datetime

 end_date = datetime.datetime.now(datetime.timezone.utc)
 start_date = end_date - datetime.timedelta(hours=1)

 compliance_report = manager.generate_compliance_report(
 start_date=start_date.isoformat(),
 end_date=end_date.isoformat()
 )

 print(f" Period: Last 1 hour")
 print(f" Total Access Events: {compliance_report['statistics']['total_access_events']}")
 print(f" Models Tracked: {compliance_report['integrity_summary']['total_models']}")
 print(f" ISO 42001 Aligned: {compliance_report['compliance_standards']['iso_42001_aligned']}")

 return manager, audit_db

 except Exception as e:
 print(f" Error in integrity management demo: {e}")
 import traceback
 traceback.print_exc()
 return None, None


def demo_suspicious_pattern_detection(manager):
 """Demonstrate suspicious pattern detection"""
 print_section("SUSPICIOUS PATTERN DETECTION")

 print(" Analyzing suspicious access patterns...")

 try:
 patterns = manager.audit_logger.get_suspicious_patterns(
 hours=1,
 min_risk_score=0.5
 )

 if patterns:
 print(f" Found {len(patterns)} suspicious patterns:")

 for pattern in patterns:
 print(f"\n Pattern: {pattern.pattern_type}")
 print(f" Description: {pattern.description}")
 print(f" Risk Score: {pattern.risk_score:.2f}")
 print(f" Events: {pattern.event_count}")
 print(f" Affected Users: {len(pattern.user_ids)}")
 print(f" IP Addresses: {len(pattern.ip_addresses)}")
 print(f" Indicators: {', '.join(pattern.indicators)}")
 else:
 print(" No suspicious patterns detected")

 except Exception as e:
 print(f" Error analyzing suspicious patterns: {e}")


def cleanup_demo_files(model_dir, key_dir, audit_db):
 """Clean up demo files"""
 print_section("CLEANUP")

 print(" Cleaning up demo files...")

 try:
 if model_dir and os.path.exists(model_dir):
 shutil.rmtree(model_dir)
 print(f" 🗑️ Removed model directory: {model_dir}")

 if key_dir and os.path.exists(key_dir):
 shutil.rmtree(key_dir)
 print(f" 🗑️ Removed key directory: {key_dir}")

 if audit_db and os.path.exists(audit_db):
 os.remove(audit_db)
 print(f" 🗑️ Removed audit database: {audit_db}")

 print(" Cleanup completed")

 except Exception as e:
 print(f" Error during cleanup: {e}")


def main():
 """Main demo function"""

 print_banner()
 print("Welcome to the BlackLoom AI Model Integrity System demonstration!")
 print("This demo showcases comprehensive AI model protection capabilities.")

 model_dir = None
 key_dir = None
 audit_db = None

 try:
 # Step 1: Create demo model
 model_dir = create_demo_model()

 # Step 2: Generate cryptographic keys
 private_key_path, public_key_path, key_dir = demo_key_generation()
 if not private_key_path:
 print(" Cannot continue without keys")
 return 1

 # Step 3: Generate signed manifest
 manifest_path = demo_manifest_generation(model_dir, private_key_path)
 if not manifest_path:
 print(" Cannot continue without manifest")
 return 1

 # Step 4: Verify original model
 verification_success = demo_manifest_verification(manifest_path, model_dir, public_key_path)

 # Step 5: Demonstrate tampering detection
 original_content = demo_model_tampering(model_dir)

 # Step 6: Verify tampered model (should fail)
 print("\n Re-verifying model after tampering...")
 tampered_verification = demo_manifest_verification(manifest_path, model_dir, public_key_path)

 if not tampered_verification:
 print(" Tampering successfully detected!")
 else:
 print(" Tampering was not detected - this shouldn't happen")

 # Restore original content for integrity manager demo
 config_file = os.path.join(model_dir, "config.json")
 with open(config_file, 'w') as f:
 f.write(original_content)

 # Step 7: Comprehensive integrity management
 manager, audit_db = demo_integrity_manager(model_dir, private_key_path, public_key_path)

 if manager:
 # Step 8: Suspicious pattern detection
 demo_suspicious_pattern_detection(manager)

 print_section("DEMO SUMMARY")
 print(" BlackLoom AI Model Integrity System Capabilities Demonstrated:")
 print(" Cryptographic key generation and management")
 print(" Model manifest generation with digital signatures")
 print(" File-level integrity verification (SHA-256)")
 print(" Tampering detection and alerts")
 print(" Comprehensive access logging and auditing")
 print(" Suspicious pattern detection and analysis")
 print(" Compliance reporting (ISO 42001 aligned)")
 print(" Model provenance and authenticity verification")

 print(f"\n Your AI models are now protected by BlackLoom AI!")
 print(" • Real-time integrity monitoring")
 print(" • Cryptographic provenance verification")
 print(" • Anti-theft detection systems")
 print(" • Regulatory compliance support")
 print(" • Comprehensive audit trails")

 return 0

 except KeyboardInterrupt:
 print("\n Demo interrupted by user")
 return 1

 except Exception as e:
 print(f"\n Demo failed with error: {str(e)}")
 import traceback
 traceback.print_exc()
 return 1

 finally:
 cleanup_demo_files(model_dir, key_dir, audit_db)


if __name__ == "__main__":
 exit(main())