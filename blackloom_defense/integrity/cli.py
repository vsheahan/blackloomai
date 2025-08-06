"""
BlackLoom Defense - Model Integrity CLI
Command-line interface for model integrity management and verification
"""

import argparse
import sys
import os
import json
from typing import Optional
import logging

from .model_integrity import ModelIntegrityManager
from .crypto_manager import CryptoManager
from .audit_logger import AccessType


def setup_logging(verbose: bool = False):
 """Setup logging configuration"""
 level = logging.INFO if verbose else logging.WARNING
 logging.basicConfig(
 level=level,
 format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
 )


def cmd_generate_keys(args):
 """Generate cryptographic keys for model signing"""
 print(" Generating BlackLoom cryptographic keys...")

 crypto_manager = CryptoManager()

 try:
 private_key_path, public_key_path = crypto_manager.generate_key_pair(
 key_name=args.name,
 output_dir=args.output_dir,
 key_size=args.key_size
 )

 print(f" Keys generated successfully:")
 print(f" Private key: {private_key_path}")
 print(f" Public key: {public_key_path}")
 print(f"\n Keep your private key secure and remember the password!")

 except Exception as e:
 print(f" Error generating keys: {e}")
 return 1

 return 0


def cmd_register_model(args):
 """Register a new model for integrity monitoring"""
 print(f" Registering model: {args.model_name} v{args.model_version}")

 setup_logging(args.verbose)

 try:
 manager = ModelIntegrityManager(
 config_path=args.config,
 audit_db_path=args.audit_db
 )

 model_id = manager.register_model(
 model_name=args.model_name,
 model_version=args.model_version,
 model_path=args.model_path,
 created_by=args.created_by,
 organization=args.organization,
 private_key_path=args.private_key,
 public_key_path=args.public_key,
 generate_manifest=not args.no_manifest,
 metadata=json.loads(args.metadata) if args.metadata else None
 )

 print(f" Model registered successfully: {model_id}")

 if not args.no_manifest:
 print(" Manifest generated and signed")

 except Exception as e:
 print(f" Error registering model: {e}")
 return 1

 return 0


def cmd_verify_model(args):
 """Verify model integrity"""
 print(f" Verifying model: {args.model_id}")

 setup_logging(args.verbose)

 try:
 manager = ModelIntegrityManager(
 config_path=args.config,
 audit_db_path=args.audit_db
 )

 result = manager.verify_model(
 model_id=args.model_id,
 public_key_path=args.public_key,
 verbose=args.verbose
 )

 if not args.verbose:
 # Print summary if not verbose
 if result.overall_status.value == "valid":
 print(f" Model integrity verified successfully")
 print(f" Files verified: {result.files_verified}")
 if result.signature_valid:
 print(f" Digital signature: Valid")
 else:
 print(f" Model integrity verification failed")
 print(f" Status: {result.overall_status.value}")
 print(f" Files failed: {result.files_failed}")
 print(f" Files missing: {result.files_missing}")
 if result.signature_valid is False:
 print(f" Digital signature: Invalid")

 return 0 if result.overall_status.value == "valid" else 1

 except Exception as e:
 print(f" Error verifying model: {e}")
 return 1


def cmd_list_models(args):
 """List registered models"""
 print(" BlackLoom Registered Models")
 print("=" * 50)

 try:
 manager = ModelIntegrityManager(
 config_path=args.config,
 audit_db_path=args.audit_db
 )

 models = manager.list_models(include_status=True)

 if not models:
 print("No models registered yet.")
 return 0

 for model in models:
 status_icon = {
 'verified': '',
 'compromised': '',
 'unknown': '',
 'error': ''
 }.get(model['integrity_status'], '❓')

 print(f"\n{status_icon} {model['name']} v{model['version']}")
 print(f" ID: {model['id']}")
 print(f" Status: {model['integrity_status']}")
 print(f" Path: {model['path']}")

 if model['last_verified']:
 print(f" Last verified: {model['last_verified']}")
 else:
 print(f" Last verified: Never")

 features = []
 if model['has_manifest']:
 features.append("Manifest")
 if model['has_signature']:
 features.append("Signed")

 if features:
 print(f" Features: {', '.join(features)}")

 except Exception as e:
 print(f" Error listing models: {e}")
 return 1

 return 0


def cmd_integrity_report(args):
 """Generate integrity report for a model"""
 print(f" Generating integrity report: {args.model_id}")

 setup_logging(args.verbose)

 try:
 manager = ModelIntegrityManager(
 config_path=args.config,
 audit_db_path=args.audit_db
 )

 report = manager.get_integrity_report(
 model_id=args.model_id,
 include_access_logs=not args.no_access_logs,
 hours_back=args.hours_back
 )

 if args.output_format == 'json':
 # Output JSON format
 report_dict = {
 'model_name': report.model_name,
 'model_version': report.model_version,
 'integrity_status': report.integrity_status.value,
 'last_verified': report.last_verified,
 'suspicious_patterns': report.suspicious_patterns,
 'access_summary': report.access_summary,
 'recommendations': report.recommendations,
 'metadata': report.metadata
 }

 if report.verification_result:
 report_dict['verification_details'] = {
 'overall_status': report.verification_result.overall_status.value,
 'files_verified': report.verification_result.files_verified,
 'files_failed': report.verification_result.files_failed,
 'signature_valid': report.verification_result.signature_valid
 }

 print(json.dumps(report_dict, indent=2))

 else:
 # Output formatted text
 status_color = {
 'verified': '\033[92m', # Green
 'compromised': '\033[91m', # Red
 'unknown': '\033[93m', # Yellow
 'error': '\033[91m' # Red
 }.get(report.integrity_status.value, '')

 reset = '\033[0m'

 print(f"\n{'='*60}")
 print(f"BlackLoom Model Integrity Report")
 print(f"{'='*60}")

 print(f"\n Model: {report.model_name} v{report.model_version}")
 print(f"{status_color} Status: {report.integrity_status.value.upper()}{reset}")
 print(f"⏰ Last Verified: {report.last_verified}")

 if report.access_summary:
 print(f"\n Access Summary (Last {args.hours_back}h):")
 print(f" Total Accesses: {report.access_summary['total_accesses']}")
 print(f" Unique Users: {report.access_summary['unique_users']}")
 print(f" Unique IPs: {report.access_summary['unique_ips']}")
 print(f" High Risk Events: {report.access_summary['high_risk_events']}")

 if report.suspicious_patterns:
 print(f"\n Suspicious Patterns Detected:")
 for pattern in report.suspicious_patterns:
 print(f" • {pattern['description']}")
 print(f" Risk Score: {pattern['risk_score']:.2f} | Events: {pattern['event_count']}")

 if report.recommendations:
 print(f"\n Recommendations:")
 for rec in report.recommendations:
 print(f" • {rec}")

 print(f"\n Report Generated: {report.metadata.get('report_generated', 'Unknown')}")

 except Exception as e:
 print(f" Error generating report: {e}")
 return 1

 return 0


def cmd_compliance_report(args):
 """Generate compliance report"""
 print(f" Generating compliance report: {args.start_date} to {args.end_date}")

 try:
 manager = ModelIntegrityManager(
 config_path=args.config,
 audit_db_path=args.audit_db
 )

 report = manager.generate_compliance_report(
 start_date=args.start_date,
 end_date=args.end_date,
 model_filter=args.model_filter
 )

 if args.output_format == 'json':
 print(json.dumps(report, indent=2))
 else:
 print(f"\n{'='*60}")
 print(f"BlackLoom Compliance Report")
 print(f"{'='*60}")

 print(f"\n📅 Period: {args.start_date} to {args.end_date}")
 if args.model_filter:
 print(f" Model Filter: {args.model_filter}")

 stats = report.get('statistics', {})
 print(f"\n Access Statistics:")
 print(f" Total Events: {stats.get('total_access_events', 0)}")
 print(f" Unique Users: {stats.get('unique_users', 0)}")
 print(f" Unique IPs: {stats.get('unique_ip_addresses', 0)}")
 print(f" Suspicious Patterns: {stats.get('suspicious_patterns_detected', 0)}")

 integrity = report.get('integrity_summary', {})
 print(f"\n Model Integrity Summary:")
 print(f" Total Models: {integrity.get('total_models', 0)}")
 print(f" Verified: {integrity.get('verified_models', 0)}")
 print(f" Compromised: {integrity.get('compromised_models', 0)}")
 print(f" With Signatures: {integrity.get('models_with_signatures', 0)}")

 compliance = report.get('compliance_standards', {})
 print(f"\n Compliance Status:")
 for standard, status in compliance.items():
 icon = "" if status else ""
 print(f" {icon} {standard.replace('_', ' ').title()}")

 except Exception as e:
 print(f" Error generating compliance report: {e}")
 return 1

 return 0


def main():
 """Main CLI entry point"""
 parser = argparse.ArgumentParser(
 description="BlackLoom Defense - Model Integrity Management CLI",
 formatter_class=argparse.RawDescriptionHelpFormatter,
 epilog="""
Examples:
 # Generate signing keys
 blackloom integrity generate-keys --name my-org-key --output-dir ./keys

 # Register a model
 blackloom integrity register --model-name "GPT-Fine-Tuned" --model-version "1.0" \\
 --model-path ./model --created-by "AI Team" --private-key ./keys/my-org-key.pem

 # Verify model integrity
 blackloom integrity verify --model-id "GPT-Fine-Tuned:1.0" --public-key ./keys/my-org-key.pub

 # Generate integrity report
 blackloom integrity report --model-id "GPT-Fine-Tuned:1.0" --hours-back 168
 """
 )

 # Global options
 parser.add_argument('--config', help='Configuration file path')
 parser.add_argument('--audit-db', default='blackloom_audit.db', help='Audit database path')
 parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

 subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

 # Generate keys command
 keys_parser = subparsers.add_parser('generate-keys', help='Generate cryptographic keys')
 keys_parser.add_argument('--name', required=True, help='Key pair name')
 keys_parser.add_argument('--output-dir', default='.', help='Output directory for keys')
 keys_parser.add_argument('--key-size', type=int, default=2048, help='RSA key size (default: 2048)')
 keys_parser.set_defaults(func=cmd_generate_keys)

 # Register model command
 register_parser = subparsers.add_parser('register', help='Register a model for integrity monitoring')
 register_parser.add_argument('--model-name', required=True, help='Model name')
 register_parser.add_argument('--model-version', required=True, help='Model version')
 register_parser.add_argument('--model-path', required=True, help='Path to model files')
 register_parser.add_argument('--created-by', required=True, help='Creator name')
 register_parser.add_argument('--organization', default='BlackLoom AI', help='Organization name')
 register_parser.add_argument('--private-key', help='Private key for signing manifest')
 register_parser.add_argument('--public-key', help='Public key for verification')
 register_parser.add_argument('--no-manifest', action='store_true', help="Don't generate manifest")
 register_parser.add_argument('--metadata', help='Additional metadata (JSON string)')
 register_parser.set_defaults(func=cmd_register_model)

 # Verify model command
 verify_parser = subparsers.add_parser('verify', help='Verify model integrity')
 verify_parser.add_argument('--model-id', required=True, help='Model ID (name:version)')
 verify_parser.add_argument('--public-key', help='Public key for signature verification')
 verify_parser.set_defaults(func=cmd_verify_model)

 # List models command
 list_parser = subparsers.add_parser('list', help='List registered models')
 list_parser.set_defaults(func=cmd_list_models)

 # Integrity report command
 report_parser = subparsers.add_parser('report', help='Generate integrity report')
 report_parser.add_argument('--model-id', required=True, help='Model ID (name:version)')
 report_parser.add_argument('--hours-back', type=int, default=24, help='Hours of logs to analyze')
 report_parser.add_argument('--no-access-logs', action='store_true', help='Skip access log analysis')
 report_parser.add_argument('--output-format', choices=['text', 'json'], default='text', help='Output format')
 report_parser.set_defaults(func=cmd_integrity_report)

 # Compliance report command
 compliance_parser = subparsers.add_parser('compliance', help='Generate compliance report')
 compliance_parser.add_argument('--start-date', required=True, help='Start date (ISO format)')
 compliance_parser.add_argument('--end-date', required=True, help='End date (ISO format)')
 compliance_parser.add_argument('--model-filter', help='Filter by model name')
 compliance_parser.add_argument('--output-format', choices=['text', 'json'], default='text', help='Output format')
 compliance_parser.set_defaults(func=cmd_compliance_report)

 # Parse arguments and execute command
 args = parser.parse_args()

 try:
 return args.func(args)
 except KeyboardInterrupt:
 print("\n Operation cancelled by user")
 return 1
 except Exception as e:
 if args.verbose:
 import traceback
 traceback.print_exc()
 else:
 print(f" Unexpected error: {e}")
 return 1


if __name__ == '__main__':
 sys.exit(main())