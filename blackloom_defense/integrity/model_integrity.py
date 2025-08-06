"""
BlackLoom Defense - Model Integrity Manager
Central orchestration for model integrity verification, auditing, and anti-theft protection
"""

import os
import json
import datetime
from typing import Optional, Dict, List, Any, Union
from dataclasses import dataclass
from enum import Enum
import logging

from .manifest_generator import ManifestGenerator, ModelManifest
from .manifest_verifier import ManifestVerifier, ManifestVerificationResult, VerificationStatus
from .crypto_manager import CryptoManager
from .audit_logger import AuditLogger, AccessType, RiskLevel


class IntegrityStatus(Enum):
 """Overall integrity status of a model"""
 VERIFIED = "verified"
 COMPROMISED = "compromised"
 UNKNOWN = "unknown"
 ERROR = "error"


@dataclass
class ModelInfo:
 """Information about a protected model"""
 name: str
 version: str
 path: str
 manifest_path: Optional[str]
 public_key_path: Optional[str]
 last_verified: Optional[str]
 integrity_status: IntegrityStatus
 metadata: Dict[str, Any]


@dataclass
class IntegrityReport:
 """Comprehensive integrity report for a model"""
 model_name: str
 model_version: str
 integrity_status: IntegrityStatus
 last_verified: str
 verification_result: Optional[ManifestVerificationResult]
 suspicious_patterns: List[Dict[str, Any]]
 access_summary: Dict[str, Any]
 recommendations: List[str]
 metadata: Dict[str, Any]


class ModelIntegrityManager:
 """
 Central manager for AI model integrity verification and protection

 Provides:
 - Model manifest generation and verification
 - Access logging and suspicious pattern detection
 - Anti-theft monitoring and compliance reporting
 - Cryptographic provenance verification
 """

 def __init__(self,
 config_path: Optional[str] = None,
 audit_db_path: str = "blackloom_audit.db"):
 """
 Initialize the Model Integrity Manager

 Args:
 config_path: Path to configuration file
 audit_db_path: Path to audit database
 """
 self.logger = logging.getLogger(__name__)

 # Load configuration
 self.config = self._load_config(config_path) if config_path else {}

 # Initialize components
 self.crypto_manager = CryptoManager()
 self.manifest_generator = ManifestGenerator(self.crypto_manager)
 self.manifest_verifier = ManifestVerifier(self.crypto_manager)
 self.audit_logger = AuditLogger(audit_db_path, self.config.get('audit', {}))

 # Model registry
 self.models_registry_path = self.config.get('models_registry', 'models_registry.json')
 self.models = self._load_models_registry()

 self.logger.info("BlackLoom Model Integrity Manager initialized")

 def _load_config(self, config_path: str) -> Dict[str, Any]:
 """Load configuration from JSON file"""
 try:
 with open(config_path, 'r') as f:
 return json.load(f)
 except FileNotFoundError:
 self.logger.warning(f"Configuration file not found: {config_path}")
 return {}
 except Exception as e:
 self.logger.error(f"Error loading configuration: {e}")
 return {}

 def _load_models_registry(self) -> Dict[str, ModelInfo]:
 """Load registered models from registry file"""
 try:
 if os.path.exists(self.models_registry_path):
 with open(self.models_registry_path, 'r') as f:
 registry_data = json.load(f)

 models = {}
 for model_id, model_data in registry_data.get('models', {}).items():
 models[model_id] = ModelInfo(
 name=model_data['name'],
 version=model_data['version'],
 path=model_data['path'],
 manifest_path=model_data.get('manifest_path'),
 public_key_path=model_data.get('public_key_path'),
 last_verified=model_data.get('last_verified'),
 integrity_status=IntegrityStatus(model_data.get('integrity_status', 'unknown')),
 metadata=model_data.get('metadata', {})
 )

 return models
 else:
 return {}

 except Exception as e:
 self.logger.error(f"Error loading models registry: {e}")
 return {}

 def _save_models_registry(self):
 """Save models registry to file"""
 try:
 registry_data = {
 "updated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
 "models": {}
 }

 for model_id, model_info in self.models.items():
 registry_data["models"][model_id] = {
 "name": model_info.name,
 "version": model_info.version,
 "path": model_info.path,
 "manifest_path": model_info.manifest_path,
 "public_key_path": model_info.public_key_path,
 "last_verified": model_info.last_verified,
 "integrity_status": model_info.integrity_status.value,
 "metadata": model_info.metadata
 }

 os.makedirs(os.path.dirname(self.models_registry_path) or ".", exist_ok=True)

 with open(self.models_registry_path, 'w') as f:
 json.dump(registry_data, f, indent=4)

 except Exception as e:
 self.logger.error(f"Error saving models registry: {e}")

 def register_model(self,
 model_name: str,
 model_version: str,
 model_path: str,
 created_by: str,
 organization: str = "BlackLoom AI",
 private_key_path: Optional[str] = None,
 public_key_path: Optional[str] = None,
 generate_manifest: bool = True,
 metadata: Optional[Dict[str, Any]] = None) -> str:
 """
 Register a new model for integrity monitoring

 Args:
 model_name: Name of the model
 model_version: Version of the model
 model_path: Path to model files
 created_by: Creator of the model
 organization: Organization name
 private_key_path: Private key for signing manifest
 public_key_path: Public key for verification
 generate_manifest: Whether to generate manifest immediately
 metadata: Additional metadata

 Returns:
 Model ID for the registered model
 """
 model_id = f"{model_name}:{model_version}"

 if model_id in self.models:
 raise ValueError(f"Model {model_id} is already registered")

 if not os.path.exists(model_path):
 raise FileNotFoundError(f"Model path does not exist: {model_path}")

 self.logger.info(f"Registering model: {model_id}")

 # Generate manifest if requested
 manifest_path = None
 if generate_manifest:
 try:
 manifest_path = self.manifest_generator.generate_and_save(
 directory=model_path,
 model_name=model_name,
 model_version=model_version,
 created_by=created_by,
 organization=organization,
 private_key_path=private_key_path,
 metadata=metadata,
 verbose=True
 )

 self.logger.info(f"Generated manifest: {manifest_path}")

 except Exception as e:
 self.logger.error(f"Failed to generate manifest: {e}")
 manifest_path = None

 # Create model info
 model_info = ModelInfo(
 name=model_name,
 version=model_version,
 path=os.path.abspath(model_path),
 manifest_path=manifest_path,
 public_key_path=public_key_path,
 last_verified=None,
 integrity_status=IntegrityStatus.UNKNOWN,
 metadata=metadata or {}
 )

 # Add to registry
 self.models[model_id] = model_info
 self._save_models_registry()

 # Log registration event
 self.audit_logger.log_access(
 access_type=AccessType.ADMIN,
 model_name=model_name,
 model_version=model_version,
 user_id=created_by,
 client_ip="system",
 user_agent="BlackLoom-Integrity-Manager",
 details={"action": "model_registration", "manifest_generated": manifest_path is not None}
 )

 self.logger.info(f" Model registered successfully: {model_id}")
 return model_id

 def verify_model(self,
 model_id: str,
 public_key_path: Optional[str] = None,
 verbose: bool = False) -> ManifestVerificationResult:
 """
 Verify the integrity of a registered model

 Args:
 model_id: ID of the model to verify
 public_key_path: Public key for signature verification
 verbose: Enable verbose output

 Returns:
 ManifestVerificationResult
 """
 if model_id not in self.models:
 raise ValueError(f"Model not registered: {model_id}")

 model_info = self.models[model_id]

 if not model_info.manifest_path or not os.path.exists(model_info.manifest_path):
 raise FileNotFoundError(f"Manifest not found for model: {model_id}")

 # Use provided public key or model's registered key
 verification_key = public_key_path or model_info.public_key_path

 if verbose:
 self.logger.info(f" Verifying model: {model_id}")

 # Perform verification
 result = self.manifest_verifier.verify_manifest(
 manifest_path=model_info.manifest_path,
 model_directory=model_info.path,
 public_key_path=verification_key,
 verbose=verbose
 )

 # Update model registry
 model_info.last_verified = datetime.datetime.now(datetime.timezone.utc).isoformat()

 if result.overall_status == VerificationStatus.VALID:
 model_info.integrity_status = IntegrityStatus.VERIFIED
 else:
 model_info.integrity_status = IntegrityStatus.COMPROMISED

 self._save_models_registry()

 # Log verification event
 self.audit_logger.log_access(
 access_type=AccessType.VERIFICATION,
 model_name=model_info.name,
 model_version=model_info.version,
 user_id="system",
 client_ip="system",
 user_agent="BlackLoom-Integrity-Manager",
 details={
 "verification_status": result.overall_status.value,
 "files_verified": result.files_verified,
 "files_failed": result.files_failed,
 "signature_valid": result.signature_valid
 },
 threat_indicators=["integrity_violation"] if result.overall_status != VerificationStatus.VALID else None
 )

 if verbose:
 self.manifest_verifier.print_verification_report(result, detailed=True)

 return result

 def log_model_access(self,
 model_id: str,
 access_type: AccessType,
 user_id: str,
 client_ip: str,
 user_agent: str = "",
 request_size: int = 0,
 response_size: int = 0,
 duration_ms: float = 0.0,
 details: Optional[Dict[str, Any]] = None,
 session_id: Optional[str] = None) -> str:
 """
 Log access to a protected model

 Args:
 model_id: ID of the accessed model
 access_type: Type of access
 user_id: ID of the user
 client_ip: Client IP address
 user_agent: User agent string
 request_size: Size of request in bytes
 response_size: Size of response in bytes
 duration_ms: Request duration in milliseconds
 details: Additional details
 session_id: Session identifier

 Returns:
 Event ID of the logged access
 """
 if model_id not in self.models:
 self.logger.warning(f"Access logged for unregistered model: {model_id}")

 model_info = self.models.get(model_id)

 return self.audit_logger.log_access(
 access_type=access_type,
 model_name=model_info.name if model_info else model_id,
 model_version=model_info.version if model_info else "unknown",
 user_id=user_id,
 client_ip=client_ip,
 user_agent=user_agent,
 request_size=request_size,
 response_size=response_size,
 duration_ms=duration_ms,
 details=details,
 session_id=session_id
 )

 def get_integrity_report(self,
 model_id: str,
 include_access_logs: bool = True,
 hours_back: int = 24) -> IntegrityReport:
 """
 Generate comprehensive integrity report for a model

 Args:
 model_id: ID of the model
 include_access_logs: Include access log analysis
 hours_back: How many hours of logs to analyze

 Returns:
 IntegrityReport
 """
 if model_id not in self.models:
 raise ValueError(f"Model not registered: {model_id}")

 model_info = self.models[model_id]

 # Get latest verification result
 verification_result = None
 if model_info.manifest_path:
 try:
 verification_result = self.verify_model(model_id, verbose=False)
 except Exception as e:
 self.logger.error(f"Verification failed for {model_id}: {e}")

 # Get suspicious patterns
 suspicious_patterns = []
 access_summary = {}

 if include_access_logs:
 # Get recent suspicious patterns
 patterns = self.audit_logger.get_suspicious_patterns(hours=hours_back)
 for pattern in patterns:
 if model_id in pattern.affected_models or f"{model_info.name}:{model_info.version}" in pattern.affected_models:
 suspicious_patterns.append({
 'type': pattern.pattern_type,
 'description': pattern.description,
 'risk_score': pattern.risk_score,
 'event_count': pattern.event_count,
 'last_seen': pattern.last_seen,
 'indicators': pattern.indicators
 })

 # Get access summary
 recent_events = self.audit_logger.get_recent_events(
 hours=hours_back,
 filters={'model_name': model_info.name}
 )

 access_summary = {
 'total_accesses': len(recent_events),
 'unique_users': len(set(e['user_id'] for e in recent_events)),
 'unique_ips': len(set(e['client_ip'] for e in recent_events)),
 'high_risk_events': len([e for e in recent_events if e['risk_level'] in ['high', 'critical']]),
 'access_types': {}
 }

 for event in recent_events:
 access_type = event['access_type']
 access_summary['access_types'][access_type] = access_summary['access_types'].get(access_type, 0) + 1

 # Generate recommendations
 recommendations = []

 if model_info.integrity_status == IntegrityStatus.COMPROMISED:
 recommendations.extend([
 "Model integrity verification failed - investigate immediately",
 "Consider regenerating model manifest after validating model files",
 "Review recent access logs for suspicious activity"
 ])

 if len(suspicious_patterns) > 0:
 recommendations.append("Suspicious access patterns detected - review audit logs")

 if not model_info.public_key_path:
 recommendations.append("Consider adding digital signature verification for enhanced security")

 if access_summary.get('high_risk_events', 0) > 0:
 recommendations.append("High-risk access events detected - review access controls")

 # Create report
 report = IntegrityReport(
 model_name=model_info.name,
 model_version=model_info.version,
 integrity_status=model_info.integrity_status,
 last_verified=model_info.last_verified or "Never",
 verification_result=verification_result,
 suspicious_patterns=suspicious_patterns,
 access_summary=access_summary,
 recommendations=recommendations,
 metadata={
 'model_path': model_info.path,
 'manifest_path': model_info.manifest_path,
 'report_generated': datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'analysis_period_hours': hours_back
 }
 )

 return report

 def list_models(self, include_status: bool = True) -> List[Dict[str, Any]]:
 """
 List all registered models

 Args:
 include_status: Include integrity status information

 Returns:
 List of model information dictionaries
 """
 models_list = []

 for model_id, model_info in self.models.items():
 model_data = {
 'id': model_id,
 'name': model_info.name,
 'version': model_info.version,
 'path': model_info.path
 }

 if include_status:
 model_data.update({
 'integrity_status': model_info.integrity_status.value,
 'last_verified': model_info.last_verified,
 'has_manifest': model_info.manifest_path is not None,
 'has_signature': model_info.public_key_path is not None
 })

 models_list.append(model_data)

 return models_list

 def generate_compliance_report(self,
 start_date: str,
 end_date: str,
 model_filter: Optional[str] = None) -> Dict[str, Any]:
 """
 Generate compliance report for regulatory requirements

 Args:
 start_date: Start date in ISO format
 end_date: End date in ISO format
 model_filter: Optional model name filter

 Returns:
 Comprehensive compliance report
 """
 # Get base compliance report from audit logger
 base_report = self.audit_logger.generate_compliance_report(
 start_date, end_date, model_filter
 )

 # Add model integrity information
 integrity_summary = {
 'total_models': len(self.models),
 'verified_models': 0,
 'compromised_models': 0,
 'unverified_models': 0,
 'models_with_signatures': 0
 }

 for model_info in self.models.values():
 if model_filter and model_info.name != model_filter:
 continue

 if model_info.integrity_status == IntegrityStatus.VERIFIED:
 integrity_summary['verified_models'] += 1
 elif model_info.integrity_status == IntegrityStatus.COMPROMISED:
 integrity_summary['compromised_models'] += 1
 else:
 integrity_summary['unverified_models'] += 1

 if model_info.public_key_path:
 integrity_summary['models_with_signatures'] += 1

 # Combine reports
 compliance_report = {
 **base_report,
 "integrity_summary": integrity_summary,
 "blackloom_version": "0.1.0",
 "compliance_standards": {
 "iso_42001_aligned": True,
 "model_provenance_tracked": True,
 "access_audit_complete": True,
 "integrity_verification_available": True
 }
 }

 return compliance_report