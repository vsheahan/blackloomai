"""
BlackLoom Defense API Gateway
Provides a secure proxy layer for protecting AI models
"""

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
import logging
import time
import asyncio
import httpx
from contextlib import asynccontextmanager

from ..core import DefenseEngine, ThreatLevel
from ..integrity import ModelIntegrityManager
from ..integrity.audit_logger import AccessType
from ..monitoring import MonitoringManager


# Request/Response Models
class ProtectedRequest(BaseModel):
 user_input: str = Field(..., description="User input to protect")
 target_model_url: str = Field(..., description="URL of the AI model to protect")
 context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional context")
 config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Defense configuration overrides")


class DefenseResponse(BaseModel):
 is_safe: bool
 threat_level: str
 detected_attacks: List[str]
 sanitized_input: Optional[str]
 confidence: float
 processing_time_ms: float
 metadata: Dict[str, Any]


class ProxyResponse(BaseModel):
 model_response: str
 defense_analysis: DefenseResponse
 output_integrity: Dict[str, Any]
 total_processing_time_ms: float


class ModelRegistrationRequest(BaseModel):
 model_name: str = Field(..., description="Name of the model")
 model_version: str = Field(..., description="Version of the model")
 model_path: str = Field(..., description="Path to model files")
 created_by: str = Field(..., description="Creator of the model")
 organization: str = Field(default="BlackLoom AI", description="Organization name")
 private_key_path: Optional[str] = Field(default=None, description="Path to private key for signing")
 public_key_path: Optional[str] = Field(default=None, description="Path to public key for verification")
 generate_manifest: bool = Field(default=True, description="Generate manifest automatically")
 metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")


class IntegrityReportRequest(BaseModel):
 model_id: str = Field(..., description="Model ID (name:version)")
 include_access_logs: bool = Field(default=True, description="Include access log analysis")
 hours_back: int = Field(default=24, description="Hours of logs to analyze")


# Security
security = HTTPBearer()


def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
 """Verify API key (simplified for demo)"""
 # In production, implement proper API key validation
 if credentials.credentials != "blackloom-demo-key":
 raise HTTPException(status_code=401, detail="Invalid API key")
 return credentials.credentials


# Application setup
@asynccontextmanager
async def lifespan(app: FastAPI):
 # Startup
 logging.basicConfig(level=logging.INFO)
 app.state.defense_engine = DefenseEngine()
 app.state.integrity_manager = ModelIntegrityManager()
 app.state.monitoring_manager = MonitoringManager()
 app.state.monitoring_manager.start_monitoring()
 app.state.http_client = httpx.AsyncClient(timeout=30.0)
 yield
 # Shutdown
 app.state.monitoring_manager.stop_monitoring()
 await app.state.http_client.aclose()


app = FastAPI(
 title="BlackLoom Defense API",
 description="AI Security Platform - Protecting AI models from adversarial attacks",
 version="0.1.0",
 lifespan=lifespan
)

# CORS middleware
app.add_middleware(
 CORSMiddleware,
 allow_origins=["*"], # Configure properly in production
 allow_credentials=True,
 allow_methods=["*"],
 allow_headers=["*"],
)

# Rate limiting middleware (simplified)
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
 # Simple rate limiting based on IP
 client_ip = request.client.host
 current_time = time.time()

 # In production, use Redis or proper rate limiting
 if not hasattr(app.state, 'rate_limits'):
 app.state.rate_limits = {}

 if client_ip in app.state.rate_limits:
 last_request, count = app.state.rate_limits[client_ip]
 if current_time - last_request < 60: # 1 minute window
 if count >= 100: # Max 100 requests per minute
 raise HTTPException(status_code=429, detail="Rate limit exceeded")
 app.state.rate_limits[client_ip] = (current_time, count + 1)
 else:
 app.state.rate_limits[client_ip] = (current_time, 1)
 else:
 app.state.rate_limits[client_ip] = (current_time, 1)

 response = await call_next(request)
 return response


@app.get("/health")
async def health_check():
 """Health check endpoint"""
 return {
 "status": "healthy",
 "service": "BlackLoom Defense",
 "version": "0.1.0",
 "timestamp": time.time()
 }


@app.post("/analyze", response_model=DefenseResponse)
async def analyze_input(
 request: ProtectedRequest,
 api_key: str = Depends(verify_api_key)
):
 """
 Analyze user input for security threats without forwarding to target model
 """
 start_time = time.time()

 try:
 # Get defense engine
 defense_engine = app.state.defense_engine

 # Analyze input
 result = defense_engine.analyze_input(
 user_input=request.user_input,
 context=request.context
 )

 processing_time = (time.time() - start_time) * 1000

 return DefenseResponse(
 is_safe=result.is_safe,
 threat_level=result.threat_level.name,
 detected_attacks=result.detected_attacks,
 sanitized_input=result.sanitized_input,
 confidence=result.confidence,
 processing_time_ms=processing_time,
 metadata=result.metadata
 )

 except Exception as e:
 logging.error(f"Error in analyze_input: {str(e)}")
 raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/proxy", response_model=ProxyResponse)
async def secure_proxy(
 request_data: ProtectedRequest,
 request: Request,
 api_key: str = Depends(verify_api_key)
):
 """
 Secure proxy that analyzes input, forwards safe requests, and monitors output
 """
 total_start_time = time.time()
 client_ip = request.client.host

 try:
 defense_engine = app.state.defense_engine
 http_client = app.state.http_client
 monitoring_manager = app.state.monitoring_manager

 # Step 1: Analyze input
 defense_start = time.time()
 defense_result = defense_engine.analyze_input(
 user_input=request_data.user_input,
 context=request_data.context
 )
 defense_time = (time.time() - defense_start) * 1000

 # Step 2: Handle unsafe inputs
 if not defense_result.is_safe:
 blocked_response = "[Request blocked for security reasons]"
 blocked_total_time = (time.time() - total_start_time) * 1000

 # Record blocked request in monitoring system
 try:
 model_name = request_data.target_model_url.split('/')[-1] if '/' in request_data.target_model_url else "unknown_model"
 complexity_score = len(request_data.user_input) + (len(defense_result.detected_attacks) * 100)

 monitoring_manager.record_request(
 client_ip=client_ip,
 model_name=model_name,
 user_input=request_data.user_input,
 model_output=blocked_response,
 response_time_ms=blocked_total_time,
 request_size=len(request_data.user_input.encode('utf-8')),
 response_size=len(blocked_response.encode('utf-8')),
 is_error=True, # Mark as error since request was blocked
 confidence_score=defense_result.confidence,
 complexity_score=complexity_score,
 metadata={
 'blocked': True,
 'defense_result': {
 'is_safe': False,
 'threat_level': defense_result.threat_level.name,
 'detected_attacks': defense_result.detected_attacks
 }
 }
 )
 except Exception as monitor_error:
 logging.error(f"Error recording blocked request in monitoring system: {monitor_error}")

 return ProxyResponse(
 model_response=blocked_response,
 defense_analysis=DefenseResponse(
 is_safe=False,
 threat_level=defense_result.threat_level.name,
 detected_attacks=defense_result.detected_attacks,
 sanitized_input=defense_result.sanitized_input,
 confidence=defense_result.confidence,
 processing_time_ms=defense_time,
 metadata=defense_result.metadata
 ),
 output_integrity={"status": "input_blocked"},
 total_processing_time_ms=blocked_total_time
 )

 # Step 3: Forward safe/sanitized input to target model
 input_to_forward = defense_result.sanitized_input or request_data.user_input

 try:
 model_start = time.time()

 # Forward request to target AI model
 response = await http_client.post(
 request_data.target_model_url,
 json={"input": input_to_forward, **request_data.context},
 headers={"Content-Type": "application/json"}
 )

 model_time = (time.time() - model_start) * 1000

 if response.status_code != 200:
 raise HTTPException(
 status_code=502,
 detail=f"Target model error: {response.status_code}"
 )

 model_response_data = response.json()
 model_response = model_response_data.get("response", str(model_response_data))

 except httpx.RequestError as e:
 logging.error(f"Error forwarding to target model: {str(e)}")
 raise HTTPException(
 status_code=502,
 detail="Unable to reach target AI model"
 )

 # Step 4: Monitor output integrity
 output_start = time.time()
 input_context = {
 'threat_level': defense_result.threat_level.name,
 'detected_attacks': defense_result.detected_attacks,
 'confidence': defense_result.confidence
 }

 output_is_safe = defense_engine.monitor_output(model_response, input_context)
 output_analysis = defense_engine.output_monitor.analyze_output(
 model_response, input_context
 )
 output_time = (time.time() - output_start) * 1000

 # Step 5: Handle compromised outputs
 final_response = model_response
 if not output_is_safe:
 logging.warning(f"Potentially compromised output detected: {output_analysis.anomalies}")
 final_response = "[Response filtered for security reasons]"

 total_time = (time.time() - total_start_time) * 1000

 # Step 6: Record request in monitoring system
 try:
 # Extract model name from URL for tracking
 model_name = request_data.target_model_url.split('/')[-1] if '/' in request_data.target_model_url else "unknown_model"

 # Calculate complexity score based on input length and detected attacks
 complexity_score = len(request_data.user_input) + (len(defense_result.detected_attacks) * 100)

 monitoring_manager.record_request(
 client_ip=client_ip,
 model_name=model_name,
 user_input=request_data.user_input,
 model_output=final_response,
 response_time_ms=total_time,
 request_size=len(request_data.user_input.encode('utf-8')),
 response_size=len(final_response.encode('utf-8')),
 is_error=False,
 confidence_score=defense_result.confidence,
 complexity_score=complexity_score,
 metadata={
 'defense_result': {
 'is_safe': defense_result.is_safe,
 'threat_level': defense_result.threat_level.name,
 'detected_attacks': defense_result.detected_attacks
 },
 'output_integrity': {
 'is_safe': output_is_safe,
 'risk_score': output_analysis.risk_score,
 'anomalies': output_analysis.anomalies
 }
 }
 )
 except Exception as monitor_error:
 logging.error(f"Error recording request in monitoring system: {monitor_error}")
 # Don't fail the request if monitoring fails

 return ProxyResponse(
 model_response=final_response,
 defense_analysis=DefenseResponse(
 is_safe=defense_result.is_safe,
 threat_level=defense_result.threat_level.name,
 detected_attacks=defense_result.detected_attacks,
 sanitized_input=defense_result.sanitized_input,
 confidence=defense_result.confidence,
 processing_time_ms=defense_time,
 metadata=defense_result.metadata
 ),
 output_integrity={
 "is_safe": output_is_safe,
 "risk_score": output_analysis.risk_score,
 "anomalies": output_analysis.anomalies,
 "processing_time_ms": output_time,
 "metadata": output_analysis.metadata
 },
 total_processing_time_ms=total_time
 )

 except HTTPException:
 raise
 except Exception as e:
 logging.error(f"Error in secure_proxy: {str(e)}")
 raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/stats")
async def get_stats(api_key: str = Depends(verify_api_key)):
 """Get system statistics and trends"""
 try:
 defense_engine = app.state.defense_engine

 # Get output monitoring trends
 trend_analysis = defense_engine.output_monitor.get_trend_analysis()

 # Get rate limiting stats
 rate_limits = getattr(app.state, 'rate_limits', {})
 active_clients = len(rate_limits)

 return {
 "system_status": "operational",
 "active_clients": active_clients,
 "output_trends": trend_analysis,
 "uptime_seconds": time.time() - getattr(app.state, 'start_time', time.time()),
 "defense_engine_status": "active"
 }

 except Exception as e:
 logging.error(f"Error in get_stats: {str(e)}")
 raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/test-attack")
async def test_attack_scenario(
 attack_payload: Dict[str, Any],
 api_key: str = Depends(verify_api_key)
):
 """
 Test endpoint for security researchers to test attack scenarios
 WARNING: Only for authorized testing
 """
 try:
 defense_engine = app.state.defense_engine

 test_input = attack_payload.get("input", "")
 attack_type = attack_payload.get("type", "unknown")

 result = defense_engine.analyze_input(
 user_input=test_input,
 context={"test_scenario": attack_type}
 )

 return {
 "attack_type": attack_type,
 "detected": not result.is_safe,
 "confidence": result.confidence,
 "detected_attacks": result.detected_attacks,
 "threat_level": result.threat_level.name,
 "sanitized_output": result.sanitized_input
 }

 except Exception as e:
 logging.error(f"Error in test_attack_scenario: {str(e)}")
 raise HTTPException(status_code=500, detail="Internal server error")


# === MODEL INTEGRITY ENDPOINTS ===

@app.post("/integrity/register")
async def register_model(
 request: ModelRegistrationRequest,
 api_key: str = Depends(verify_api_key)
):
 """
 Register a model for integrity monitoring and verification
 """
 try:
 integrity_manager = app.state.integrity_manager

 model_id = integrity_manager.register_model(
 model_name=request.model_name,
 model_version=request.model_version,
 model_path=request.model_path,
 created_by=request.created_by,
 organization=request.organization,
 private_key_path=request.private_key_path,
 public_key_path=request.public_key_path,
 generate_manifest=request.generate_manifest,
 metadata=request.metadata
 )

 return {
 "status": "success",
 "model_id": model_id,
 "message": "Model registered successfully",
 "manifest_generated": request.generate_manifest
 }

 except Exception as e:
 logging.error(f"Error registering model: {str(e)}")
 raise HTTPException(status_code=500, detail=str(e))


@app.get("/integrity/models")
async def list_models(api_key: str = Depends(verify_api_key)):
 """
 List all registered models with their integrity status
 """
 try:
 integrity_manager = app.state.integrity_manager
 models = integrity_manager.list_models(include_status=True)

 return {
 "status": "success",
 "total_models": len(models),
 "models": models
 }

 except Exception as e:
 logging.error(f"Error listing models: {str(e)}")
 raise HTTPException(status_code=500, detail=str(e))


@app.post("/integrity/verify/{model_id}")
async def verify_model(
 model_id: str,
 public_key_path: Optional[str] = None,
 api_key: str = Depends(verify_api_key)
):
 """
 Verify the integrity of a registered model
 """
 try:
 integrity_manager = app.state.integrity_manager

 result = integrity_manager.verify_model(
 model_id=model_id,
 public_key_path=public_key_path,
 verbose=False
 )

 return {
 "status": "success",
 "model_id": model_id,
 "verification_result": {
 "overall_status": result.overall_status.value,
 "signature_valid": result.signature_valid,
 "files_verified": result.files_verified,
 "files_failed": result.files_failed,
 "files_missing": result.files_missing,
 "verification_time": result.verification_time,
 "messages": result.messages
 }
 }

 except Exception as e:
 logging.error(f"Error verifying model {model_id}: {str(e)}")
 raise HTTPException(status_code=500, detail=str(e))


@app.post("/integrity/report")
async def get_integrity_report(
 request: IntegrityReportRequest,
 api_key: str = Depends(verify_api_key)
):
 """
 Generate comprehensive integrity report for a model
 """
 try:
 integrity_manager = app.state.integrity_manager

 report = integrity_manager.get_integrity_report(
 model_id=request.model_id,
 include_access_logs=request.include_access_logs,
 hours_back=request.hours_back
 )

 # Convert to serializable format
 report_data = {
 "model_name": report.model_name,
 "model_version": report.model_version,
 "integrity_status": report.integrity_status.value,
 "last_verified": report.last_verified,
 "suspicious_patterns": report.suspicious_patterns,
 "access_summary": report.access_summary,
 "recommendations": report.recommendations,
 "metadata": report.metadata
 }

 if report.verification_result:
 report_data["verification_details"] = {
 "overall_status": report.verification_result.overall_status.value,
 "files_verified": report.verification_result.files_verified,
 "files_failed": report.verification_result.files_failed,
 "signature_valid": report.verification_result.signature_valid
 }

 return {
 "status": "success",
 "report": report_data
 }

 except Exception as e:
 logging.error(f"Error generating integrity report: {str(e)}")
 raise HTTPException(status_code=500, detail=str(e))


@app.get("/integrity/compliance")
async def get_compliance_report(
 start_date: str,
 end_date: str,
 model_filter: Optional[str] = None,
 api_key: str = Depends(verify_api_key)
):
 """
 Generate compliance report for regulatory requirements
 """
 try:
 integrity_manager = app.state.integrity_manager

 report = integrity_manager.generate_compliance_report(
 start_date=start_date,
 end_date=end_date,
 model_filter=model_filter
 )

 return {
 "status": "success",
 "compliance_report": report
 }

 except Exception as e:
 logging.error(f"Error generating compliance report: {str(e)}")
 raise HTTPException(status_code=500, detail=str(e))


@app.get("/integrity/audit/patterns")
async def get_suspicious_patterns(
 hours: int = 24,
 min_risk_score: float = 0.5,
 api_key: str = Depends(verify_api_key)
):
 """
 Get suspicious access patterns detected in the specified time period
 """
 try:
 integrity_manager = app.state.integrity_manager
 patterns = integrity_manager.audit_logger.get_suspicious_patterns(
 hours=hours,
 min_risk_score=min_risk_score
 )

 patterns_data = []
 for pattern in patterns:
 patterns_data.append({
 "pattern_id": pattern.pattern_id,
 "pattern_type": pattern.pattern_type,
 "description": pattern.description,
 "first_seen": pattern.first_seen,
 "last_seen": pattern.last_seen,
 "event_count": pattern.event_count,
 "risk_score": pattern.risk_score,
 "affected_models": pattern.affected_models,
 "user_ids": pattern.user_ids,
 "ip_addresses": pattern.ip_addresses,
 "indicators": pattern.indicators
 })

 return {
 "status": "success",
 "patterns_found": len(patterns_data),
 "time_period_hours": hours,
 "min_risk_score": min_risk_score,
 "patterns": patterns_data
 }

 except Exception as e:
 logging.error(f"Error getting suspicious patterns: {str(e)}")
 raise HTTPException(status_code=500, detail=str(e))


# === MONITORING ENDPOINTS ===

@app.get("/monitoring/health")
async def get_monitoring_health(api_key: str = Depends(verify_api_key)):
 """
 Get overall monitoring system health status
 """
 try:
 monitoring_manager = app.state.monitoring_manager
 health_data = monitoring_manager.get_overall_health()

 return {
 "status": "success",
 "monitoring_health": health_data
 }

 except Exception as e:
 logging.error(f"Error getting monitoring health: {str(e)}")
 raise HTTPException(status_code=500, detail=str(e))


@app.get("/monitoring/alerts")
async def get_recent_alerts(
 hours_back: int = 24,
 api_key: str = Depends(verify_api_key)
):
 """
 Get recent alerts from all monitoring systems
 """
 try:
 monitoring_manager = app.state.monitoring_manager
 alerts = monitoring_manager.get_recent_alerts(hours_back=hours_back)

 return {
 "status": "success",
 "time_period_hours": hours_back,
 "total_alerts": sum(len(alert_list) for alert_list in alerts.values()),
 "alerts": alerts
 }

 except Exception as e:
 logging.error(f"Error getting recent alerts: {str(e)}")
 raise HTTPException(status_code=500, detail=str(e))


@app.get("/monitoring/performance")
async def get_performance_metrics(api_key: str = Depends(verify_api_key)):
 """
 Get current performance metrics and analysis
 """
 try:
 monitoring_manager = app.state.monitoring_manager
 metrics = monitoring_manager.get_performance_metrics()

 return {
 "status": "success",
 "performance_data": metrics
 }

 except Exception as e:
 logging.error(f"Error getting performance metrics: {str(e)}")
 raise HTTPException(status_code=500, detail=str(e))


@app.get("/monitoring/quality")
async def get_quality_summary(
 hours_back: int = 1,
 api_key: str = Depends(verify_api_key)
):
 """
 Get model output quality summary and analysis
 """
 try:
 monitoring_manager = app.state.monitoring_manager
 quality_data = monitoring_manager.get_quality_summary()

 return {
 "status": "success",
 "quality_analysis": quality_data
 }

 except Exception as e:
 logging.error(f"Error getting quality summary: {str(e)}")
 raise HTTPException(status_code=500, detail=str(e))


@app.get("/monitoring/dos")
async def get_dos_status(api_key: str = Depends(verify_api_key)):
 """
 Get DoS monitoring status and recent attack patterns
 """
 try:
 monitoring_manager = app.state.monitoring_manager
 dos_data = monitoring_manager.get_dos_status()

 return {
 "status": "success",
 "dos_monitoring": dos_data
 }

 except Exception as e:
 logging.error(f"Error getting DoS status: {str(e)}")
 raise HTTPException(status_code=500, detail=str(e))


@app.get("/monitoring/statistics")
async def get_monitoring_statistics(api_key: str = Depends(verify_api_key)):
 """
 Get comprehensive monitoring statistics
 """
 try:
 monitoring_manager = app.state.monitoring_manager
 stats = monitoring_manager.get_monitoring_statistics()

 return {
 "status": "success",
 "monitoring_statistics": stats
 }

 except Exception as e:
 logging.error(f"Error getting monitoring statistics: {str(e)}")
 raise HTTPException(status_code=500, detail=str(e))


@app.post("/monitoring/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
 alert_id: str,
 acknowledged_by: str,
 note: str = "",
 api_key: str = Depends(verify_api_key)
):
 """
 Acknowledge a specific alert
 """
 try:
 monitoring_manager = app.state.monitoring_manager

 if monitoring_manager.alert_system:
 success = monitoring_manager.alert_system.acknowledge_alert(
 alert_id=alert_id,
 acknowledged_by=acknowledged_by,
 note=note
 )

 return {
 "status": "success" if success else "not_found",
 "alert_id": alert_id,
 "acknowledged": success
 }
 else:
 raise HTTPException(status_code=503, detail="Alert system not available")

 except Exception as e:
 logging.error(f"Error acknowledging alert: {str(e)}")
 raise HTTPException(status_code=500, detail=str(e))


@app.post("/monitoring/alerts/{alert_id}/resolve")
async def resolve_alert(
 alert_id: str,
 resolved_by: str,
 resolution_note: str = "",
 api_key: str = Depends(verify_api_key)
):
 """
 Resolve a specific alert
 """
 try:
 monitoring_manager = app.state.monitoring_manager

 if monitoring_manager.alert_system:
 success = monitoring_manager.alert_system.resolve_alert(
 alert_id=alert_id,
 resolved_by=resolved_by,
 resolution_note=resolution_note
 )

 return {
 "status": "success" if success else "not_found",
 "alert_id": alert_id,
 "resolved": success
 }
 else:
 raise HTTPException(status_code=503, detail="Alert system not available")

 except Exception as e:
 logging.error(f"Error resolving alert: {str(e)}")
 raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
 import uvicorn
 uvicorn.run(app, host="0.0.0.0", port=8000)