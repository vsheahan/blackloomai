"""
BlackLoom Defense - Monitoring Manager
Central orchestrator for post-deployment monitoring system
Addresses OWASP ML04 (Model DoS) and ML09 (Overreliance)
"""

import time
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
import logging
import json

from .dos_monitor import DoSMonitor, DoSAlert
from .performance_monitor import PerformanceMonitor, PerformanceMetrics
from .quality_monitor import QualityMonitor, QualityAlert
from .alert_system import AlertSystem, AlertLevel, AlertType


@dataclass
class MonitoringConfig:
 """Configuration for monitoring system"""
 dos_enabled: bool = True
 performance_enabled: bool = True
 quality_enabled: bool = True
 alerts_enabled: bool = True

 # Update intervals
 metrics_update_interval: int = 60 # seconds
 alert_check_interval: int = 30 # seconds

 # Integration settings
 auto_mitigation: bool = True
 alert_routing: Dict[str, List[str]] = None


class MonitoringManager:
 """
 Central manager for BlackLoom Defense monitoring system
 Coordinates DoS detection, performance monitoring, quality assessment, and alerting
 """

 def __init__(self, config: Optional[Dict] = None):
 self.config = config or {}
 self.logger = logging.getLogger(__name__)

 # Initialize monitoring configuration
 self.monitoring_config = MonitoringConfig(**self.config.get('monitoring', {}))

 # Initialize monitoring components
 self.dos_monitor = None
 self.performance_monitor = None
 self.quality_monitor = None
 self.alert_system = None

 self._init_monitoring_components()

 # Monitoring state
 self.monitoring_active = False
 self.monitor_thread = None

 # Callbacks for external integration
 self.alert_callbacks = []
 self.mitigation_callbacks = []

 # Thread safety
 self._lock = threading.Lock()

 self.logger.info("Monitoring Manager initialized")

 def _init_monitoring_components(self):
 """Initialize all monitoring components"""

 # DoS Monitor
 if self.monitoring_config.dos_enabled:
 self.dos_monitor = DoSMonitor(self.config.get('dos_monitor', {}))
 self.logger.info("DoS Monitor enabled")

 # Performance Monitor
 if self.monitoring_config.performance_enabled:
 self.performance_monitor = PerformanceMonitor(self.config.get('performance_monitor', {}))
 self.logger.info("Performance Monitor enabled")

 # Quality Monitor
 if self.monitoring_config.quality_enabled:
 self.quality_monitor = QualityMonitor(self.config.get('quality_monitor', {}))
 self.logger.info("Quality Monitor enabled")

 # Alert System
 if self.monitoring_config.alerts_enabled:
 self.alert_system = AlertSystem(self.config.get('alert_system', {}))
 self.logger.info("Alert System enabled")

 def start_monitoring(self):
 """Start the monitoring system"""
 if self.monitoring_active:
 self.logger.warning("Monitoring already active")
 return

 self.monitoring_active = True

 # Start monitoring thread
 self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
 self.monitor_thread.start()

 self.logger.info("Monitoring system started")

 def stop_monitoring(self):
 """Stop the monitoring system"""
 self.monitoring_active = False

 if self.monitor_thread:
 self.monitor_thread.join(timeout=10)

 # Shutdown components
 if self.performance_monitor:
 self.performance_monitor.shutdown()

 self.logger.info("Monitoring system stopped")

 def _monitoring_loop(self):
 """Main monitoring loop"""
 while self.monitoring_active:
 try:
 # Check for alerts and trigger notifications
 self._process_monitoring_cycle()

 # Wait for next cycle
 time.sleep(self.monitoring_config.alert_check_interval)

 except Exception as e:
 self.logger.error(f"Error in monitoring loop: {e}")
 time.sleep(self.monitoring_config.alert_check_interval)

 def _process_monitoring_cycle(self):
 """Process one monitoring cycle - check for issues and generate alerts"""

 # Get current metrics from all monitors
 dos_status = self.get_dos_status() if self.dos_monitor else {}
 performance_metrics = self.get_performance_metrics() if self.performance_monitor else {}
 quality_summary = self.get_quality_summary() if self.quality_monitor else {}

 # Check for threshold violations and generate alerts
 self._check_performance_thresholds(performance_metrics)
 self._check_quality_thresholds(quality_summary)
 self._check_dos_thresholds(dos_status)

 def record_request(self,
 client_ip: str,
 model_name: str,
 user_input: str,
 model_output: str,
 response_time_ms: float,
 request_size: int = 0,
 response_size: int = 0,
 is_error: bool = False,
 confidence_score: Optional[float] = None,
 complexity_score: float = 0.0,
 metadata: Optional[Dict] = None):
 """
 Record a model request across all monitoring systems

 Args:
 client_ip: Source IP address
 model_name: Name of the accessed model
 user_input: User's input to the model
 model_output: Model's response
 response_time_ms: Request processing time
 request_size: Size of request in bytes
 response_size: Size of response in bytes
 is_error: Whether request resulted in error
 confidence_score: Model's confidence (if available)
 complexity_score: Computational complexity score
 metadata: Additional request metadata
 """

 # Record in DoS monitor
 if self.dos_monitor:
 self.dos_monitor.record_request(
 client_ip=client_ip,
 model_name=model_name,
 response_time_ms=response_time_ms,
 request_size=request_size,
 response_size=response_size,
 is_error=is_error,
 complexity_score=complexity_score,
 metadata=metadata
 )

 # Record in performance monitor
 if self.performance_monitor:
 self.performance_monitor.record_request(
 model_name=model_name,
 response_time_ms=response_time_ms,
 success=not is_error,
 request_size=request_size,
 response_size=response_size,
 metadata=metadata
 )

 # Analyze in quality monitor
 if self.quality_monitor:
 quality_alerts = self.quality_monitor.analyze_output_quality(
 model_name=model_name,
 user_input=user_input,
 model_output=model_output,
 response_time_ms=response_time_ms,
 confidence_score=confidence_score,
 metadata=metadata
 )

 # Convert quality alerts to system alerts
 for quality_alert in quality_alerts:
 self._create_quality_alert(quality_alert)

 def _create_quality_alert(self, quality_alert: QualityAlert):
 """Convert quality alert to system alert"""
 if not self.alert_system:
 return

 # Map quality issue severity
 severity_map = {
 "LOW": AlertLevel.LOW,
 "MEDIUM": AlertLevel.MEDIUM,
 "HIGH": AlertLevel.HIGH,
 "CRITICAL": AlertLevel.CRITICAL
 }

 alert_level = severity_map.get(quality_alert.severity, AlertLevel.MEDIUM)

 self.alert_system.create_alert(
 alert_type=AlertType.QUALITY_DEGRADATION,
 alert_level=alert_level,
 title=f"Quality Issue: {quality_alert.quality_issue.value}",
 description=quality_alert.description,
 source_component="quality_monitor",
 affected_models=quality_alert.affected_models,
 recommendations=quality_alert.sample_outputs[:3], # Use sample outputs as recommendations
 metadata={
 'quality_issue_type': quality_alert.quality_issue.value,
 'confidence_score': quality_alert.confidence_score,
 'sample_outputs': quality_alert.sample_outputs
 }
 )

 def _check_performance_thresholds(self, metrics: Dict):
 """Check performance metrics against thresholds"""
 if not metrics or not self.alert_system:
 return

 current_metrics = metrics.get('current_metrics', {})

 # Check response time
 avg_response_time = current_metrics.get('avg_response_time_ms', 0)
 if avg_response_time > 3000: # 3 second threshold
 self.alert_system.create_alert(
 alert_type=AlertType.PERFORMANCE_ISSUE,
 alert_level=AlertLevel.HIGH,
 title="High Response Time",
 description=f"Average response time is {avg_response_time:.0f}ms",
 source_component="performance_monitor",
 recommendations=[
 "Scale up infrastructure",
 "Optimize model performance",
 "Check for resource constraints"
 ],
 metadata={'avg_response_time_ms': avg_response_time}
 )

 # Check throughput
 throughput = current_metrics.get('throughput_rps', 0)
 if throughput < 0.1: # Very low throughput
 self.alert_system.create_alert(
 alert_type=AlertType.PERFORMANCE_ISSUE,
 alert_level=AlertLevel.MEDIUM,
 title="Low Throughput",
 description=f"Throughput is {throughput:.2f} RPS",
 source_component="performance_monitor",
 recommendations=[
 "Check for bottlenecks",
 "Verify system health",
 "Review resource allocation"
 ],
 metadata={'throughput_rps': throughput}
 )

 def _check_quality_thresholds(self, summary: Dict):
 """Check quality metrics against thresholds"""
 if not summary or not self.alert_system:
 return

 current_metrics = summary.get('current_metrics', {})

 # Check coherence score
 coherence = current_metrics.get('avg_coherence_score', 1.0)
 if coherence < 0.6:
 self.alert_system.create_alert(
 alert_type=AlertType.QUALITY_DEGRADATION,
 alert_level=AlertLevel.HIGH,
 title="Low Output Coherence",
 description=f"Average coherence score is {coherence:.2f}",
 source_component="quality_monitor",
 recommendations=[
 "Review model outputs for quality",
 "Consider model retraining",
 "Enable human review for low-coherence outputs"
 ],
 metadata={'avg_coherence_score': coherence}
 )

 # Check hallucination rate
 hallucination_rate = current_metrics.get('hallucination_rate', 0.0)
 if hallucination_rate > 0.1: # 10% threshold
 self.alert_system.create_alert(
 alert_type=AlertType.QUALITY_DEGRADATION,
 alert_level=AlertLevel.CRITICAL,
 title="High Hallucination Rate",
 description=f"Hallucination rate is {hallucination_rate:.2%}",
 source_component="quality_monitor",
 recommendations=[
 "Implement hallucination detection",
 "Add confidence thresholding",
 "Enable mandatory human review"
 ],
 metadata={'hallucination_rate': hallucination_rate}
 )

 def _check_dos_thresholds(self, status: Dict):
 """Check DoS metrics against thresholds"""
 if not status or not self.alert_system:
 return

 current_metrics = status.get('current_metrics', {})
 recent_alerts = status.get('recent_alerts', 0)

 # Check for recent DoS alerts
 if recent_alerts > 0:
 self.alert_system.create_alert(
 alert_type=AlertType.DOS_ATTACK,
 alert_level=AlertLevel.HIGH,
 title="DoS Attack Detected",
 description=f"{recent_alerts} DoS alerts in last 5 minutes",
 source_component="dos_monitor",
 recommendations=[
 "Review blocked IPs",
 "Scale infrastructure if needed",
 "Enable additional rate limiting"
 ],
 metadata={'recent_dos_alerts': recent_alerts}
 )

 # Check request rate
 rps = current_metrics.get('requests_per_second', 0)
 if rps > 50: # High request rate threshold
 self.alert_system.create_alert(
 alert_type=AlertType.DOS_ATTACK,
 alert_level=AlertLevel.MEDIUM,
 title="High Request Rate",
 description=f"Request rate is {rps:.1f} RPS",
 source_component="dos_monitor",
 recommendations=[
 "Monitor for potential DoS attack",
 "Enable request throttling",
 "Check request patterns"
 ],
 metadata={'requests_per_second': rps}
 )

 def get_overall_health(self) -> Dict[str, Any]:
 """Get overall system health status"""
 health_data = {
 'timestamp': time.time(),
 'overall_status': 'healthy',
 'components': {}
 }

 issues = []

 # DoS Monitor Health
 if self.dos_monitor:
 dos_status = self.dos_monitor.get_current_status()
 health_data['components']['dos_monitor'] = {
 'status': 'healthy' if dos_status['recent_alerts'] == 0 else 'alert',
 'recent_alerts': dos_status['recent_alerts'],
 'blocked_ips': len(dos_status['blocked_ips'])
 }
 if dos_status['recent_alerts'] > 0:
 issues.append('dos_alerts')

 # Performance Monitor Health
 if self.performance_monitor:
 perf_metrics = self.performance_monitor.get_current_metrics()
 avg_response_time = perf_metrics.get('avg_response_time_ms', 0)

 health_data['components']['performance_monitor'] = {
 'status': 'healthy' if avg_response_time < 2000 else 'warning',
 'avg_response_time_ms': avg_response_time,
 'throughput_rps': perf_metrics.get('throughput_rps', 0)
 }
 if avg_response_time > 3000:
 issues.append('performance_degradation')

 # Quality Monitor Health
 if self.quality_monitor:
 quality_summary = self.quality_monitor.get_quality_summary(hours_back=1)
 if quality_summary.get('status') != 'no_data':
 current_metrics = quality_summary.get('current_metrics', {})
 coherence = current_metrics.get('avg_coherence_score', 1.0)

 health_data['components']['quality_monitor'] = {
 'status': 'healthy' if coherence > 0.7 else 'warning',
 'avg_coherence_score': coherence,
 'recent_alerts': quality_summary.get('total_alerts', 0)
 }
 if coherence < 0.6:
 issues.append('quality_degradation')

 # Alert System Health
 if self.alert_system:
 alert_health = self.alert_system.get_health_summary()
 health_data['components']['alert_system'] = alert_health

 if alert_health['health_status'] == 'critical':
 issues.append('critical_alerts')

 # Determine overall status
 if any(issue in ['critical_alerts'] for issue in issues):
 health_data['overall_status'] = 'critical'
 elif issues:
 health_data['overall_status'] = 'warning'

 health_data['active_issues'] = issues
 health_data['monitoring_active'] = self.monitoring_active

 return health_data

 def get_dos_status(self) -> Dict[str, Any]:
 """Get DoS monitoring status"""
 if not self.dos_monitor:
 return {'status': 'disabled'}

 return self.dos_monitor.get_current_status()

 def get_performance_metrics(self) -> Dict[str, Any]:
 """Get performance metrics"""
 if not self.performance_monitor:
 return {'status': 'disabled'}

 current_metrics = self.performance_monitor.get_current_metrics()
 performance_summary = self.performance_monitor.get_performance_summary(hours_back=1)

 return {
 'current_metrics': current_metrics,
 'performance_summary': performance_summary,
 'capacity_recommendations': self.performance_monitor.get_capacity_recommendations()
 }

 def get_quality_summary(self) -> Dict[str, Any]:
 """Get quality monitoring summary"""
 if not self.quality_monitor:
 return {'status': 'disabled'}

 return self.quality_monitor.get_quality_summary(hours_back=1)

 def get_recent_alerts(self, hours_back: int = 24) -> Dict[str, List]:
 """Get recent alerts from all systems"""
 alerts = {
 'system_alerts': [],
 'dos_alerts': [],
 'quality_alerts': []
 }

 # System alerts
 if self.alert_system:
 system_alerts = self.alert_system.get_alert_history(hours_back)
 alerts['system_alerts'] = [
 {
 'alert_id': alert.alert_id,
 'timestamp': alert.timestamp,
 'alert_type': alert.alert_type.value,
 'alert_level': alert.alert_level.value,
 'title': alert.title,
 'description': alert.description,
 'source_component': alert.source_component,
 'resolved': alert.resolved
 }
 for alert in system_alerts
 ]

 # DoS alerts
 if self.dos_monitor:
 dos_alerts = self.dos_monitor.get_recent_alerts(hours_back)
 alerts['dos_alerts'] = [
 {
 'alert_id': alert.alert_id,
 'timestamp': alert.timestamp,
 'dos_type': alert.dos_type.value,
 'severity': alert.severity,
 'description': alert.description,
 'source_ips': alert.source_ips,
 'mitigation_actions': alert.mitigation_actions
 }
 for alert in dos_alerts
 ]

 # Quality alerts
 if self.quality_monitor:
 quality_alerts = self.quality_monitor.get_recent_alerts(hours_back)
 alerts['quality_alerts'] = [
 {
 'alert_id': alert.alert_id,
 'timestamp': alert.timestamp,
 'quality_issue': alert.quality_issue.value,
 'severity': alert.severity,
 'description': alert.description,
 'affected_models': alert.affected_models,
 'confidence_score': alert.confidence_score,
 'recommendation': alert.recommendation
 }
 for alert in quality_alerts
 ]

 return alerts

 def register_alert_callback(self, callback: Callable[[Dict], None]):
 """Register callback for alert notifications"""
 self.alert_callbacks.append(callback)

 def register_mitigation_callback(self, callback: Callable[[str, Dict], bool]):
 """Register callback for automated mitigation"""
 self.mitigation_callbacks.append(callback)

 def get_monitoring_statistics(self) -> Dict[str, Any]:
 """Get comprehensive monitoring statistics"""
 stats = {
 'timestamp': time.time(),
 'monitoring_active': self.monitoring_active,
 'components_enabled': {
 'dos_monitor': self.dos_monitor is not None,
 'performance_monitor': self.performance_monitor is not None,
 'quality_monitor': self.quality_monitor is not None,
 'alert_system': self.alert_system is not None
 }
 }

 # Add component statistics
 if self.dos_monitor:
 stats['dos_statistics'] = self.dos_monitor.get_metrics_summary(window_minutes=60)

 if self.performance_monitor:
 stats['performance_statistics'] = self.performance_monitor.get_performance_summary(hours_back=1)

 if self.quality_monitor:
 stats['quality_statistics'] = self.quality_monitor.get_quality_summary(hours_back=1)

 if self.alert_system:
 stats['alert_statistics'] = self.alert_system.get_alert_statistics(hours_back=24)

 return stats