"""
BlackLoom Defense - DoS Attack Monitor
Detects and mitigates Model Denial of Service attacks (OWASP ML04)
"""

import time
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from collections import deque, defaultdict
from enum import Enum
import statistics
import logging


class DoSType(Enum):
 """Types of DoS attacks detected"""
 RESOURCE_EXHAUSTION = "resource_exhaustion"
 REQUEST_FLOODING = "request_flooding"
 COMPLEXITY_ATTACK = "complexity_attack"
 CONCURRENT_OVERLOAD = "concurrent_overload"
 MEMORY_EXHAUSTION = "memory_exhaustion"


@dataclass
class DoSMetrics:
 """DoS-related metrics for a time window"""
 timestamp: float
 requests_per_second: float
 avg_response_time_ms: float
 concurrent_requests: int
 memory_usage_mb: float
 cpu_usage_percent: float
 error_rate: float
 queue_depth: int
 rejected_requests: int


@dataclass
class DoSAlert:
 """Alert for detected DoS attack"""
 alert_id: str
 timestamp: float
 dos_type: DoSType
 severity: str
 description: str
 metrics: DoSMetrics
 source_ips: List[str]
 affected_models: List[str]
 mitigation_actions: List[str]
 metadata: Dict[str, Any]


class DoSMonitor:
 """
 Monitors for Model Denial of Service attacks
 Detects resource exhaustion, request flooding, and complexity attacks
 """

 def __init__(self, config: Optional[Dict] = None):
 self.config = config or {}
 self.logger = logging.getLogger(__name__)

 # Thresholds for DoS detection
 self.thresholds = self.config.get('dos_thresholds', {
 'max_rps': 100, # Requests per second
 'max_response_time_ms': 5000, # Response time threshold
 'max_concurrent_requests': 50, # Concurrent request limit
 'max_memory_usage_mb': 4096, # Memory usage limit
 'max_cpu_usage': 85, # CPU usage percentage
 'max_error_rate': 0.1, # 10% error rate threshold
 'max_queue_depth': 100, # Request queue depth
 'complexity_threshold': 1000 # Token/computation threshold
 })

 # Time windows for analysis
 self.window_sizes = self.config.get('window_sizes', {
 'short': 60, # 1 minute
 'medium': 300, # 5 minutes
 'long': 900 # 15 minutes
 })

 # Data storage
 self.metrics_history = deque(maxlen=1000)
 self.request_history = deque(maxlen=10000)
 self.alerts_history = deque(maxlen=100)

 # IP-based tracking for flooding detection
 self.ip_request_counts = defaultdict(lambda: deque(maxlen=1000))
 self.blocked_ips = set()

 # Thread safety
 self._lock = threading.Lock()

 # Current state
 self.current_metrics = DoSMetrics(
 timestamp=time.time(),
 requests_per_second=0.0,
 avg_response_time_ms=0.0,
 concurrent_requests=0,
 memory_usage_mb=0.0,
 cpu_usage_percent=0.0,
 error_rate=0.0,
 queue_depth=0,
 rejected_requests=0
 )

 self.logger.info("DoS Monitor initialized")

 def record_request(self,
 client_ip: str,
 model_name: str,
 response_time_ms: float,
 request_size: int,
 response_size: int,
 is_error: bool = False,
 complexity_score: float = 0.0,
 metadata: Optional[Dict] = None):
 """
 Record a model request for DoS analysis

 Args:
 client_ip: Source IP address
 model_name: Name of the accessed model
 response_time_ms: Request processing time
 request_size: Size of request in bytes
 response_size: Size of response in bytes
 is_error: Whether request resulted in error
 complexity_score: Computational complexity score
 metadata: Additional request metadata
 """
 with self._lock:
 current_time = time.time()

 # Record request details
 request_data = {
 'timestamp': current_time,
 'client_ip': client_ip,
 'model_name': model_name,
 'response_time_ms': response_time_ms,
 'request_size': request_size,
 'response_size': response_size,
 'is_error': is_error,
 'complexity_score': complexity_score,
 'metadata': metadata or {}
 }

 self.request_history.append(request_data)
 self.ip_request_counts[client_ip].append(current_time)

 # Update current metrics
 self._update_current_metrics()

 # Check for DoS patterns
 alerts = self._analyze_dos_patterns(request_data)

 for alert in alerts:
 self.alerts_history.append(alert)
 self.logger.warning(f"DoS Alert: {alert.dos_type.value} - {alert.description}")

 def _update_current_metrics(self):
 """Update current DoS metrics based on recent requests"""
 current_time = time.time()

 # Get requests from last minute
 recent_requests = [
 req for req in self.request_history
 if current_time - req['timestamp'] <= 60
 ]

 if not recent_requests:
 return

 # Calculate metrics
 self.current_metrics = DoSMetrics(
 timestamp=current_time,
 requests_per_second=len(recent_requests) / 60.0,
 avg_response_time_ms=statistics.mean([req['response_time_ms'] for req in recent_requests]),
 concurrent_requests=self._estimate_concurrent_requests(),
 memory_usage_mb=self._get_memory_usage(),
 cpu_usage_percent=self._get_cpu_usage(),
 error_rate=sum(1 for req in recent_requests if req['is_error']) / len(recent_requests),
 queue_depth=0, # Would be provided by application
 rejected_requests=0 # Would be tracked separately
 )

 # Store metrics history
 self.metrics_history.append(asdict(self.current_metrics))

 def _analyze_dos_patterns(self, request_data: Dict) -> List[DoSAlert]:
 """Analyze request patterns for DoS attacks"""
 alerts = []
 current_time = time.time()

 # 1. Request Flooding Detection
 flooding_alert = self._check_request_flooding(request_data, current_time)
 if flooding_alert:
 alerts.append(flooding_alert)

 # 2. Resource Exhaustion Detection
 resource_alert = self._check_resource_exhaustion()
 if resource_alert:
 alerts.append(resource_alert)

 # 3. Complexity Attack Detection
 complexity_alert = self._check_complexity_attack(request_data)
 if complexity_alert:
 alerts.append(complexity_alert)

 # 4. Concurrent Request Overload
 concurrent_alert = self._check_concurrent_overload()
 if concurrent_alert:
 alerts.append(concurrent_alert)

 return alerts

 def _check_request_flooding(self, request_data: Dict, current_time: float) -> Optional[DoSAlert]:
 """Check for request flooding attacks"""
 client_ip = request_data['client_ip']

 # Count requests from this IP in last minute
 ip_requests = [
 timestamp for timestamp in self.ip_request_counts[client_ip]
 if current_time - timestamp <= 60
 ]

 requests_per_minute = len(ip_requests)

 # Check if exceeds threshold (convert RPS to RPM)
 if requests_per_minute > self.thresholds['max_rps'] * 60:

 # Generate alert
 alert_id = f"flooding_{client_ip}_{int(current_time)}"

 return DoSAlert(
 alert_id=alert_id,
 timestamp=current_time,
 dos_type=DoSType.REQUEST_FLOODING,
 severity="HIGH",
 description=f"Request flooding detected from {client_ip}: {requests_per_minute} requests/min",
 metrics=self.current_metrics,
 source_ips=[client_ip],
 affected_models=[request_data['model_name']],
 mitigation_actions=[
 f"Rate limit IP {client_ip}",
 "Enable CAPTCHA verification",
 "Consider IP blocking"
 ],
 metadata={
 'requests_per_minute': requests_per_minute,
 'threshold_exceeded': requests_per_minute - (self.thresholds['max_rps'] * 60)
 }
 )

 return None

 def _check_resource_exhaustion(self) -> Optional[DoSAlert]:
 """Check for resource exhaustion attacks"""
 metrics = self.current_metrics

 alerts = []

 # Check response time
 if metrics.avg_response_time_ms > self.thresholds['max_response_time_ms']:
 alerts.append("High response times detected")

 # Check memory usage
 if metrics.memory_usage_mb > self.thresholds['max_memory_usage_mb']:
 alerts.append("Memory usage threshold exceeded")

 # Check CPU usage
 if metrics.cpu_usage_percent > self.thresholds['max_cpu_usage']:
 alerts.append("CPU usage threshold exceeded")

 # Check error rate
 if metrics.error_rate > self.thresholds['max_error_rate']:
 alerts.append("Error rate threshold exceeded")

 if alerts:
 alert_id = f"resource_exhaustion_{int(time.time())}"

 return DoSAlert(
 alert_id=alert_id,
 timestamp=time.time(),
 dos_type=DoSType.RESOURCE_EXHAUSTION,
 severity="CRITICAL" if len(alerts) > 2 else "HIGH",
 description=f"Resource exhaustion detected: {', '.join(alerts)}",
 metrics=metrics,
 source_ips=[],
 affected_models=[],
 mitigation_actions=[
 "Scale up infrastructure",
 "Enable request queuing",
 "Implement circuit breakers",
 "Add resource monitoring alerts"
 ],
 metadata={
 'resource_issues': alerts,
 'response_time_ms': metrics.avg_response_time_ms,
 'memory_usage_mb': metrics.memory_usage_mb,
 'cpu_usage_percent': metrics.cpu_usage_percent
 }
 )

 return None

 def _check_complexity_attack(self, request_data: Dict) -> Optional[DoSAlert]:
 """Check for complexity-based DoS attacks"""
 complexity_score = request_data.get('complexity_score', 0)

 if complexity_score > self.thresholds['complexity_threshold']:
 alert_id = f"complexity_attack_{int(time.time())}"

 return DoSAlert(
 alert_id=alert_id,
 timestamp=time.time(),
 dos_type=DoSType.COMPLEXITY_ATTACK,
 severity="MEDIUM",
 description=f"High complexity request detected: score {complexity_score}",
 metrics=self.current_metrics,
 source_ips=[request_data['client_ip']],
 affected_models=[request_data['model_name']],
 mitigation_actions=[
 "Implement input complexity limits",
 "Add request preprocessing validation",
 "Set maximum computation timeouts"
 ],
 metadata={
 'complexity_score': complexity_score,
 'threshold': self.thresholds['complexity_threshold'],
 'request_size': request_data['request_size']
 }
 )

 return None

 def _check_concurrent_overload(self) -> Optional[DoSAlert]:
 """Check for concurrent request overload"""
 concurrent_requests = self.current_metrics.concurrent_requests

 if concurrent_requests > self.thresholds['max_concurrent_requests']:
 alert_id = f"concurrent_overload_{int(time.time())}"

 return DoSAlert(
 alert_id=alert_id,
 timestamp=time.time(),
 dos_type=DoSType.CONCURRENT_OVERLOAD,
 severity="HIGH",
 description=f"Concurrent request limit exceeded: {concurrent_requests} active",
 metrics=self.current_metrics,
 source_ips=[],
 affected_models=[],
 mitigation_actions=[
 "Implement connection pooling",
 "Add request queuing",
 "Scale horizontal infrastructure",
 "Enable load balancing"
 ],
 metadata={
 'concurrent_requests': concurrent_requests,
 'threshold': self.thresholds['max_concurrent_requests']
 }
 )

 return None

 def _estimate_concurrent_requests(self) -> int:
 """Estimate current concurrent requests"""
 current_time = time.time()

 # Count requests that started recently and might still be processing
 active_requests = [
 req for req in self.request_history
 if current_time - req['timestamp'] <= req['response_time_ms'] / 1000.0
 ]

 return len(active_requests)

 def _get_memory_usage(self) -> float:
 """Get current memory usage in MB"""
 try:
 import psutil
 process = psutil.Process()
 return process.memory_info().rss / (1024 * 1024)
 except ImportError:
 # Fallback if psutil not available
 return 0.0

 def _get_cpu_usage(self) -> float:
 """Get current CPU usage percentage"""
 try:
 import psutil
 return psutil.cpu_percent(interval=None)
 except ImportError:
 # Fallback if psutil not available
 return 0.0

 def get_current_status(self) -> Dict[str, Any]:
 """Get current DoS monitoring status"""
 return {
 'current_metrics': asdict(self.current_metrics),
 'recent_alerts': len([
 alert for alert in self.alerts_history
 if time.time() - alert.timestamp <= 300 # Last 5 minutes
 ]),
 'blocked_ips': list(self.blocked_ips),
 'monitoring_active': True,
 'thresholds': self.thresholds
 }

 def get_recent_alerts(self, hours_back: int = 1) -> List[DoSAlert]:
 """Get recent DoS alerts"""
 cutoff_time = time.time() - (hours_back * 3600)

 return [
 alert for alert in self.alerts_history
 if alert.timestamp >= cutoff_time
 ]

 def get_metrics_summary(self, window_minutes: int = 60) -> Dict[str, Any]:
 """Get summary of DoS metrics for specified time window"""
 cutoff_time = time.time() - (window_minutes * 60)

 recent_metrics = [
 metrics for metrics in self.metrics_history
 if metrics['timestamp'] >= cutoff_time
 ]

 if not recent_metrics:
 return {'status': 'no_data'}

 return {
 'time_window_minutes': window_minutes,
 'total_data_points': len(recent_metrics),
 'avg_rps': statistics.mean([m['requests_per_second'] for m in recent_metrics]),
 'max_rps': max([m['requests_per_second'] for m in recent_metrics]),
 'avg_response_time_ms': statistics.mean([m['avg_response_time_ms'] for m in recent_metrics]),
 'max_response_time_ms': max([m['avg_response_time_ms'] for m in recent_metrics]),
 'avg_error_rate': statistics.mean([m['error_rate'] for m in recent_metrics]),
 'max_concurrent_requests': max([m['concurrent_requests'] for m in recent_metrics]),
 'alerts_in_window': len([
 alert for alert in self.alerts_history
 if alert.timestamp >= cutoff_time
 ])
 }

 def apply_mitigation(self, alert: DoSAlert) -> bool:
 """Apply automatic mitigation for DoS attack"""
 try:
 if alert.dos_type == DoSType.REQUEST_FLOODING:
 # Block flooding IPs
 for ip in alert.source_ips:
 self.blocked_ips.add(ip)
 self.logger.info(f"Blocked IP for flooding: {ip}")
 return True

 elif alert.dos_type == DoSType.RESOURCE_EXHAUSTION:
 # Could trigger scaling, circuit breakers, etc.
 self.logger.info("Resource exhaustion mitigation triggered")
 return True

 elif alert.dos_type == DoSType.COMPLEXITY_ATTACK:
 # Could implement complexity limits
 self.logger.info("Complexity attack mitigation triggered")
 return True

 return False

 except Exception as e:
 self.logger.error(f"Error applying DoS mitigation: {e}")
 return False

 def is_ip_blocked(self, client_ip: str) -> bool:
 """Check if an IP address is blocked"""
 return client_ip in self.blocked_ips

 def unblock_ip(self, client_ip: str) -> bool:
 """Unblock an IP address"""
 if client_ip in self.blocked_ips:
 self.blocked_ips.remove(client_ip)
 self.logger.info(f"Unblocked IP: {client_ip}")
 return True
 return False