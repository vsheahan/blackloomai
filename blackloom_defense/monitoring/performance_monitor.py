"""
BlackLoom Defense - Performance Monitor
Monitors model performance metrics and resource utilization
"""

import time
import statistics
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from collections import deque
import threading
import logging


@dataclass
class PerformanceMetrics:
 """Performance metrics for a time window"""
 timestamp: float
 avg_response_time_ms: float
 p95_response_time_ms: float
 p99_response_time_ms: float
 throughput_rps: float
 success_rate: float
 avg_cpu_usage: float
 avg_memory_usage_mb: float
 avg_gpu_usage: float
 concurrent_requests: int
 queue_depth: int


@dataclass
class ResourceUsage:
 """Current resource usage snapshot"""
 timestamp: float
 cpu_percent: float
 memory_mb: float
 gpu_percent: float
 disk_io_mb: float
 network_io_mb: float


class PerformanceMonitor:
 """
 Monitors model performance and resource utilization
 Provides metrics for capacity planning and performance optimization
 """

 def __init__(self, config: Optional[Dict] = None):
 self.config = config or {}
 self.logger = logging.getLogger(__name__)

 # Monitoring configuration
 self.sample_interval = self.config.get('sample_interval', 60) # seconds
 self.history_size = self.config.get('history_size', 1440) # 24 hours at 1min intervals

 # Data storage
 self.metrics_history = deque(maxlen=self.history_size)
 self.resource_history = deque(maxlen=self.history_size)
 self.request_timings = deque(maxlen=10000)

 # Current state
 self.current_concurrent_requests = 0
 self.current_queue_depth = 0

 # Thread safety
 self._lock = threading.Lock()

 # Performance tracking
 self._init_performance_tracking()

 self.logger.info("Performance Monitor initialized")

 def _init_performance_tracking(self):
 """Initialize performance tracking components"""
 self.start_time = time.time()
 self.total_requests = 0
 self.total_errors = 0
 self.total_response_time = 0.0

 # Start resource monitoring thread
 self.monitoring_active = True
 self.monitor_thread = threading.Thread(target=self._resource_monitor_loop, daemon=True)
 self.monitor_thread.start()

 def record_request(self,
 model_name: str,
 response_time_ms: float,
 success: bool,
 request_size: int = 0,
 response_size: int = 0,
 metadata: Optional[Dict] = None):
 """
 Record a model request for performance analysis

 Args:
 model_name: Name of the model
 response_time_ms: Request processing time
 success: Whether request was successful
 request_size: Size of request in bytes
 response_size: Size of response in bytes
 metadata: Additional metadata
 """
 with self._lock:
 current_time = time.time()

 # Record timing data
 timing_data = {
 'timestamp': current_time,
 'model_name': model_name,
 'response_time_ms': response_time_ms,
 'success': success,
 'request_size': request_size,
 'response_size': response_size,
 'metadata': metadata or {}
 }

 self.request_timings.append(timing_data)

 # Update counters
 self.total_requests += 1
 self.total_response_time += response_time_ms
 if not success:
 self.total_errors += 1

 # Update concurrent request tracking
 self._update_concurrent_tracking()

 def increment_concurrent_requests(self):
 """Increment concurrent request counter"""
 with self._lock:
 self.current_concurrent_requests += 1

 def decrement_concurrent_requests(self):
 """Decrement concurrent request counter"""
 with self._lock:
 self.current_concurrent_requests = max(0, self.current_concurrent_requests - 1)

 def update_queue_depth(self, queue_depth: int):
 """Update current queue depth"""
 with self._lock:
 self.current_queue_depth = queue_depth

 def _update_concurrent_tracking(self):
 """Update concurrent request estimates based on recent requests"""
 current_time = time.time()

 # Estimate concurrent requests based on recent activity
 recent_requests = [
 req for req in self.request_timings
 if current_time - req['timestamp'] <= req['response_time_ms'] / 1000.0
 ]

 # Use actual count or estimated count, whichever is higher
 estimated_concurrent = len(recent_requests)
 self.current_concurrent_requests = max(self.current_concurrent_requests, estimated_concurrent)

 def _resource_monitor_loop(self):
 """Background thread for resource monitoring"""
 while self.monitoring_active:
 try:
 # Collect resource usage
 resource_usage = self._collect_resource_usage()

 with self._lock:
 self.resource_history.append(resource_usage)

 # Calculate and store performance metrics
 metrics = self._calculate_performance_metrics()
 if metrics:
 with self._lock:
 self.metrics_history.append(metrics)

 time.sleep(self.sample_interval)

 except Exception as e:
 self.logger.error(f"Error in resource monitoring: {e}")
 time.sleep(self.sample_interval)

 def _collect_resource_usage(self) -> ResourceUsage:
 """Collect current resource usage"""
 current_time = time.time()

 try:
 import psutil

 # CPU usage
 cpu_percent = psutil.cpu_percent(interval=1)

 # Memory usage
 memory = psutil.virtual_memory()
 memory_mb = memory.used / (1024 * 1024)

 # Disk I/O
 disk_io = psutil.disk_io_counters()
 disk_io_mb = (disk_io.read_bytes + disk_io.write_bytes) / (1024 * 1024) if disk_io else 0

 # Network I/O
 network_io = psutil.net_io_counters()
 network_io_mb = (network_io.bytes_sent + network_io.bytes_recv) / (1024 * 1024) if network_io else 0

 # GPU usage (if available)
 gpu_percent = self._get_gpu_usage()

 except ImportError:
 # Fallback values if psutil not available
 cpu_percent = 0.0
 memory_mb = 0.0
 disk_io_mb = 0.0
 network_io_mb = 0.0
 gpu_percent = 0.0

 return ResourceUsage(
 timestamp=current_time,
 cpu_percent=cpu_percent,
 memory_mb=memory_mb,
 gpu_percent=gpu_percent,
 disk_io_mb=disk_io_mb,
 network_io_mb=network_io_mb
 )

 def _get_gpu_usage(self) -> float:
 """Get GPU usage percentage (if available)"""
 try:
 import GPUtil
 gpus = GPUtil.getGPUs()
 if gpus:
 return sum(gpu.load * 100 for gpu in gpus) / len(gpus)
 except ImportError:
 pass

 return 0.0

 def _calculate_performance_metrics(self) -> Optional[PerformanceMetrics]:
 """Calculate performance metrics for the current time window"""
 current_time = time.time()
 window_start = current_time - self.sample_interval

 # Get requests from the current window
 window_requests = [
 req for req in self.request_timings
 if window_start <= req['timestamp'] <= current_time
 ]

 if not window_requests:
 return None

 # Calculate response time percentiles
 response_times = [req['response_time_ms'] for req in window_requests]
 response_times.sort()

 avg_response_time = statistics.mean(response_times)
 p95_response_time = self._calculate_percentile(response_times, 0.95)
 p99_response_time = self._calculate_percentile(response_times, 0.99)

 # Calculate throughput (requests per second)
 throughput_rps = len(window_requests) / self.sample_interval

 # Calculate success rate
 successful_requests = sum(1 for req in window_requests if req['success'])
 success_rate = successful_requests / len(window_requests)

 # Get recent resource usage
 recent_resources = [
 res for res in self.resource_history
 if window_start <= res.timestamp <= current_time
 ]

 if recent_resources:
 avg_cpu = statistics.mean([res.cpu_percent for res in recent_resources])
 avg_memory = statistics.mean([res.memory_mb for res in recent_resources])
 avg_gpu = statistics.mean([res.gpu_percent for res in recent_resources])
 else:
 avg_cpu = avg_memory = avg_gpu = 0.0

 return PerformanceMetrics(
 timestamp=current_time,
 avg_response_time_ms=avg_response_time,
 p95_response_time_ms=p95_response_time,
 p99_response_time_ms=p99_response_time,
 throughput_rps=throughput_rps,
 success_rate=success_rate,
 avg_cpu_usage=avg_cpu,
 avg_memory_usage_mb=avg_memory,
 avg_gpu_usage=avg_gpu,
 concurrent_requests=self.current_concurrent_requests,
 queue_depth=self.current_queue_depth
 )

 def _calculate_percentile(self, sorted_values: List[float], percentile: float) -> float:
 """Calculate percentile from sorted values"""
 if not sorted_values:
 return 0.0

 index = int(percentile * len(sorted_values))
 if index >= len(sorted_values):
 index = len(sorted_values) - 1

 return sorted_values[index]

 def get_current_metrics(self) -> Dict[str, Any]:
 """Get current performance metrics"""
 with self._lock:
 if self.metrics_history:
 latest_metrics = self.metrics_history[-1]
 return asdict(latest_metrics)
 else:
 return {}

 def get_performance_summary(self, hours_back: int = 1) -> Dict[str, Any]:
 """Get performance summary for specified time period"""
 cutoff_time = time.time() - (hours_back * 3600)

 with self._lock:
 # Get metrics from time period
 period_metrics = [
 metrics for metrics in self.metrics_history
 if metrics.timestamp >= cutoff_time
 ]

 period_resources = [
 resource for resource in self.resource_history
 if resource.timestamp >= cutoff_time
 ]

 if not period_metrics:
 return {'status': 'no_data'}

 # Calculate aggregated statistics
 response_times = [m.avg_response_time_ms for m in period_metrics]
 throughput_values = [m.throughput_rps for m in period_metrics]
 success_rates = [m.success_rate for m in period_metrics]

 cpu_usage = [r.cpu_percent for r in period_resources] if period_resources else [0]
 memory_usage = [r.memory_mb for r in period_resources] if period_resources else [0]
 gpu_usage = [r.gpu_percent for r in period_resources] if period_resources else [0]

 return {
 'time_period_hours': hours_back,
 'total_data_points': len(period_metrics),
 'response_time': {
 'avg_ms': statistics.mean(response_times),
 'min_ms': min(response_times),
 'max_ms': max(response_times),
 'p95_ms': statistics.mean([m.p95_response_time_ms for m in period_metrics]),
 'p99_ms': statistics.mean([m.p99_response_time_ms for m in period_metrics])
 },
 'throughput': {
 'avg_rps': statistics.mean(throughput_values),
 'max_rps': max(throughput_values),
 'total_requests': sum(m.throughput_rps * self.sample_interval for m in period_metrics)
 },
 'reliability': {
 'avg_success_rate': statistics.mean(success_rates),
 'min_success_rate': min(success_rates)
 },
 'resource_usage': {
 'avg_cpu_percent': statistics.mean(cpu_usage),
 'max_cpu_percent': max(cpu_usage),
 'avg_memory_mb': statistics.mean(memory_usage),
 'max_memory_mb': max(memory_usage),
 'avg_gpu_percent': statistics.mean(gpu_usage),
 'max_gpu_percent': max(gpu_usage)
 },
 'concurrency': {
 'avg_concurrent_requests': statistics.mean([m.concurrent_requests for m in period_metrics]),
 'max_concurrent_requests': max([m.concurrent_requests for m in period_metrics]),
 'avg_queue_depth': statistics.mean([m.queue_depth for m in period_metrics])
 }
 }

 def get_performance_trends(self, hours_back: int = 24) -> Dict[str, str]:
 """Analyze performance trends over time"""
 cutoff_time = time.time() - (hours_back * 3600)

 with self._lock:
 period_metrics = [
 metrics for metrics in self.metrics_history
 if metrics.timestamp >= cutoff_time
 ]

 if len(period_metrics) < 10:
 return {'status': 'insufficient_data'}

 # Split into first and second half for trend analysis
 mid_point = len(period_metrics) // 2
 first_half = period_metrics[:mid_point]
 second_half = period_metrics[mid_point:]

 trends = {}

 # Response time trend
 first_half_rt = statistics.mean([m.avg_response_time_ms for m in first_half])
 second_half_rt = statistics.mean([m.avg_response_time_ms for m in second_half])

 if second_half_rt > first_half_rt * 1.1:
 trends['response_time'] = 'degrading'
 elif second_half_rt < first_half_rt * 0.9:
 trends['response_time'] = 'improving'
 else:
 trends['response_time'] = 'stable'

 # Throughput trend
 first_half_tp = statistics.mean([m.throughput_rps for m in first_half])
 second_half_tp = statistics.mean([m.throughput_rps for m in second_half])

 if second_half_tp > first_half_tp * 1.1:
 trends['throughput'] = 'increasing'
 elif second_half_tp < first_half_tp * 0.9:
 trends['throughput'] = 'decreasing'
 else:
 trends['throughput'] = 'stable'

 # Success rate trend
 first_half_sr = statistics.mean([m.success_rate for m in first_half])
 second_half_sr = statistics.mean([m.success_rate for m in second_half])

 if second_half_sr > first_half_sr + 0.05:
 trends['success_rate'] = 'improving'
 elif second_half_sr < first_half_sr - 0.05:
 trends['success_rate'] = 'degrading'
 else:
 trends['success_rate'] = 'stable'

 return trends

 def get_capacity_recommendations(self) -> List[str]:
 """Generate capacity planning recommendations"""
 recommendations = []

 # Get recent performance data
 recent_summary = self.get_performance_summary(hours_back=1)

 if recent_summary.get('status') == 'no_data':
 return ["Insufficient data for recommendations"]

 resource_usage = recent_summary.get('resource_usage', {})
 response_time = recent_summary.get('response_time', {})
 concurrency = recent_summary.get('concurrency', {})

 # CPU recommendations
 avg_cpu = resource_usage.get('avg_cpu_percent', 0)
 max_cpu = resource_usage.get('max_cpu_percent', 0)

 if max_cpu > 90:
 recommendations.append("Critical: CPU usage exceeding 90%. Scale up immediately.")
 elif avg_cpu > 70:
 recommendations.append("Warning: High CPU usage. Consider scaling up resources.")

 # Memory recommendations
 avg_memory = resource_usage.get('avg_memory_mb', 0)
 max_memory = resource_usage.get('max_memory_mb', 0)

 if max_memory > 3584: # 3.5GB threshold
 recommendations.append("High memory usage detected. Monitor for memory leaks.")

 # Response time recommendations
 avg_rt = response_time.get('avg_ms', 0)
 p99_rt = response_time.get('p99_ms', 0)

 if p99_rt > 5000:
 recommendations.append("P99 response time exceeds 5s. Optimize model or scale infrastructure.")
 elif avg_rt > 1000:
 recommendations.append("Average response time high. Consider performance optimization.")

 # Concurrency recommendations
 max_concurrent = concurrency.get('max_concurrent_requests', 0)
 avg_queue_depth = concurrency.get('avg_queue_depth', 0)

 if max_concurrent > 80:
 recommendations.append("High concurrency detected. Consider horizontal scaling.")

 if avg_queue_depth > 10:
 recommendations.append("Request queuing detected. Scale up to reduce latency.")

 if not recommendations:
 recommendations.append("Performance metrics are within normal ranges.")

 return recommendations

 def shutdown(self):
 """Shutdown the performance monitor"""
 self.monitoring_active = False
 if hasattr(self, 'monitor_thread'):
 self.monitor_thread.join(timeout=5)

 self.logger.info("Performance Monitor shutdown complete")