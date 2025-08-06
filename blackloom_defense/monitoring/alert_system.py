"""
BlackLoom Defense - Alert System
Centralized alerting for DoS attacks, quality issues, and performance problems
"""

import time
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from collections import deque, defaultdict
from enum import Enum
import logging
import threading


class AlertLevel(Enum):
 """Alert severity levels"""
 INFO = "info"
 LOW = "low"
 MEDIUM = "medium"
 HIGH = "high"
 CRITICAL = "critical"


class AlertType(Enum):
 """Types of alerts"""
 DOS_ATTACK = "dos_attack"
 QUALITY_DEGRADATION = "quality_degradation"
 PERFORMANCE_ISSUE = "performance_issue"
 SECURITY_THREAT = "security_threat"
 SYSTEM_ERROR = "system_error"
 RESOURCE_EXHAUSTION = "resource_exhaustion"


@dataclass
class Alert:
 """Alert data structure"""
 alert_id: str
 timestamp: float
 alert_type: AlertType
 alert_level: AlertLevel
 title: str
 description: str
 source_component: str
 affected_models: List[str]
 metrics: Dict[str, Any]
 recommendations: List[str]
 metadata: Dict[str, Any]
 resolved: bool = False
 resolved_timestamp: Optional[float] = None
 acknowledgments: List[str] = None


@dataclass
class AlertRule:
 """Alert rule configuration"""
 rule_id: str
 name: str
 alert_type: AlertType
 condition: str
 threshold: float
 duration_seconds: int
 alert_level: AlertLevel
 enabled: bool
 cooldown_seconds: int = 300


class AlertSystem:
 """
 Centralized alert management system
 Handles alert generation, routing, and notifications
 """

 def __init__(self, config: Optional[Dict] = None):
 self.config = config or {}
 self.logger = logging.getLogger(__name__)

 # Alert storage
 self.active_alerts = {} # alert_id -> Alert
 self.alert_history = deque(maxlen=10000)
 self.suppressed_alerts = set()

 # Alert rules
 self.alert_rules = {}
 self._init_default_rules()

 # Notification configuration
 self.notification_config = self.config.get('notifications', {})
 self.notification_handlers = {}
 self._init_notification_handlers()

 # Rate limiting
 self.alert_counts = defaultdict(list) # alert_type -> [timestamps]
 self.rate_limits = self.config.get('rate_limits', {
 'max_alerts_per_hour': 100,
 'max_same_type_per_hour': 10
 })

 # Alert aggregation
 self.aggregation_window = self.config.get('aggregation_window', 300) # 5 minutes

 # Thread safety
 self._lock = threading.Lock()

 self.logger.info("Alert System initialized")

 def _init_default_rules(self):
 """Initialize default alert rules"""
 default_rules = [
 AlertRule(
 rule_id="dos_high_rps",
 name="High Request Rate DoS",
 alert_type=AlertType.DOS_ATTACK,
 condition="requests_per_second > threshold",
 threshold=100.0,
 duration_seconds=60,
 alert_level=AlertLevel.HIGH,
 enabled=True,
 cooldown_seconds=300
 ),
 AlertRule(
 rule_id="quality_low_coherence",
 name="Low Output Coherence",
 alert_type=AlertType.QUALITY_DEGRADATION,
 condition="coherence_score < threshold",
 threshold=0.7,
 duration_seconds=300,
 alert_level=AlertLevel.MEDIUM,
 enabled=True,
 cooldown_seconds=600
 ),
 AlertRule(
 rule_id="performance_high_latency",
 name="High Response Latency",
 alert_type=AlertType.PERFORMANCE_ISSUE,
 condition="avg_response_time_ms > threshold",
 threshold=5000.0,
 duration_seconds=180,
 alert_level=AlertLevel.HIGH,
 enabled=True,
 cooldown_seconds=300
 ),
 AlertRule(
 rule_id="resource_high_cpu",
 name="High CPU Usage",
 alert_type=AlertType.RESOURCE_EXHAUSTION,
 condition="cpu_usage_percent > threshold",
 threshold=85.0,
 duration_seconds=300,
 alert_level=AlertLevel.HIGH,
 enabled=True,
 cooldown_seconds=600
 ),
 AlertRule(
 rule_id="security_blocked_ips",
 name="Multiple Blocked IPs",
 alert_type=AlertType.SECURITY_THREAT,
 condition="blocked_ips_count > threshold",
 threshold=10.0,
 duration_seconds=900,
 alert_level=AlertLevel.CRITICAL,
 enabled=True,
 cooldown_seconds=1800
 )
 ]

 for rule in default_rules:
 self.alert_rules[rule.rule_id] = rule

 def _init_notification_handlers(self):
 """Initialize notification handlers"""

 # Email notifications
 if self.notification_config.get('email', {}).get('enabled', False):
 self.notification_handlers['email'] = self._send_email_notification

 # Webhook notifications
 if self.notification_config.get('webhook', {}).get('enabled', False):
 self.notification_handlers['webhook'] = self._send_webhook_notification

 # Slack notifications (placeholder)
 if self.notification_config.get('slack', {}).get('enabled', False):
 self.notification_handlers['slack'] = self._send_slack_notification

 # Console logging (always enabled)
 self.notification_handlers['console'] = self._log_alert

 def create_alert(self,
 alert_type: AlertType,
 alert_level: AlertLevel,
 title: str,
 description: str,
 source_component: str,
 affected_models: Optional[List[str]] = None,
 metrics: Optional[Dict[str, Any]] = None,
 recommendations: Optional[List[str]] = None,
 metadata: Optional[Dict[str, Any]] = None) -> str:
 """
 Create a new alert

 Args:
 alert_type: Type of alert
 alert_level: Severity level
 title: Alert title
 description: Detailed description
 source_component: Component that generated the alert
 affected_models: List of affected models
 metrics: Related metrics
 recommendations: Recommended actions
 metadata: Additional metadata

 Returns:
 Alert ID
 """
 with self._lock:
 current_time = time.time()
 alert_id = f"{alert_type.value}_{int(current_time)}_{hash(title) % 10000}"

 # Check rate limits
 if not self._check_rate_limits(alert_type, current_time):
 self.logger.warning(f"Alert rate limited: {alert_type.value}")
 return ""

 # Check for alert suppression
 if self._is_alert_suppressed(alert_type, title):
 self.logger.debug(f"Alert suppressed: {title}")
 return ""

 # Create alert
 alert = Alert(
 alert_id=alert_id,
 timestamp=current_time,
 alert_type=alert_type,
 alert_level=alert_level,
 title=title,
 description=description,
 source_component=source_component,
 affected_models=affected_models or [],
 metrics=metrics or {},
 recommendations=recommendations or [],
 metadata=metadata or {},
 acknowledgments=[]
 )

 # Store alert
 self.active_alerts[alert_id] = alert
 self.alert_history.append(alert)

 # Update rate limiting counters
 self.alert_counts[alert_type].append(current_time)

 # Send notifications
 self._process_notifications(alert)

 self.logger.info(f"Alert created: {alert_id} - {title}")
 return alert_id

 def _check_rate_limits(self, alert_type: AlertType, current_time: float) -> bool:
 """Check if alert creation should be rate limited"""

 # Clean old entries
 cutoff_time = current_time - 3600 # 1 hour

 # Check overall rate limit
 total_recent_alerts = sum(
 len([t for t in timestamps if t >= cutoff_time])
 for timestamps in self.alert_counts.values()
 )

 if total_recent_alerts >= self.rate_limits['max_alerts_per_hour']:
 return False

 # Check type-specific rate limit
 type_recent_alerts = len([
 t for t in self.alert_counts[alert_type]
 if t >= cutoff_time
 ])

 if type_recent_alerts >= self.rate_limits['max_same_type_per_hour']:
 return False

 return True

 def _is_alert_suppressed(self, alert_type: AlertType, title: str) -> bool:
 """Check if alert should be suppressed"""
 suppression_key = f"{alert_type.value}:{hash(title)}"
 return suppression_key in self.suppressed_alerts

 def _process_notifications(self, alert: Alert):
 """Process notifications for an alert"""

 # Determine notification channels based on alert level
 channels = []

 if alert.alert_level == AlertLevel.CRITICAL:
 channels.extend(['console', 'email', 'webhook', 'slack'])
 elif alert.alert_level == AlertLevel.HIGH:
 channels.extend(['console', 'email', 'webhook'])
 elif alert.alert_level == AlertLevel.MEDIUM:
 channels.extend(['console', 'webhook'])
 else:
 channels.append('console')

 # Send notifications
 for channel in channels:
 handler = self.notification_handlers.get(channel)
 if handler:
 try:
 handler(alert)
 except Exception as e:
 self.logger.error(f"Failed to send {channel} notification: {e}")

 def _log_alert(self, alert: Alert):
 """Log alert to console"""
 level_colors = {
 AlertLevel.INFO: '',
 AlertLevel.LOW: '\033[94m', # Blue
 AlertLevel.MEDIUM: '\033[93m', # Yellow
 AlertLevel.HIGH: '\033[91m', # Red
 AlertLevel.CRITICAL: '\033[95m' # Magenta
 }

 reset_color = '\033[0m'
 color = level_colors.get(alert.alert_level, '')

 self.logger.warning(
 f"{color} ALERT [{alert.alert_level.value.upper()}] "
 f"{alert.title} | {alert.description}{reset_color}"
 )

 def _send_email_notification(self, alert: Alert):
 """Send email notification"""
 email_config = self.notification_config.get('email', {})

 if not email_config.get('smtp_server'):
 return

 try:
 # Create message
 msg = MIMEMultipart()
 msg['From'] = email_config.get('from_address', 'alerts@blackloom.ai')
 msg['To'] = ', '.join(email_config.get('to_addresses', []))
 msg['Subject'] = f"BlackLoom Alert [{alert.alert_level.value.upper()}]: {alert.title}"

 # Create email body
 body = f"""
BlackLoom Defense Alert

Alert ID: {alert.alert_id}
Type: {alert.alert_type.value}
Level: {alert.alert_level.value}
Source: {alert.source_component}
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(alert.timestamp))}

Description:
{alert.description}

Affected Models:
{', '.join(alert.affected_models) if alert.affected_models else 'None'}

Recommendations:
{chr(10).join('• ' + rec for rec in alert.recommendations)}

Metrics:
{json.dumps(alert.metrics, indent=2)}
"""

 msg.attach(MIMEText(body, 'plain'))

 # Send email
 server = smtplib.SMTP(email_config['smtp_server'], email_config.get('smtp_port', 587))
 server.starttls()

 if email_config.get('username'):
 server.login(email_config['username'], email_config['password'])

 server.send_message(msg)
 server.quit()

 except Exception as e:
 self.logger.error(f"Failed to send email alert: {e}")

 def _send_webhook_notification(self, alert: Alert):
 """Send webhook notification"""
 webhook_config = self.notification_config.get('webhook', {})

 if not webhook_config.get('url'):
 return

 try:
 import requests

 payload = {
 'alert_id': alert.alert_id,
 'timestamp': alert.timestamp,
 'alert_type': alert.alert_type.value,
 'alert_level': alert.alert_level.value,
 'title': alert.title,
 'description': alert.description,
 'source_component': alert.source_component,
 'affected_models': alert.affected_models,
 'metrics': alert.metrics,
 'recommendations': alert.recommendations,
 'metadata': alert.metadata
 }

 headers = {
 'Content-Type': 'application/json',
 'User-Agent': 'BlackLoom-Defense-Alerts/1.0'
 }

 # Add authentication headers if configured
 if webhook_config.get('auth_token'):
 headers['Authorization'] = f"Bearer {webhook_config['auth_token']}"

 response = requests.post(
 webhook_config['url'],
 json=payload,
 headers=headers,
 timeout=10
 )

 response.raise_for_status()

 except Exception as e:
 self.logger.error(f"Failed to send webhook alert: {e}")

 def _send_slack_notification(self, alert: Alert):
 """Send Slack notification (placeholder implementation)"""
 slack_config = self.notification_config.get('slack', {})

 if not slack_config.get('webhook_url'):
 return

 try:
 import requests

 color_map = {
 AlertLevel.INFO: '#36a64f', # Green
 AlertLevel.LOW: '#ffeb3b', # Yellow
 AlertLevel.MEDIUM: '#ff9800', # Orange
 AlertLevel.HIGH: '#f44336', # Red
 AlertLevel.CRITICAL: '#9c27b0' # Purple
 }

 payload = {
 'attachments': [{
 'color': color_map.get(alert.alert_level, '#808080'),
 'title': f"BlackLoom Alert: {alert.title}",
 'text': alert.description,
 'fields': [
 {'title': 'Alert Level', 'value': alert.alert_level.value, 'short': True},
 {'title': 'Type', 'value': alert.alert_type.value, 'short': True},
 {'title': 'Source', 'value': alert.source_component, 'short': True},
 {'title': 'Models', 'value': ', '.join(alert.affected_models), 'short': True}
 ],
 'footer': 'BlackLoom Defense',
 'ts': int(alert.timestamp)
 }]
 }

 response = requests.post(slack_config['webhook_url'], json=payload, timeout=10)
 response.raise_for_status()

 except Exception as e:
 self.logger.error(f"Failed to send Slack alert: {e}")

 def acknowledge_alert(self, alert_id: str, acknowledged_by: str, note: str = "") -> bool:
 """Acknowledge an alert"""
 with self._lock:
 if alert_id in self.active_alerts:
 alert = self.active_alerts[alert_id]

 acknowledgment = {
 'acknowledged_by': acknowledged_by,
 'timestamp': time.time(),
 'note': note
 }

 if not alert.acknowledgments:
 alert.acknowledgments = []

 alert.acknowledgments.append(acknowledgment)

 self.logger.info(f"Alert acknowledged: {alert_id} by {acknowledged_by}")
 return True

 return False

 def resolve_alert(self, alert_id: str, resolved_by: str, resolution_note: str = "") -> bool:
 """Resolve an alert"""
 with self._lock:
 if alert_id in self.active_alerts:
 alert = self.active_alerts[alert_id]
 alert.resolved = True
 alert.resolved_timestamp = time.time()

 # Add resolution metadata
 alert.metadata['resolution'] = {
 'resolved_by': resolved_by,
 'timestamp': alert.resolved_timestamp,
 'note': resolution_note
 }

 # Remove from active alerts
 del self.active_alerts[alert_id]

 self.logger.info(f"Alert resolved: {alert_id} by {resolved_by}")
 return True

 return False

 def suppress_alert_type(self, alert_type: AlertType, title_pattern: str, duration_minutes: int = 60):
 """Temporarily suppress alerts of a specific type"""
 suppression_key = f"{alert_type.value}:{hash(title_pattern)}"
 self.suppressed_alerts.add(suppression_key)

 # Auto-remove suppression after duration
 def remove_suppression():
 time.sleep(duration_minutes * 60)
 self.suppressed_alerts.discard(suppression_key)

 threading.Thread(target=remove_suppression, daemon=True).start()

 self.logger.info(f"Alert suppression added: {alert_type.value} for {duration_minutes} minutes")

 def get_active_alerts(self,
 alert_type: Optional[AlertType] = None,
 alert_level: Optional[AlertLevel] = None) -> List[Alert]:
 """Get currently active alerts"""
 with self._lock:
 alerts = list(self.active_alerts.values())

 # Filter by type
 if alert_type:
 alerts = [alert for alert in alerts if alert.alert_type == alert_type]

 # Filter by level
 if alert_level:
 alerts = [alert for alert in alerts if alert.alert_level == alert_level]

 # Sort by timestamp (newest first)
 alerts.sort(key=lambda x: x.timestamp, reverse=True)

 return alerts

 def get_alert_history(self,
 hours_back: int = 24,
 alert_type: Optional[AlertType] = None,
 alert_level: Optional[AlertLevel] = None) -> List[Alert]:
 """Get alert history for specified time period"""
 cutoff_time = time.time() - (hours_back * 3600)

 with self._lock:
 alerts = [
 alert for alert in self.alert_history
 if alert.timestamp >= cutoff_time
 ]

 # Apply filters
 if alert_type:
 alerts = [alert for alert in alerts if alert.alert_type == alert_type]

 if alert_level:
 alerts = [alert for alert in alerts if alert.alert_level == alert_level]

 return alerts

 def get_alert_statistics(self, hours_back: int = 24) -> Dict[str, Any]:
 """Get alert statistics for specified time period"""
 alerts = self.get_alert_history(hours_back)

 if not alerts:
 return {'status': 'no_alerts'}

 # Count by type
 type_counts = defaultdict(int)
 level_counts = defaultdict(int)
 hourly_counts = defaultdict(int)

 for alert in alerts:
 type_counts[alert.alert_type.value] += 1
 level_counts[alert.alert_level.value] += 1

 # Hour bucket for trending
 hour_bucket = int(alert.timestamp // 3600) * 3600
 hourly_counts[hour_bucket] += 1

 # Calculate resolution stats
 resolved_alerts = [alert for alert in alerts if alert.resolved]
 resolution_rate = len(resolved_alerts) / len(alerts) if alerts else 0

 # Average resolution time
 resolution_times = [
 (alert.resolved_timestamp - alert.timestamp) / 60 # minutes
 for alert in resolved_alerts
 if alert.resolved_timestamp
 ]

 avg_resolution_time = (
 sum(resolution_times) / len(resolution_times)
 if resolution_times else 0
 )

 return {
 'time_period_hours': hours_back,
 'total_alerts': len(alerts),
 'active_alerts': len(self.active_alerts),
 'resolved_alerts': len(resolved_alerts),
 'resolution_rate': resolution_rate,
 'avg_resolution_time_minutes': avg_resolution_time,
 'alerts_by_type': dict(type_counts),
 'alerts_by_level': dict(level_counts),
 'hourly_distribution': dict(hourly_counts)
 }

 def create_alert_rule(self, rule: AlertRule) -> bool:
 """Create a new alert rule"""
 with self._lock:
 self.alert_rules[rule.rule_id] = rule
 self.logger.info(f"Alert rule created: {rule.rule_id}")
 return True

 def update_alert_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
 """Update an existing alert rule"""
 with self._lock:
 if rule_id in self.alert_rules:
 rule = self.alert_rules[rule_id]

 for key, value in updates.items():
 if hasattr(rule, key):
 setattr(rule, key, value)

 self.logger.info(f"Alert rule updated: {rule_id}")
 return True

 return False

 def get_health_summary(self) -> Dict[str, Any]:
 """Get overall alert system health summary"""
 with self._lock:
 active_count = len(self.active_alerts)
 critical_count = len([
 alert for alert in self.active_alerts.values()
 if alert.alert_level == AlertLevel.CRITICAL
 ])
 high_count = len([
 alert for alert in self.active_alerts.values()
 if alert.alert_level == AlertLevel.HIGH
 ])

 # Determine overall health status
 if critical_count > 0:
 health_status = "critical"
 elif high_count > 3:
 health_status = "degraded"
 elif active_count > 10:
 health_status = "warning"
 else:
 health_status = "healthy"

 return {
 'health_status': health_status,
 'active_alerts': active_count,
 'critical_alerts': critical_count,
 'high_alerts': high_count,
 'notification_handlers': list(self.notification_handlers.keys()),
 'alert_rules_count': len(self.alert_rules),
 'suppressed_patterns': len(self.suppressed_alerts)
 }