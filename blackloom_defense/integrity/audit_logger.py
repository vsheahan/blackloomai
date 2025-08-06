"""
BlackLoom Defense - Model Access Audit Logger
Tracks all model access patterns for theft detection and compliance
"""

import json
import datetime
import hashlib
import os
import sqlite3
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import threading
from contextlib import contextmanager


class AccessType(Enum):
 """Types of model access events"""
 QUERY = "query"
 DOWNLOAD = "download"
 UPLOAD = "upload"
 INFERENCE = "inference"
 ADMIN = "admin"
 VERIFICATION = "verification"


class RiskLevel(Enum):
 """Risk levels for access events"""
 LOW = "low"
 MEDIUM = "medium"
 HIGH = "high"
 CRITICAL = "critical"


@dataclass
class AccessEvent:
 """Represents a model access event"""
 timestamp: str
 event_id: str
 access_type: AccessType
 model_name: str
 model_version: str
 user_id: str
 client_ip: str
 user_agent: str
 request_size: int
 response_size: int
 duration_ms: float
 risk_level: RiskLevel
 details: Dict[str, Any]
 session_id: Optional[str] = None
 threat_indicators: Optional[List[str]] = None
 geo_location: Optional[str] = None


@dataclass
class SuspiciousPattern:
 """Represents a detected suspicious access pattern"""
 pattern_id: str
 pattern_type: str
 description: str
 first_seen: str
 last_seen: str
 event_count: int
 risk_score: float
 affected_models: List[str]
 user_ids: List[str]
 ip_addresses: List[str]
 indicators: List[str]


class AuditLogger:
 """
 Comprehensive audit logging system for AI model access
 Tracks access patterns, detects suspicious behavior, and maintains compliance logs
 """

 def __init__(self, db_path: str = "blackloom_audit.db", config: Optional[Dict] = None):
 self.db_path = db_path
 self.config = config or {}
 self.logger = logging.getLogger(__name__)
 self._lock = threading.Lock()

 # Risk scoring thresholds
 self.risk_thresholds = self.config.get('risk_thresholds', {
 'query_rate_per_minute': 100,
 'download_size_mb': 1000,
 'failed_attempts_threshold': 5,
 'unique_ips_threshold': 10
 })

 # Initialize database
 self._init_database()

 def _init_database(self):
 """Initialize SQLite database for audit logging"""
 with sqlite3.connect(self.db_path) as conn:
 cursor = conn.cursor()

 # Create access_events table
 cursor.execute('''
 CREATE TABLE IF NOT EXISTS access_events (
 event_id TEXT PRIMARY KEY,
 timestamp TEXT NOT NULL,
 access_type TEXT NOT NULL,
 model_name TEXT NOT NULL,
 model_version TEXT NOT NULL,
 user_id TEXT NOT NULL,
 client_ip TEXT NOT NULL,
 user_agent TEXT,
 request_size INTEGER,
 response_size INTEGER,
 duration_ms REAL,
 risk_level TEXT NOT NULL,
 session_id TEXT,
 threat_indicators TEXT,
 geo_location TEXT,
 details TEXT NOT NULL
 )
 ''')

 # Create suspicious_patterns table
 cursor.execute('''
 CREATE TABLE IF NOT EXISTS suspicious_patterns (
 pattern_id TEXT PRIMARY KEY,
 pattern_type TEXT NOT NULL,
 description TEXT NOT NULL,
 first_seen TEXT NOT NULL,
 last_seen TEXT NOT NULL,
 event_count INTEGER NOT NULL,
 risk_score REAL NOT NULL,
 affected_models TEXT NOT NULL,
 user_ids TEXT NOT NULL,
 ip_addresses TEXT NOT NULL,
 indicators TEXT NOT NULL
 )
 ''')

 # Create indexes for performance
 cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON access_events(timestamp)')
 cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_id ON access_events(user_id)')
 cursor.execute('CREATE INDEX IF NOT EXISTS idx_client_ip ON access_events(client_ip)')
 cursor.execute('CREATE INDEX IF NOT EXISTS idx_model_name ON access_events(model_name)')
 cursor.execute('CREATE INDEX IF NOT EXISTS idx_risk_level ON access_events(risk_level)')

 conn.commit()

 @contextmanager
 def _get_db_connection(self):
 """Thread-safe database connection context manager"""
 with self._lock:
 conn = sqlite3.connect(self.db_path)
 try:
 yield conn
 finally:
 conn.close()

 def _generate_event_id(self, access_event: Dict[str, Any]) -> str:
 """Generate unique event ID based on event details"""
 event_str = f"{access_event['timestamp']}{access_event['user_id']}{access_event['model_name']}"
 return hashlib.sha256(event_str.encode()).hexdigest()[:16]

 def _calculate_risk_level(self, access_event: Dict[str, Any]) -> RiskLevel:
 """Calculate risk level based on access patterns and indicators"""
 risk_score = 0.0

 # Check request/response size
 if access_event.get('request_size', 0) > self.risk_thresholds['download_size_mb'] * 1024 * 1024:
 risk_score += 0.3

 if access_event.get('response_size', 0) > self.risk_thresholds['download_size_mb'] * 1024 * 1024:
 risk_score += 0.4

 # Check for threat indicators
 threat_indicators = access_event.get('threat_indicators', [])
 if threat_indicators:
 risk_score += len(threat_indicators) * 0.2

 # Check access type
 if access_event.get('access_type') == AccessType.DOWNLOAD:
 risk_score += 0.2
 elif access_event.get('access_type') == AccessType.ADMIN:
 risk_score += 0.1

 # Check unusual patterns
 if access_event.get('unusual_pattern', False):
 risk_score += 0.3

 # Convert to risk level
 if risk_score >= 0.8:
 return RiskLevel.CRITICAL
 elif risk_score >= 0.6:
 return RiskLevel.HIGH
 elif risk_score >= 0.3:
 return RiskLevel.MEDIUM
 else:
 return RiskLevel.LOW

 def log_access(self,
 access_type: AccessType,
 model_name: str,
 model_version: str,
 user_id: str,
 client_ip: str,
 user_agent: str = "",
 request_size: int = 0,
 response_size: int = 0,
 duration_ms: float = 0.0,
 session_id: Optional[str] = None,
 details: Optional[Dict[str, Any]] = None,
 threat_indicators: Optional[List[str]] = None,
 geo_location: Optional[str] = None) -> str:
 """
 Log a model access event

 Args:
 access_type: Type of access (query, download, etc.)
 model_name: Name of the accessed model
 model_version: Version of the accessed model
 user_id: ID of the user making the request
 client_ip: Client IP address
 user_agent: User agent string
 request_size: Size of request in bytes
 response_size: Size of response in bytes
 duration_ms: Request duration in milliseconds
 session_id: Session identifier
 details: Additional event details
 threat_indicators: List of detected threat indicators
 geo_location: Geographic location of the client

 Returns:
 Event ID of the logged event
 """
 timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

 # Prepare event data
 event_data = {
 'timestamp': timestamp,
 'access_type': access_type,
 'model_name': model_name,
 'model_version': model_version,
 'user_id': user_id,
 'client_ip': client_ip,
 'user_agent': user_agent,
 'request_size': request_size,
 'response_size': response_size,
 'duration_ms': duration_ms,
 'session_id': session_id,
 'threat_indicators': threat_indicators or [],
 'geo_location': geo_location,
 'details': details or {}
 }

 event_id = self._generate_event_id(event_data)
 risk_level = self._calculate_risk_level(event_data)

 # Create access event
 access_event = AccessEvent(
 timestamp=timestamp,
 event_id=event_id,
 access_type=access_type,
 model_name=model_name,
 model_version=model_version,
 user_id=user_id,
 client_ip=client_ip,
 user_agent=user_agent,
 request_size=request_size,
 response_size=response_size,
 duration_ms=duration_ms,
 risk_level=risk_level,
 session_id=session_id,
 threat_indicators=threat_indicators,
 geo_location=geo_location,
 details=details or {}
 )

 # Store in database
 try:
 with self._get_db_connection() as conn:
 cursor = conn.cursor()
 cursor.execute('''
 INSERT INTO access_events (
 event_id, timestamp, access_type, model_name, model_version,
 user_id, client_ip, user_agent, request_size, response_size,
 duration_ms, risk_level, session_id, threat_indicators,
 geo_location, details
 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
 ''', (
 event_id, timestamp, access_type.value, model_name, model_version,
 user_id, client_ip, user_agent, request_size, response_size,
 duration_ms, risk_level.value, session_id,
 json.dumps(threat_indicators) if threat_indicators else None,
 geo_location, json.dumps(details or {})
 ))
 conn.commit()

 # Check for suspicious patterns after logging
 if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
 self._analyze_suspicious_patterns(access_event)

 self.logger.info(f"Access logged: {event_id} ({risk_level.value})")
 return event_id

 except Exception as e:
 self.logger.error(f"Failed to log access event: {e}")
 raise

 def _analyze_suspicious_patterns(self, access_event: AccessEvent):
 """Analyze recent events for suspicious patterns"""
 patterns_detected = []

 # Pattern 1: High frequency access from same IP
 recent_events = self.get_recent_events(
 hours=1,
 filters={'client_ip': access_event.client_ip}
 )

 if len(recent_events) > self.risk_thresholds['query_rate_per_minute']:
 patterns_detected.append({
 'type': 'high_frequency_access',
 'description': f'High frequency access from IP {access_event.client_ip}',
 'risk_score': 0.8,
 'indicators': ['rapid_requests', 'potential_scraping']
 })

 # Pattern 2: Access to multiple models by same user
 user_models = self.get_user_model_access(access_event.user_id, hours=24)
 if len(user_models) > 5:
 patterns_detected.append({
 'type': 'multi_model_access',
 'description': f'User {access_event.user_id} accessed {len(user_models)} models in 24h',
 'risk_score': 0.6,
 'indicators': ['model_enumeration', 'potential_theft']
 })

 # Pattern 3: Large download volumes
 if access_event.response_size > self.risk_thresholds['download_size_mb'] * 1024 * 1024:
 patterns_detected.append({
 'type': 'large_download',
 'description': f'Large download: {access_event.response_size / (1024*1024):.1f}MB',
 'risk_score': 0.7,
 'indicators': ['model_extraction', 'potential_theft']
 })

 # Store detected patterns
 for pattern in patterns_detected:
 self._store_suspicious_pattern(pattern, access_event)

 def _store_suspicious_pattern(self, pattern_data: Dict[str, Any], access_event: AccessEvent):
 """Store a detected suspicious pattern"""
 pattern_id = hashlib.sha256(
 f"{pattern_data['type']}{access_event.user_id}{access_event.client_ip}".encode()
 ).hexdigest()[:16]

 timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

 try:
 with self._get_db_connection() as conn:
 cursor = conn.cursor()

 # Check if pattern already exists
 cursor.execute(
 'SELECT event_count FROM suspicious_patterns WHERE pattern_id = ?',
 (pattern_id,)
 )
 result = cursor.fetchone()

 if result:
 # Update existing pattern
 cursor.execute('''
 UPDATE suspicious_patterns
 SET last_seen = ?, event_count = event_count + 1
 WHERE pattern_id = ?
 ''', (timestamp, pattern_id))
 else:
 # Create new pattern
 suspicious_pattern = SuspiciousPattern(
 pattern_id=pattern_id,
 pattern_type=pattern_data['type'],
 description=pattern_data['description'],
 first_seen=timestamp,
 last_seen=timestamp,
 event_count=1,
 risk_score=pattern_data['risk_score'],
 affected_models=[f"{access_event.model_name}:{access_event.model_version}"],
 user_ids=[access_event.user_id],
 ip_addresses=[access_event.client_ip],
 indicators=pattern_data['indicators']
 )

 cursor.execute('''
 INSERT INTO suspicious_patterns (
 pattern_id, pattern_type, description, first_seen, last_seen,
 event_count, risk_score, affected_models, user_ids,
 ip_addresses, indicators
 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
 ''', (
 pattern_id, suspicious_pattern.pattern_type,
 suspicious_pattern.description, suspicious_pattern.first_seen,
 suspicious_pattern.last_seen, suspicious_pattern.event_count,
 suspicious_pattern.risk_score,
 json.dumps(suspicious_pattern.affected_models),
 json.dumps(suspicious_pattern.user_ids),
 json.dumps(suspicious_pattern.ip_addresses),
 json.dumps(suspicious_pattern.indicators)
 ))

 conn.commit()

 except Exception as e:
 self.logger.error(f"Failed to store suspicious pattern: {e}")

 def get_recent_events(self,
 hours: int = 24,
 filters: Optional[Dict[str, str]] = None,
 limit: int = 1000) -> List[Dict[str, Any]]:
 """
 Get recent access events with optional filters

 Args:
 hours: Number of hours back to search
 filters: Optional filters (user_id, client_ip, model_name, etc.)
 limit: Maximum number of events to return

 Returns:
 List of access events
 """
 since_time = (
 datetime.datetime.now(datetime.timezone.utc) -
 datetime.timedelta(hours=hours)
 ).isoformat()

 query = "SELECT * FROM access_events WHERE timestamp >= ?"
 params = [since_time]

 if filters:
 for key, value in filters.items():
 query += f" AND {key} = ?"
 params.append(value)

 query += " ORDER BY timestamp DESC LIMIT ?"
 params.append(limit)

 try:
 with self._get_db_connection() as conn:
 cursor = conn.cursor()
 cursor.execute(query, params)

 columns = [desc[0] for desc in cursor.description]
 events = []

 for row in cursor.fetchall():
 event = dict(zip(columns, row))
 # Parse JSON fields
 if event['threat_indicators']:
 event['threat_indicators'] = json.loads(event['threat_indicators'])
 if event['details']:
 event['details'] = json.loads(event['details'])
 events.append(event)

 return events

 except Exception as e:
 self.logger.error(f"Failed to get recent events: {e}")
 return []

 def get_user_model_access(self, user_id: str, hours: int = 24) -> List[str]:
 """Get list of models accessed by a user in the specified time period"""
 recent_events = self.get_recent_events(hours, {'user_id': user_id})
 models = set()

 for event in recent_events:
 models.add(f"{event['model_name']}:{event['model_version']}")

 return list(models)

 def get_suspicious_patterns(self,
 hours: int = 24,
 min_risk_score: float = 0.5) -> List[SuspiciousPattern]:
 """Get suspicious patterns detected in the specified time period"""
 since_time = (
 datetime.datetime.now(datetime.timezone.utc) -
 datetime.timedelta(hours=hours)
 ).isoformat()

 try:
 with self._get_db_connection() as conn:
 cursor = conn.cursor()
 cursor.execute('''
 SELECT * FROM suspicious_patterns
 WHERE last_seen >= ? AND risk_score >= ?
 ORDER BY risk_score DESC, last_seen DESC
 ''', (since_time, min_risk_score))

 patterns = []
 for row in cursor.fetchall():
 pattern = SuspiciousPattern(
 pattern_id=row[0],
 pattern_type=row[1],
 description=row[2],
 first_seen=row[3],
 last_seen=row[4],
 event_count=row[5],
 risk_score=row[6],
 affected_models=json.loads(row[7]),
 user_ids=json.loads(row[8]),
 ip_addresses=json.loads(row[9]),
 indicators=json.loads(row[10])
 )
 patterns.append(pattern)

 return patterns

 except Exception as e:
 self.logger.error(f"Failed to get suspicious patterns: {e}")
 return []

 def generate_compliance_report(self,
 start_date: str,
 end_date: str,
 model_name: Optional[str] = None) -> Dict[str, Any]:
 """
 Generate a compliance report for the specified date range

 Args:
 start_date: Start date in ISO format
 end_date: End date in ISO format
 model_name: Optional model name filter

 Returns:
 Compliance report dictionary
 """
 query = "SELECT * FROM access_events WHERE timestamp BETWEEN ? AND ?"
 params = [start_date, end_date]

 if model_name:
 query += " AND model_name = ?"
 params.append(model_name)

 try:
 with self._get_db_connection() as conn:
 cursor = conn.cursor()
 cursor.execute(query, params)
 events = cursor.fetchall()

 # Generate statistics
 total_access = len(events)
 unique_users = len(set(event[5] for event in events)) # user_id column
 unique_ips = len(set(event[6] for event in events)) # client_ip column

 access_types = {}
 risk_levels = {}

 for event in events:
 access_type = event[2] # access_type column
 risk_level = event[11] # risk_level column

 access_types[access_type] = access_types.get(access_type, 0) + 1
 risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1

 # Get suspicious patterns in date range
 patterns_query = "SELECT * FROM suspicious_patterns WHERE first_seen BETWEEN ? AND ?"
 cursor.execute(patterns_query, [start_date, end_date])
 suspicious_patterns = len(cursor.fetchall())

 report = {
 "report_generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
 "period": {
 "start_date": start_date,
 "end_date": end_date
 },
 "model_filter": model_name,
 "statistics": {
 "total_access_events": total_access,
 "unique_users": unique_users,
 "unique_ip_addresses": unique_ips,
 "suspicious_patterns_detected": suspicious_patterns
 },
 "access_breakdown": {
 "by_type": access_types,
 "by_risk_level": risk_levels
 },
 "compliance_status": {
 "high_risk_events": risk_levels.get('high', 0) + risk_levels.get('critical', 0),
 "audit_trail_complete": True,
 "suspicious_activity_monitored": True
 }
 }

 return report

 except Exception as e:
 self.logger.error(f"Failed to generate compliance report: {e}")
 return {"error": str(e)}