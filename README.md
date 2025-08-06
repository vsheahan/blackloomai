# BlackLoom Defense

<p align="center">
  <img src="assets/blackloomai-logo.png" alt="BlackLoom AI Logo" width="600"/>
</p>

**Comprehensive AI Security Platform - Complete protection for AI models in production**

BlackLoom AI is an POC security platform designed to protect AI models from the complete spectrum of security threats outlined in the OWASP Machine Learning Security Top 10. It provides real-time defense, model integrity verification, and continuous post-deployment monitoring through advanced detection algorithms and automated mitigation strategies.

## Core Security Components

### 1. Real-Time Input/Output Defense
- **Prompt Injection Detection**: Advanced pattern matching detecting sophisticated injection attacks
- **Input Sanitization**: Intelligent sanitization preserving legitimate content while neutralizing threats
- **Output Integrity Monitoring**: Real-time analysis detecting compromised AI model responses
- **Adversarial Pattern Detection**: Detection of token stuffing, encoding attacks, and manipulation techniques

### 2. Model Integrity & Auditing
- **Cryptographic Verification**: RSA-2048 digital signatures with SHA-256 hashing for model authenticity
- **Tamper Detection**: File-level integrity monitoring with comprehensive verification reports
- **Access Auditing**: Complete audit trails of all model interactions and access patterns
- **Compliance Reporting**: Automated regulatory compliance reports and suspicious pattern detection

### 3. Post-Deployment Monitoring
- **DoS Attack Detection**: Real-time detection of Model Denial of Service attacks with automatic mitigation
- **Performance Monitoring**: Continuous tracking of response times, throughput, and resource utilization
- **Quality Degradation Detection**: Monitoring for output quality issues preventing overreliance
- **Centralized Alerting**: Multi-channel alert system with email, webhook, and Slack notifications

## OWASP ML Security Coverage

BlackLoom Defense provides comprehensive protection against OWASP ML Security Top 10 risks:

| Risk | Component | Protection |
|------|-----------|------------|
| **ML01** - Input Manipulation | Defense Engine | Real-time input validation and sanitization |
| **ML04** - Model DoS | DoS Monitor | Request flooding and resource exhaustion detection |
| **ML05** - Model Theft | Integrity System | Access auditing and suspicious pattern detection |
| **ML09** - Overreliance | Quality Monitor | Output quality degradation and confidence tracking |
| **ML10** - Model Poisoning | Integrity System | Cryptographic verification and tamper detection |

## Quick Start

### Installation

```bash
git clone <repository-url>
cd blackloom
pip install -r requirements.txt
```

### Running the Platform

```bash
# Start the complete BlackLoom Defense platform
python -m blackloom_defense.api.gateway

# The API will be available at http://localhost:8000
```

### Running Demos

```bash
# Comprehensive monitoring system demo
python demo_monitoring.py

# Interactive testing mode
python demo_monitoring.py --interactive

# Original defense system demo
python demo_blackloom.py
```

## Architecture

BlackLoom Defense follows a comprehensive modular architecture:

```
blackloom_defense/
├── core/ # Real-time Defense Engine
│ ├── defense_engine.py # Main orchestration layer
│ ├── prompt_injection_detector.py # Advanced injection detection
│ ├── input_sanitizer.py # Intelligent input sanitization
│ └── output_monitor.py # Output integrity monitoring
├── integrity/ # Model Integrity & Auditing
│ ├── model_integrity.py # Central integrity manager
│ ├── crypto/ # Cryptographic operations
│ ├── verification/ # Model verification system
│ └── audit_logger.py # Access auditing and logging
├── monitoring/ # Post-Deployment Monitoring
│ ├── monitoring_manager.py # Central monitoring orchestrator
│ ├── dos_monitor.py # DoS attack detection
│ ├── performance_monitor.py # Performance tracking
│ ├── quality_monitor.py # Quality degradation detection
│ └── alert_system.py # Centralized alerting
├── api/
│ └── gateway.py # Comprehensive REST API
└── tests/
 └── comprehensive test suites # Full attack scenario coverage
```

## API Endpoints

### Core Defense
- `GET /health` - System health check
- `POST /analyze` - Analyze input for security threats
- `POST /proxy` - Secure proxy with complete protection pipeline
- `GET /stats` - Defense system statistics and trends

### Model Integrity & Auditing
- `POST /integrity/register` - Register model for integrity monitoring
- `GET /integrity/models` - List all registered models with status
- `POST /integrity/verify/{model_id}` - Verify model integrity
- `POST /integrity/report` - Generate comprehensive integrity report
- `GET /integrity/compliance` - Generate compliance reports
- `GET /integrity/audit/patterns` - Get suspicious access patterns

### Post-Deployment Monitoring
- `GET /monitoring/health` - Overall monitoring system health
- `GET /monitoring/alerts` - Recent alerts from all monitoring systems
- `GET /monitoring/performance` - Current performance metrics and analysis
- `GET /monitoring/quality` - Model output quality analysis
- `GET /monitoring/dos` - DoS monitoring status and attack patterns
- `GET /monitoring/statistics` - Comprehensive monitoring statistics
- `POST /monitoring/alerts/{alert_id}/acknowledge` - Acknowledge specific alert
- `POST /monitoring/alerts/{alert_id}/resolve` - Resolve specific alert

### Testing & Research
- `POST /test-attack` - Test specific attack scenarios (authorized researchers)

## Configuration

### Defense Engine Configuration

```python
from blackloom_defense.core import DefenseEngine

config = {
 'threat_thresholds': {
 'block_threshold': 0.7, # Block requests above this confidence
 'warn_threshold': 0.5, # Log warnings above this threshold
 'sanitize_threshold': 0.3 # Sanitize inputs above this threshold
 },
 'prompt_detection': {
 'weights': {
 'direct_injection': 0.9,
 'role_manipulation': 0.8,
 'system_prompt_leak': 0.9,
 'jailbreak_attempt': 0.7
 }
 }
}

defense = DefenseEngine(config)
```

### Monitoring System Configuration

```python
from blackloom_defense.monitoring import MonitoringManager

monitoring_config = {
 'dos_monitor': {
 'dos_thresholds': {
 'max_rps': 100,
 'max_response_time_ms': 5000,
 'max_concurrent_requests': 50
 }
 },
 'quality_monitor': {
 'quality_thresholds': {
 'min_coherence_score': 0.7,
 'max_repetition_rate': 0.3,
 'min_confidence_score': 0.6
 }
 },
 'alert_system': {
 'notifications': {
 'email': {
 'enabled': True,
 'smtp_server': 'smtp.company.com',
 'to_addresses': ['security@company.com']
 },
 'webhook': {
 'enabled': True,
 'url': 'https://alerts.company.com/webhook'
 }
 }
 }
}

monitoring = MonitoringManager(monitoring_config)
```

## Security Features

### Advanced Threat Detection
- **Multi-Layer Analysis**: Pattern matching, statistical analysis, and heuristic detection
- **Context Awareness**: Risk assessment based on request patterns and user behavior
- **Encoding Detection**: Base64, URL encoding, Unicode, and other obfuscation methods
- **Language-Agnostic**: Detection across multiple languages and character sets

### Cryptographic Security
- **Digital Signatures**: RSA-2048 signatures for model authenticity verification
- **Hash Verification**: SHA-256 integrity checking for all model files
- **Key Management**: Secure key generation, storage, and rotation
- **Certificate Chain**: Full certificate chain validation for model provenance

### Real-Time Monitoring
- **DoS Protection**: Automatic detection and mitigation of denial of service attacks
- **Performance Tracking**: Real-time metrics with capacity planning recommendations
- **Quality Assurance**: Continuous monitoring for output quality degradation
- **Automated Alerts**: Multi-channel alerting with escalation policies

## Testing & Validation

### Comprehensive Test Coverage

```bash
# Run all test suites
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/test_prompt_injection.py -v
python -m pytest tests/test_integrity_system.py -v
python -m pytest tests/test_monitoring_system.py -v
```

### Attack Scenarios Covered
- **Prompt Injection**: Direct injection, role manipulation, jailbreak attempts
- **System Extraction**: System prompt leak attempts and information gathering
- **Encoding Attacks**: Base64, URL encoding, Unicode obfuscation
- **DoS Attacks**: Request flooding, resource exhaustion, complexity attacks
- **Model Integrity**: Tampering detection, unauthorized access patterns
- **Quality Issues**: Coherence degradation, bias detection, hallucinations

### Demo Scripts

```bash
# Complete monitoring system demonstration
python demo_monitoring.py

# Interactive mode for specific testing
python demo_monitoring.py --interactive

# Original defense capabilities demo
python demo_blackloom.py --comprehensive
```

## Monitoring & Analytics

### Real-Time Dashboards
- **Security Overview**: Live threat detection and blocking statistics
- **Performance Metrics**: Response times, throughput, and resource utilization
- **Quality Trends**: Output quality metrics and degradation detection
- **Alert Management**: Centralized alert viewing, acknowledgment, and resolution

### Analytics & Reporting
- **Attack Pattern Analysis**: Trending attack vectors and effectiveness metrics
- **Model Integrity Reports**: Comprehensive verification and audit reports
- **Performance Analytics**: Capacity planning and optimization recommendations
- **Compliance Reports**: Automated regulatory compliance documentation

## Production Deployment

### Security Considerations
1. **Authentication**: Implement enterprise SSO integration
2. **API Security**: Rate limiting, request validation, secure headers
3. **Data Protection**: Encrypt sensitive data at rest and in transit
4. **Access Control**: Role-based access control with audit trails
5. **Network Security**: Deploy behind WAF and implement network segmentation

### Scalability & Performance
1. **Horizontal Scaling**: Multi-instance deployment with load balancing
2. **Caching Strategy**: Redis integration for improved performance
3. **Database Optimization**: PostgreSQL with proper indexing for audit logs
4. **Monitoring Integration**: Prometheus/Grafana for operational metrics
5. **Backup & Recovery**: Automated backup strategies for critical data

### Integration
1. **CI/CD Pipeline**: Automated testing and deployment integration
2. **SIEM Integration**: Security information and event management connectivity
3. **Model Deployment**: MLOps pipeline integration for model lifecycle management
4. **API Management**: Enterprise API gateway integration
5. **Notification Systems**: Integration with existing alerting infrastructure

## Use Cases

### Enterprise AI Security
- **Production AI Models**: Protect customer-facing AI applications
- **Internal AI Tools**: Secure employee-facing AI assistants and tools
- **API Protection**: Secure AI API endpoints from malicious requests
- **Compliance**: Meet regulatory requirements for AI system security

### Research & Development
- **Attack Research**: Test and validate new attack vectors
- **Defense Validation**: Evaluate defense mechanism effectiveness
- **Security Auditing**: Comprehensive security assessment of AI systems
- **Threat Intelligence**: Analyze emerging AI security threats

## Contributing

BlackLoom Defense is designed as a comprehensive AI security platform. For production deployment and contributions:

1. **Security Review**: Complete security audit and penetration testing
2. **Performance Testing**: Load testing and performance optimization
3. **Integration Testing**: Validate with production AI model deployments
4. **Documentation**: Expand operational documentation and runbooks
5. **Community**: Engage with AI security research community

## Resources & Research

### OWASP ML Security
- [OWASP ML Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [OWASP ML Security Guide](https://github.com/OWASP/www-project-machine-learning-security-top-10)

### Academic Research
- [Prompt Injection Attacks](https://arxiv.org/abs/2302.12173)
- [Adversarial Machine Learning](https://arxiv.org/abs/1812.00292)
- [AI Model Security Assessment](https://arxiv.org/abs/2309.15324)

### Industry Standards
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [ISO/IEC 27090 AI Security](https://www.iso.org/standard/80392.html)

## License

This project demonstrates comprehensive AI security capabilities for BlackLoom AI. Enterprise licensing available for production deployments.

---

**BlackLoom Defense** - *Comprehensive AI Security for the Modern Enterprise*