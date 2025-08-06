# Security Guidelines for BlackLoom Defense

This document outlines security practices and guidelines for the BlackLoom Defense repository.

## What Should NOT be Committed

### Cryptographic Keys & Certificates
- `*.key` - Private keys
- `*.pem` - Certificate files
- `*.crt` - Certificate files
- `*.p12`, `*.pfx` - PKCS#12 files
- Any files in `private_keys/` or `certificates/` directories

### Configuration & Secrets
- `.env` files (use `.env.example` as template)
- `api_keys.txt`
- `secrets.json`
- Database connection strings
- Service account credentials

### Application Data
- `*.db`, `*.sqlite*` - Database files
- `models_registry.json` - Contains sensitive file paths
- `audit_logs/` - May contain sensitive access data
- `logs/` - Application logs
- Performance monitoring data

### System Files
- `.DS_Store` (macOS)
- `Thumbs.db` (Windows)
- `__pycache__/` (Python bytecode)
- `*.pyc`, `*.pyo` (Python compiled files)
- `*.tmp`, `*.temp` (Temporary files)

## Safe to Commit

### Code & Documentation
- All source code (`.py` files)
- Documentation (`.md` files)
- Configuration templates (`.env.example`)
- Test files and test data (anonymized)

### Example Data
- Anonymized configuration examples
- Sample model registry entries (no real paths)
- Demo scripts and examples
- Test attack vectors (for research)

## Security Tools

### Automated Cleanup
Run the cleanup script before committing:

```bash
# Check what would be removed (dry run)
python3 cleanup_sensitive_data.py --dry-run

# Clean sensitive files
python3 cleanup_sensitive_data.py --create-gitkeep
```

### Git Hooks (Recommended)
Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
echo " Checking for sensitive files..."
python3 cleanup_sensitive_data.py --dry-run
if [ $? -ne 0 ]; then
 echo " Sensitive data cleanup failed"
 exit 1
fi
echo " Pre-commit security check passed"
```

### Environment Configuration
1. Copy `.env.example` to `.env`
2. Fill in your actual values
3. **Never commit the `.env` file**

```bash
cp .env.example .env
# Edit .env with your actual configuration
```

## Production Deployment Security

### Authentication
- Use strong, unique API keys
- Implement proper JWT token validation
- Enable multi-factor authentication where possible

### Encryption
- Encrypt sensitive data at rest
- Use TLS 1.3 for all communications
- Implement proper key rotation policies

### Access Control
- Follow principle of least privilege
- Implement role-based access control (RBAC)
- Maintain comprehensive audit logs

### Infrastructure Security
- Deploy behind a Web Application Firewall (WAF)
- Implement network segmentation
- Use container security scanning
- Regular security updates and patches

## Security Checklist

Before making your repository public:

- [ ] Run `python3 cleanup_sensitive_data.py`
- [ ] Verify `.gitignore` is properly configured
- [ ] Check that no `.env` files are committed
- [ ] Confirm no real API keys or passwords in code
- [ ] Verify model registry contains only example data
- [ ] Remove any real cryptographic keys
- [ ] Clean up any debug/development artifacts
- [ ] Review commit history for accidentally committed secrets

## If Secrets Are Accidentally Committed

### Immediate Actions
1. **Change all compromised credentials immediately**
2. **Remove secrets from latest commit**:
 ```bash
 git rm file_with_secrets
 git commit -m "Remove accidentally committed secrets"
 ```

3. **For public repositories, secrets in history are compromised**:
 - Consider the secrets permanently compromised
 - Rotate all affected credentials
 - May require repository deletion and recreation

### Git History Cleanup (Use with caution)
```bash
# Remove sensitive file from entire git history
git filter-branch --force --index-filter \
 "git rm --cached --ignore-unmatch path/to/sensitive/file" \
 --prune-empty --tag-name-filter cat -- --all

# Force push (DANGEROUS - coordinate with team)
git push origin --force --all
```

## 📞 Security Contact

For security vulnerabilities or concerns:
- Create a private security advisory on GitHub
- Email: security@blackloom.ai (if available)
- Report through responsible disclosure practices

## Regular Security Maintenance

### Weekly
- Review access logs for suspicious patterns
- Check for outdated dependencies
- Verify backup integrity

### Monthly
- Rotate API keys and certificates
- Review user access and permissions
- Update security documentation

### Quarterly
- Conduct security assessments
- Review and update threat models
- Test incident response procedures

## Security Resources

### OWASP Guidelines
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP ML Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

### AI Security Resources
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [Microsoft AI Security Guidelines](https://www.microsoft.com/en-us/ai/responsible-ai)
- [Google AI Security Best Practices](https://ai.google/responsibilities/responsible-ai-practices/)

---

**Remember**: Security is everyone's responsibility. When in doubt, err on the side of caution and ask for review.