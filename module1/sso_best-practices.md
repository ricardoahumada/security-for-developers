# SSO Security Best Practices

### **1. Session Management**
```javascript
sessionOptions = {
  secure: true,           // HTTPS only
  httpOnly: true,         // XSS protection  
  sameSite: 'strict',     // CSRF protection
  maxAge: 24 * 60 * 60 * 1000  // 24 hours
}
```


### **2. Token Validation**
```javascript
jwt.verify(token, signingKey, {
  audience: process.env.AUTH0_AUDIENCE,
  issuer: `https://${process.env.AUTH0_DOMAIN}/`,
  algorithms: ['RS256']
})
```


### **3. Certificate Management**
```yaml
rotation:
  schedule: 90d         # Regular rotation every 90 days
  grace_period: 30d     # 30-day overlap for smooth transition  
  notification: 7d      # 7-day advance warning
```


### **4. Multi-Factor Authentication (MFA)**
```yaml
authentication_policies:
  require_mfa: true
  mfa_methods:
    - totp          # Time-based one-time passwords
    - sms           # SMS verification
    - hardware      # Hardware tokens (FIDO2/WebAuthn)
```

### **5. Principle of Least Privilege**
```yaml
attribute_filtering:
  required_attributes: ["email", "first_name"]
  optional_attributes: ["department", "manager"]
  forbidden_attributes: ["salary", "ssn"]
```

### **6. Audit Logging & Monitoring**
```yaml
audit_logging:
  enabled: true
  events:
    - user_login
    - failed_authentication
    - token_validation_failure
    - certificate_rotation
  retention: 365d
  alerts:
    - repeated_failures: 5
    - suspicious_locations: true
```

### **7. Cross-Origin Resource Sharing (CORS)**
```javascript
const corsOptions = {
  origin: ['https://app.company.com', 'https://portal.company.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Authorization', 'Content-Type'],
  exposedHeaders: ['X-CSRF-Token']
};
```

### **8. Session Concurrency Controls**
```yaml
session_management:
  max_concurrent_sessions: 3
  force_logout_on_new: false  # or true for banking apps
  idle_timeout: 1800s         # 30 minutes
  absolute_timeout: 28800s    # 8 hours
```

### **9. Attribute Mapping Validation**
```javascript
function validateAttributeMapping(userInfo, requiredAttributes) {
  for (const attr of requiredAttributes) {
    if (!userInfo[attr] || userInfo[attr].length === 0) {
      throw new Error(`Required attribute '${attr}' missing or empty`);
    }
  }
  return true;
}
```

### **10. Time-Based Security**
```python
from datetime import datetime, timedelta

# SAML assertion lifetime limits
assertion_lifetime = timedelta(minutes=5)  # Very short lifetime
clock_skew = timedelta(seconds=60)         # Allow small time differences

# Force periodic re-authentication
re_authentication_interval = timedelta(hours=8)
```

### **11. Fail-Safe Defaults**
```yaml
security_defaults:
  deny_unauthenticated: true
  default_role: "guest"
  require_attribute_validation: true
  session_invalidation_on_logout: true
```

### **12. Geographic and Device Controls**
```yaml
access_policies:
  allowed_locations:
    - "US"
    - "CA"
    - "UK"
  
  device_requirements:
    require_managed_device: false
    require_encrypted_storage: true
    
  behavioral_checks:
    unusual_login_pattern: true
    impossible_travel: true
```
