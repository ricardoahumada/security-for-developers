# 5. JWT Security Vulnerabilities and Attacks

## Vulnerability 01: None Algorithm Attack

**Problem**: Setting algorithm to "none" bypasses signature verification.

```javascript
// VULNERABLE - This is what attackers try to exploit
const header = {
  alg: "none",
  typ: "JWT"
};

const payload = {
  sub: "1234567890",
  role: "admin",
  iat: 1516239022
};

// Attacker creates token with "none" algorithm
const maliciousToken = base64UrlEncode(JSON.stringify(header)) + "." + 
                      base64UrlEncode(JSON.stringify(payload)) + ".";

// If server accepts "none" algorithm, signature is ignored!
jwt.verify(maliciousToken, '', { algorithms: ['none', 'HS256'] });
```

**Prevention**:
```javascript
// SECURE - Explicitly specify allowed algorithms
const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';

jwt.verify(token, secretKey, {
  algorithms: ['HS256'], // Only allow HS256
  issuer: 'my-app',
  audience: 'my-web-app'
});

// Never accept 'none' algorithm
if (decodedHeader.alg === 'none') {
  throw new Error('Algorithm "none" is not allowed');
}
```

## Vulnerability 02: Algorithm Confusion Attack

**Problem**: Switching from RS256 to HS256 using public key as HMAC secret.

```javascript
// ATTACK SCENARIO
const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----`;

// Attacker creates token with HS256 algorithm but uses public key as secret
const maliciousPayload = {
  sub: "1234567890",
  role: "admin",
  iat: 1516239022
};

const maliciousToken = jwt.sign(maliciousPayload, publicKey, { 
  algorithm: 'HS256' 
});

// If server doesn't check algorithm strictly, this might work!
```

**Prevention**:
```javascript
// SECURE - Store algorithm separately from token
const tokenAlgorithms = {
  [tokenId]: 'RS256' // Store expected algorithm
};

// Verification
const decoded = jwt.decode(token);
const expectedAlg = tokenAlgorithms[decoded.jti];

jwt.verify(token, publicKey, {
  algorithms: [expectedAlg], // Only allow expected algorithm
  issuer: 'my-app',
  audience: 'my-web-app'
});
```

## Vulnerability 03: Key Confusion via kid Header

**Problem**: Manipulating the "kid" (key ID) header to access unintended keys.

```javascript
// ATTACK SCENARIO
// kid can be used to select which key to use for verification
const header = {
  alg: "HS256",
  typ: "JWT",
  kid: "../../../etc/passwd" // Path traversal attack
};

// If server uses kid to select files/keys without sanitization
const key = loadKey(header.kid); // Could load wrong file!
```

**Prevention**:
```javascript
// SECURE - Sanitize and validate kid
function selectKey(header) {
  // Validate kid format
  if (!/^[a-zA-Z0-9_-]+$/.test(header.kid)) {
    throw new Error('Invalid kid format');
  }
  
  // Use whitelist approach
  const allowedKeys = {
    'key-1': key1,
    'key-2': key2,
    'current': currentKey
  };
  
  return allowedKeys[header.kid];
}
```

## Vulnerability 04: JWT Timing Attacks

**Problem**: Timing differences in verification can leak information.

**Prevention**:
```javascript
// SECURE - Constant-time comparison
function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}

// Use with JWT verification
try {
  jwt.verify(token, secretKey, { algorithms: ['HS256'] });
} catch (error) {
  // Don't reveal which part failed
  return false;
}
```

### Vulnerability 5: Token Hijacking via Weak Secrets
```javascript
// VULNERABLE - Weak secret
const secret = "secret"; // Too predictable

// ATTACKER can brute force this
for (let guess = 0; guess < 10000; guess++) {
  try {
    jwt.verify(token, String(guess));
    console.log("Found secret:", guess);
  } catch (e) {}
}
```

**Prevention:** Use cryptographically strong secrets (32+ random characters).

---

### Vulnerability 6: JSON Injection Attacks
```javascript
// VULNERABLE - No validation of payload content
const decoded = jwt.decode(token);
user.role = decoded.role; // Could be malicious object
```

**Prevention:** Strictly validate all JWT payload claims and their expected data types.

---

### Vulnerability 7: Freshness Attacks (Replay Attacks)
```javascript
// VULNERABLE - No expiration or replay protection
const token = jwt.sign({ userId: "123" }, secret);
// This token is valid forever!
```

**Prevention:** Always include `exp` claim and implement anti-replay mechanisms for sensitive operations.

---

### Vulnerability 8: Key Leakage via Error Messages
```javascript
// VULNERABLE - Reveals too much information
if (err.message.includes("secret")) {
  return "Secret is wrong";
}
if (err.message.includes("expired")) {
  return "Token expired";
}
```

**Prevention:** Use generic error messages that don't reveal which specific validation failed.

---

### Vulnerability 9: JWT Header Confusion (typ confusion)
```javascript
// ATTACK - Using wrong type header
header = {
  typ: "JWS", // Should be "JWT"
  alg: "HS256"
}
```

**Prevention:** Always validate the `typ` header matches expected value.

---

### Vulnerability 10: Weak Algorithm Support
```javascript
// VULNERABLE - Allowing weak algorithms
jwt.verify(token, key, { 
  algorithms: ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'] 
});
```

**Prevention:** Only allow the specific algorithm(s) needed by your application. Don't allow multiple algorithms unless absolutely necessary.

---

### Vulnerability 11: Insufficient Audience Validation
```javascript
// VULNERABLE - No audience check
jwt.verify(token, key); // Works for any audience!
```

**Prevention:** Always validate `aud` claim matches your application's audience identifier.

---

### Vulnerability 12: Weak Token Expiration Management
```javascript
// VULNERABLE - Very long expiration
jwt.sign(payload, key, { expiresIn: '365d' }); // 1 year!

// VULNERABLE - No expiration at all
jwt.sign(payload, key); // Never expires!
```

**Prevention:** Use short expiration times (15 minutes to 1 hour) for access tokens. Use refresh tokens for longer sessions.

---

## **Comprehensive Security Checklist**

### **Algorithm Security:**
- ✅ Never accept `alg: "none"`
- ✅ Restrict to specific algorithms only
- ✅ Separate algorithm storage from tokens
- ✅ Use strong cryptographic keys (32+ chars)

### **Token Validation:**
- ✅ Validate `iss` (issuer)
- ✅ Validate `aud` (audience) 
- ✅ Validate `exp` (expiration)
- ✅ Validate `nbf` (not before)
- ✅ Validate `typ` (type)
- ✅ Validate payload content structure

### **Key Management:**
- ✅ Sanitize `kid` header parameter
- ✅ Use whitelist for allowed keys
- ✅ Implement proper key rotation
- ✅ Secure key storage (not in code)
- ✅ Use different keys for different environments

### **Error Handling:**
- ✅ Generic error messages
- ✅ Don't leak implementation details
- ✅ Log security events properly
- ✅ Monitor for unusual patterns

### **Operational Security:**
- ✅ Short token lifetimes
- ✅ Refresh token rotation
- ✅ Rate limiting on validation endpoints
- ✅ Anti-replay mechanisms
- ✅ Regular security audits
