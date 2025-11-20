# 5. JWT Security Vulnerabilities and Attacks

## Vulnerability 1: None Algorithm Attack

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

## Vulnerability 2: Algorithm Confusion Attack

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

## Vulnerability 3: Key Confusion via kid Header

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

## Vulnerability 4: JWT Timing Attacks

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
