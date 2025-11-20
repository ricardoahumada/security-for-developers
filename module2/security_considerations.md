# OAuth 2.0 Security Considerations

## Security Fundamentals

OAuth 2.0 introduces new attack vectors that must be properly addressed:

### 1. Client Registration and Authentication
```javascript
// SECURE: Proper client authentication
class OAuthClient {
  constructor(clientId, clientSecret, redirectUri) {
    this.clientId = clientId;
    this.clientSecret = clientSecret; // Keep secret secure
    this.redirectUri = this.validateRedirectUri(redirectUri);
    this.registeredRedirectUris = [redirectUri]; // Only allow registered URIs
  }
  
  validateRedirectUri(uri) {
    // Only allow HTTPS and pre-registered URIs
    if (!uri.startsWith('https://') && !uri.startsWith('http://localhost')) {
      throw new Error('Only HTTPS redirect URIs allowed');
    }
    
    if (!this.registeredRedirectUris.includes(uri)) {
      throw new Error('Redirect URI not registered');
    }
    
    return uri;
  }
}
```

### 2. Token Storage and Transmission
```javascript
// SECURE: Token storage strategies
class TokenManager {
  // For confidential clients (server-side)
  storeServerToken(token, userId) {
    // Store in secure database with encryption
    return database.tokens.create({
      access_token: this.encrypt(token),
      user_id: userId,
      created_at: new Date()
    });
  }
  
  // For public clients (SPA/mobile)
  storeClientToken(token) {
    // Use secure storage mechanisms
    if (this.isServerSide()) {
      return this.storeInHttpOnlyCookie(token);
    } else {
      return this.storeInSecureStorage(token);
    }
  }
  
  storeInHttpOnlyCookie(token) {
    return {
      'Set-Cookie': `access_token=${token}; HttpOnly; Secure; SameSite=Strict`
    };
  }
  
  storeInSecureStorage(token) {
    // For mobile: Keychain/Keystore
    // For SPA: sessionStorage (not localStorage)
    return sessionStorage.setItem('access_token', token);
  }
}
```

### 3. Token Validation
```javascript
// SECURE: Token validation middleware
const validateToken = async (req, res, next) => {
  try {
    const token = extractToken(req);
    
    if (!token) {
      return res.status(401).json({ error: 'No access token provided' });
    }
    
    // Decode token (don't trust it yet)
    const decoded = jwt.decode(token);
    
    if (!decoded) {
      return res.status(401).json({ error: 'Invalid token format' });
    }
    
    // Validate token with authorization server
    const isValid = await this.validateTokenWithAuthServer(token);
    
    if (!isValid) {
      return res.status(401).json({ error: 'Token validation failed' });
    }
    
    // Check token scope
    const requiredScope = getRequiredScope(req.path);
    if (!this.hasRequiredScope(decoded.scope, requiredScope)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        required: requiredScope 
      });
    }
    
    req.user = decoded;
    next();
    
  } catch (error) {
    res.status(401).json({ error: 'Token validation error' });
  }
};
```

## Common OAuth 2.0 Vulnerabilities

### 1. Redirect URI Manipulation
**Vulnerability**: Attacker tricks users into authorizing with malicious redirect URI

```javascript
// VULNERABLE: No redirect URI validation
const client = {
  redirectUri: 'https://attacker.com/callback' // Could be manipulated
};

// SECURE: Strict redirect URI validation
const secureClient = {
  registeredRedirectUris: [
    'https://myapp.com/callback',
    'https://myapp-dev.com/callback'
  ]
};
```

### 2. Scope Escalation
**Vulnerability**: Client requests unnecessary or dangerous scopes

```javascript
// VULNERABLE: Overly broad scope request
const broadScopes = ['admin:*', 'delete:*', 'financial:*'];

// SECURE: Minimal scope request
const minimalScopes = ['read:profile', 'write:posts'];
```

### 3. Token Replay Attacks
**Vulnerability**: Attacker intercepts and reuses valid tokens

```javascript
// SECURE: Token binding and validation
const secureTokenManager = {
  async validateReplay(token) {
    // Check if token has been used before
    const usageCount = await database.tokenUsage.count({
      token_hash: this.hashToken(token),
      user_id: this.getUserIdFromToken(token)
    });
    
    if (usageCount > 1) {
      throw new Error('Token replay detected');
    }
    
    // Mark token as used
    await database.tokenUsage.create({
      token_hash: this.hashToken(token),
      user_id: this.getUserIdFromToken(token),
      used_at: new Date()
    });
  }
};
```