# Common OAuth 2.0 Vulnerabilities

## 1. Redirect URI Manipulation
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

## 2. Scope Escalation
**Vulnerability**: Client requests unnecessary or dangerous scopes

```javascript
// VULNERABLE: Overly broad scope request
const broadScopes = ['admin:*', 'delete:*', 'financial:*'];

// SECURE: Minimal scope request
const minimalScopes = ['read:profile', 'write:posts'];
```

## 3. Token Replay Attacks
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