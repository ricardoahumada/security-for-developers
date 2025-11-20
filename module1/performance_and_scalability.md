# JWT Performance and Scalability Considerations

## Token Size Optimization

**Problem**: Large JWTs increase network traffic and parsing time

**Solutions**:
```javascript
// Minimal JWT - only essential claims
const minimalToken = jwt.sign({
  sub: userId,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600
}, secret);

// Reference tokens - store claims server-side
const referenceToken = jwt.sign({
  ref: tokenReferenceId, // Short reference
  sub: userId,
  iat: Date.now()
}, secret);
```

## Caching Strategies

```javascript
// JWT validation caching
class JWTCache {
  constructor(ttl = 5 * 60 * 1000) { // 5 minutes
    this.cache = new Map();
    this.ttl = ttl;
  }

  get(key) {
    const item = this.cache.get(key);
    if (!item) return null;
    
    if (Date.now() > item.expires) {
      this.cache.delete(key);
      return null;
    }
    
    return item.value;
  }

  set(key, value) {
    this.cache.set(key, {
      value,
      expires: Date.now() + this.ttl
    });
  }
}

// Usage in middleware
const jwtCache = new JWTCache();

const cachedValidation = (req, res, next) => {
  const token = extractToken(req);
  const cacheKey = `validate:${token}`;
  
  let decoded = jwtCache.get(cacheKey);
  
  if (!decoded) {
    try {
      decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
      jwtCache.set(cacheKey, decoded);
    } catch (error) {
      return res.status(403).json({ error: 'Token invalid' });
    }
  }
  
  req.user = decoded;
  next();
};
```

## Database Integration

```javascript
// JWT token blacklist for revocation
class TokenBlacklist {
  constructor() {
    this.blacklist = new Set();
  }

  async revokeToken(jti) {
    this.blacklist.add(jti);
    
    // Schedule cleanup (tokens expire naturally)
    setTimeout(() => {
      this.blacklist.delete(jti);
    }, 24 * 60 * 60 * 1000); // 24 hours
  }

  async isRevoked(jti) {
    return this.blacklist.has(jti);
  }
}

// Enhanced validation with blacklist check
const validateWithBlacklist = async (token) => {
  const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
  
  if (await tokenBlacklist.isRevoked(decoded.jti)) {
    throw new Error('Token has been revoked');
  }
  
  return decoded;
};
```
