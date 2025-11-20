# Security Best Practices

## 1. Session Management
```javascript
// Secure session configuration
const sessionOptions = {
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,           // HTTPS only
    httpOnly: true,         // XSS protection
    sameSite: 'strict',     // CSRF protection
    maxAge: 24 * 60 * 60 * 1000  // 24 hours
  }
};
```

## 2. Token Validation
```javascript
// JWT validation middleware
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({
  jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
});

function validateToken(token) {
  return new Promise((resolve, reject) => {
    const decoded = jwt.decode(token, { complete: true });
    
    if (!decoded) {
      return reject(new Error('Invalid token'));
    }
    
    client.getSigningKey(decoded.header.kid, (err, key) => {
      if (err) {
        return reject(err);
      }
      
      const signingKey = key.getPublicKey();
      
      jwt.verify(token, signingKey, {
        audience: process.env.AUTH0_AUDIENCE,
        issuer: `https://${process.env.AUTH0_DOMAIN}/`,
        algorithms: ['RS256']
      }, (err, decoded) => {
        if (err) {
          return reject(err);
        }
        resolve(decoded);
      });
    });
  });
}
```

## 3. Certificate Management
```yaml
# SAML certificate rotation strategy
saml_config:
  certificates:
    current: /path/to/current-cert.pem
    next: /path/to/next-cert.pem
  rotation:
    schedule: 90d
    grace_period: 30d
    notification: 7d
```
