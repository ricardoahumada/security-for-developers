# JWT Implementation Patterns

## 1. Express.js JWT Authentication

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();

// Middleware for JWT verification
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Authenticate user
    const user = await authenticateUser(username, password);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      {
        sub: user.id,
        username: user.username,
        role: user.role,
        permissions: user.permissions
      },
      process.env.JWT_SECRET,
      {
        expiresIn: '1h',
        issuer: 'my-app',
        audience: 'my-web-app'
      }
    );

    res.json({
      access_token: token,
      token_type: 'Bearer',
      expires_in: 3600
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route
app.get('/api/profile', authenticateToken, (req, res) => {
  res.json({
    id: req.user.sub,
    username: req.user.username,
    role: req.user.role
  });
});
```

## 2. Refresh Token Implementation

```javascript
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

class TokenManager {
  constructor() {
    this.refreshTokens = new Map(); // In production, use Redis or database
    this.refreshTokenTTL = 7 * 24 * 60 * 60 * 1000; // 7 days
  }

  generateTokens(payload) {
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
      algorithm: 'HS256',
      expiresIn: '15m', // Short-lived access token
      issuer: 'my-app',
      audience: 'my-web-app'
    });

    const refreshToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + this.refreshTokenTTL);
    
    this.refreshTokens.set(refreshToken, {
      userId: payload.sub,
      expiresAt,
      used: false
    });

    return { accessToken, refreshToken };
  }

  async refreshAccessToken(refreshToken) {
    const tokenData = this.refreshTokens.get(refreshToken);
    
    if (!tokenData || tokenData.used || tokenData.expiresAt < new Date()) {
      throw new Error('Invalid refresh token');
    }

    // Mark refresh token as used
    tokenData.used = true;
    
    // Generate new access token
    const newPayload = {
      sub: tokenData.userId,
      // Add any other claims needed
    };

    return jwt.sign(newPayload, process.env.JWT_SECRET, {
      algorithm: 'HS256',
      expiresIn: '15m',
      issuer: 'my-app',
      audience: 'my-web-app'
    });
  }

  revokeRefreshToken(refreshToken) {
    this.refreshTokens.delete(refreshToken);
  }
}
```

## 3. Multi-Service JWT Validation

```javascript
// Microservice JWT validation middleware
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

// For RS256 tokens from external IdP
const client = jwksClient({
  jwksUri: 'https://auth.company.com/.well-known/jwks.json',
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 1000 // 10 minutes
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      return callback(err);
    }
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

const validateToken = (req, res, next) => {
  const token = extractToken(req);
  
  if (!token) {
    return res.status(401).json({ error: 'Token required' });
  }

  jwt.verify(token, getKey, {
    algorithms: ['RS256'],
    issuer: 'https://auth.company.com',
    audience: 'my-service'
  }, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token validation failed' });
    }
    req.user = decoded;
    next();
  });
};
```

## 4. Role-Based JWT Middleware

```javascript
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userRole = req.user.role;
    const hasRole = roles.includes(userRole);

    if (!hasRole) {
      return res.status(403).json({ 
        error: 'Insufficient privileges',
        required: roles,
        current: userRole
      });
    }

    next();
  };
}

function requirePermission(...permissions) {
  return (req, res, next) => {
    if (!req.user || !req.user.permissions) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userPermissions = req.user.permissions;
    const hasPermission = permissions.every(p => userPermissions.includes(p));

    if (!hasPermission) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        required: permissions,
        current: userPermissions
      });
    }

    next();
  };
}

// Usage
app.get('/admin/users', 
  authenticateToken,
  requireRole('admin'),
  requirePermission('users.read'),
  getUsers
);

app.post('/admin/users',
  authenticateToken,
  requireRole('admin'),
  requirePermission('users.create'),
  createUser
);
```
