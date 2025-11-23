# JWT Secure Cookie Implementation Example

## Overview
This example demonstrates secure JWT storage using HttpOnly, Secure cookies - the recommended approach for modern web applications to prevent XSS attacks while maintaining user authentication state.

## Security Benefits
- **HttpOnly flag**: Prevents JavaScript access (XSS protection)
- **Secure flag**: Ensures transmission only over HTTPS
- **SameSite**: CSRF protection
- **No localStorage**: Eliminates XSS token theft

---

## Backend Implementation (Node.js/Express)

### 1. JWT Cookie Configuration
```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cookieParser());

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const COOKIE_NAME = 'auth_token';
const COOKIE_OPTIONS = {
  httpOnly: true,        // JavaScript cannot access
  secure: true,          // Only HTTPS transmission
  sameSite: 'strict',    // CSRF protection
  maxAge: 24 * 60 * 60 * 1000, // 24 hours
  path: '/',             // Available to all routes
};

// Generate secure JWT token
function generateJWT(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: '24h',
    issuer: 'your-domain.com',
    audience: 'your-webapp'
  });
}

// Verify JWT token
function verifyJWT(token) {
  return jwt.verify(token, JWT_SECRET, {
    issuer: 'your-domain.com',
    audience: 'your-webapp'
  });
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = verifyJWT(token);
    req.user = decoded;
    next();
  } catch (error) {
    // Clear invalid token
    res.clearCookie(COOKIE_NAME, COOKIE_OPTIONS);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}
```

### 2. Login Endpoint - Setting Secure Cookie
```javascript
// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate user credentials (example - replace with real auth)
    const user = await validateUser(email, password);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create JWT payload
    const payload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      sessionId: crypto.randomUUID()
    };

    // Generate JWT
    const token = generateJWT(payload);

    // Set secure cookie
    res.cookie(COOKIE_NAME, token, COOKIE_OPTIONS);

    // Return user info (no token exposed to frontend)
    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        name: user.name
      }
    });

    console.log(`User ${user.email} logged in successfully`);

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// GET /api/auth/me - Verify current session
app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({
    user: {
      id: req.user.userId,
      email: req.user.email,
      role: req.user.role,
      name: req.user.name
    }
  });
});

// POST /api/auth/logout - Clear secure cookie
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, COOKIE_OPTIONS);
  res.json({ success: true, message: 'Logged out successfully' });
});
```

### 3. Protected Route Example
```javascript
// GET /api/protected/data
app.get('/api/protected/data', authenticateToken, (req, res) => {
  // Access user info from JWT payload
  const { userId, email, role } = req.user;
  
  // Check permissions
  if (role !== 'admin') {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }

  // Return protected data
  res.json({
    sensitiveData: 'This is protected information',
    userId: userId,
    timestamp: new Date().toISOString()
  });
});

// Server startup
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

---

## Frontend Implementation (React)

### 1. Authentication Hook
```javascript
// hooks/useAuth.js
import { useState, useEffect, useCallback } from 'react';

export function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Check current session
  const checkAuth = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/auth/me', {
        method: 'GET',
        credentials: 'include'  // Include cookies in request
      });

      if (response.ok) {
        const userData = await response.json();
        setUser(userData.user);
      } else {
        setUser(null);
      }
    } catch (err) {
      console.error('Auth check failed:', err);
      setError('Authentication check failed');
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  // Login function
  const login = async (email, password) => {
    try {
      setError(null);
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',  // Crucial for cookie handling
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (response.ok) {
        setUser(data.user);
        return { success: true };
      } else {
        setError(data.error || 'Login failed');
        return { success: false, error: data.error };
      }
    } catch (err) {
      const errorMsg = 'Network error during login';
      setError(errorMsg);
      return { success: false, error: errorMsg };
    }
  };

  // Logout function
  const logout = async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include'
      });
      setUser(null);
    } catch (err) {
      console.error('Logout error:', err);
    }
  };

  // Check auth on mount
  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  return {
    user,
    loading,
    error,
    login,
    logout,
    isAuthenticated: !!user,
    checkAuth
  };
}
```

### 2. Protected Route Component
```javascript
// components/ProtectedRoute.js
import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export function ProtectedRoute({ children, requiredRole }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="loading-spinner">
        <p>Loading...</p>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (requiredRole && user.role !== requiredRole) {
    return (
      <div className="access-denied">
        <h2>Access Denied</h2>
        <p>Insufficient permissions to access this page.</p>
      </div>
    );
  }

  return children;
}
```

### 3. Login Page Component
```javascript
// pages/LoginPage.js
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { login, error } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    const result = await login(email, password);
    
    if (result.success) {
      navigate('/dashboard');
    }
    
    setIsLoading(false);
  };

  return (
    <div className="login-container">
      <form onSubmit={handleSubmit} className="login-form">
        <h2>Secure Login</h2>
        
        <div className="form-group">
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="email"
          />
        </div>

        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
          />
        </div>

        {error && (
          <div className="error-message">
            {error}
          </div>
        )}

        <button 
          type="submit" 
          disabled={isLoading}
          className="login-button"
        >
          {isLoading ? 'Signing in...' : 'Sign In'}
        </button>
      </form>
    </div>
  );
}
```

### 4. Dashboard Component (Protected)
```javascript
// pages/Dashboard.js
import React from 'react';
import { useAuth } from '../hooks/useAuth';

export function Dashboard() {
  const { user, logout } = useAuth();

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>Welcome, {user.name}</h1>
        <div className="user-info">
          <span>Email: {user.email}</span>
          <span>Role: {user.role}</span>
        </div>
        <button onClick={logout} className="logout-button">
          Logout
        </button>
      </header>

      <main className="dashboard-content">
        <h2>Protected Content</h2>
        <p>You are authenticated and can access this content.</p>
        <p>Your JWT is stored securely in an HttpOnly cookie.</p>
      </main>
    </div>
  );
}
```

---

## Security Testing Checklist

### ✅ Verify Secure Cookie Settings
```bash
# Check in browser DevTools > Application > Cookies
# The auth_token should have:
# - Name: auth_token
# - HttpOnly: ✓
# - Secure: ✓
# - SameSite: Strict
# - Expires: [Future date]
```

### ✅ XSS Protection Test
```javascript
// In browser console - should return undefined
console.log(document.cookie);
// Should NOT show: auth_token=...

// Try to access via JavaScript - should fail
localStorage.getItem('auth_token');  // Returns null
sessionStorage.getItem('auth_token'); // Returns null
```

### ✅ HTTPS Requirement Test
```javascript
// Should work only on HTTPS in production
// HTTP will be blocked due to Secure flag
```

### ✅ CSRF Protection Test
```javascript
// SameSite=Strict prevents cross-site requests
// Forms from other domains will be blocked
```

---

## Environment Setup

### Backend Dependencies
```json
{
  "dependencies": {
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.2",
    "cookie-parser": "^1.4.6",
    "bcrypt": "^5.1.1"
  }
}
```

### Frontend Setup
```javascript
// In your React app setup
// Ensure fetch includes credentials
const api = {
  get: (url) => fetch(url, { credentials: 'include' }),
  post: (url, data) => fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(data)
  })
};
```

---

## Key Security Features Demonstrated

1. **HttpOnly Cookie**: Prevents JavaScript access to tokens
2. **Secure Flag**: Ensures HTTPS-only transmission
3. **SameSite Protection**: CSRF attack prevention
4. **Server-Side Validation**: JWT verification on every request
5. **Automatic Cleanup**: Token clearing on logout/error
6. **Role-Based Access**: Authorization through JWT payload
7. **Session Management**: Unique session IDs for tracking

This implementation provides enterprise-grade security while maintaining excellent user experience and developer convenience.