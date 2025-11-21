# Secure Headers Implementation

**Author:** MiniMax Agent  
**Date:** 2025-11-15

## Overview

This document provides comprehensive implementations for secure HTTP headers across different web application frameworks and deployment scenarios.

## 1. Express.js Secure Headers Implementation

```javascript
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

class SecureHeadersManager {
  constructor() {
    this.app = express();
    this.securityHeaders = new Map();
    this.headerSets = new Map();
    
    this.setupDefaultHeaders();
  }

  setupDefaultHeaders() {
    // Define different security header sets for different scenarios
    this.headerSets.set('default', this.getDefaultSecurityHeaders());
    this.headerSets.set('api', this.getAPISecurityHeaders());
    this.headerSets.set('admin', this.getAdminSecurityHeaders());
    this.headerSets.set('public', this.getPublicSecurityHeaders());
    this.headerSets.set('healthcare', this.getHealthcareSecurityHeaders());
  }

  getDefaultSecurityHeaders() {
    return {
      // Content Security Policy
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
      
      // Clickjacking protection
      'X-Frame-Options': 'DENY',
      
      // MIME type sniffing protection
      'X-Content-Type-Options': 'nosniff',
      
      // XSS Protection
      'X-XSS-Protection': '1; mode=block',
      
      // Referrer Policy
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      
      // HSTS (only for HTTPS)
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
      
      // Permissions Policy
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
      
      // Remove server information
      'Server': '(remove)',
      'X-Powered-By': '(remove)'
    };
  }

  getAPISecurityHeaders() {
    return {
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none';",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'no-referrer',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
      'Cache-Control': 'no-store, no-cache, must-revalidate, private',
      'Pragma': 'no-cache',
      'Expires': '0',
      'Server': '(remove)',
      'X-Powered-By': '(remove)'
    };
  }

  getAdminSecurityHeaders() {
    return {
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self';",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=()',
      'Cache-Control': 'no-store, no-cache, must-revalidate, private, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
      'Server': '(remove)',
      'X-Powered-By': '(remove)'
    };
  }

  getPublicSecurityHeaders() {
    return {
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
      'Server': '(remove)',
      'X-Powered-By': '(remove)'
    };
  }

  getHealthcareSecurityHeaders() {
    return {
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'strict-dynamic'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://ehr.healthcare.org; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self';",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'same-origin',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=()',
      'Cache-Control': 'no-store, no-cache, must-revalidate, private, no-store',
      'Pragma': 'no-cache',
      'Expires': '0',
      'Server': '(remove)',
      'X-Powered-By': '(remove)',
      'X-Healthcare-Compliance': 'HIPAA-compliant'
    };
  }

  configureBasicSecurity() {
    // Use Helmet for basic security headers
    this.app.use(helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
          fontSrc: ["'self'"],
          connectSrc: ["'self'"],
          frameSrc: ["'none'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          childSrc: ["'none'"]
        }
      },
      crossOriginEmbedderPolicy: false,
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    }));

    // Remove server information
    this.app.use((req, res, next) => {
      res.removeHeader('X-Powered-By');
      res.removeHeader('Server');
      next();
    });

    return this.app;
  }

  configureAdvancedSecurity(headerSet = 'default') {
    const headers = this.headerSets.get(headerSet) || this.headerSets.get('default');
    
    // Apply security headers
    this.app.use((req, res, next) => {
      // Set security headers
      Object.entries(headers).forEach(([header, value]) => {
        if (value === '(remove)') {
          res.removeHeader(header);
        } else {
          res.setHeader(header, value);
        }
      });
      
      // Additional security middleware
      this.applyAdditionalSecurity(req, res);
      
      next();
    });

    return this.app;
  }

  applyAdditionalSecurity(req, res) {
    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP'
    });
    
    // Apply rate limiting to API endpoints
    if (req.path.startsWith('/api/')) {
      limiter(req, res, () => {});
    }

    // Security logging
    this.logSecurityEvent(req, res);
  }

  logSecurityEvent(req, res) {
    // Log security-relevant events
    if (req.path.includes('/admin') || req.path.includes('/api/admin')) {
      console.log('Admin access attempt', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
        timestamp: new Date().toISOString()
      });
    }
  }

  getApplication() {
    return this.app;
  }

  // Middleware for dynamic header configuration
  getDynamicHeaderMiddleware() {
    return (req, res, next) => {
      const headerSet = this.determineHeaderSet(req);
      const headers = this.headerSets.get(headerSet);
      
      Object.entries(headers).forEach(([header, value]) => {
        if (value === '(remove)') {
          res.removeHeader(header);
        } else {
          res.setHeader(header, value);
        }
      });
      
      next();
    };
  }

  determineHeaderSet(req) {
    // Determine appropriate header set based on request
    if (req.path.startsWith('/api/')) {
      return 'api';
    } else if (req.path.startsWith('/admin')) {
      return 'admin';
    } else if (req.path.startsWith('/healthcare')) {
      return 'healthcare';
    } else if (req.path.startsWith('/public')) {
      return 'public';
    } else {
      return 'default';
    }
  }
}

// Usage example
const app = new SecureHeadersManager();

// Configure advanced security
app.configureAdvancedSecurity('healthcare');

// Add routes
app.getApplication().get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.getApplication().get('/api/secure', (req, res) => {
  res.json({ message: 'This endpoint has enhanced security headers' });
});

app.getApplication().get('/', (req, res) => {
  res.send('Secure application with healthcare headers');
});

module.exports = SecureHeadersManager;
```

## 2. Python Flask Secure Headers

```python
from flask import Flask, request, jsonify, g
from flask_talisman import Talisman
from functools import wraps
import logging
import secrets

app = Flask(__name__)

class FlaskSecureHeaders:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        # Configure Talisman for security headers
        Talisman(app, 
            force_https=False,  # Set to True in production
            session_cookie_secure=True,
            session_cookie_http_only=True,
            session_cookie_samesite='Lax',
            content_security_policy={
                'default-src': "'self'",
                'script-src': "'self'",
                'style-src': "'self' 'unsafe-inline'",
                'img-src': "'self' data: https:",
                'font-src': "'self'",
                'connect-src': "'self'",
                'frame-ancestors': "'none'",
                'object-src': "'none'",
                'base-uri': "'self'",
                'form-action': "'self'"
            },
            content_security_policy_nonce_in=['script-src']
        )
        
        # Register after request handler
        app.after_request(self.add_security_headers)
        app.before_request(self.log_security_events)
    
    def add_security_headers(self, response):
        """Add additional security headers after each request"""
        
        # Remove server information
        response.headers.pop('Server', None)
        response.headers.pop('X-Powered-By', None)
        
        # Add security headers based on endpoint
        if request.endpoint:
            if request.endpoint.startswith('api.'):
                self.add_api_security_headers(response)
            elif request.endpoint.startswith('admin.'):
                self.add_admin_security_headers(response)
            elif request.endpoint.startswith('healthcare.'):
                self.add_healthcare_security_headers(response)
            else:
                self.add_default_security_headers(response)
        
        return response
    
    def add_default_security_headers(self, response):
        """Add default security headers"""
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    def add_api_security_headers(self, response):
        """Add API-specific security headers"""
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    def add_admin_security_headers(self, response):
        """Add admin-specific security headers"""
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    
    def add_healthcare_security_headers(self, response):
        """Add healthcare-specific security headers"""
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['X-Healthcare-Compliance'] = 'HIPAA-compliant'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, no-store'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    def log_security_events(self):
        """Log security-relevant events"""
        # Log admin access attempts
        if request.endpoint and request.endpoint.startswith('admin.'):
            app.logger.info(f'Admin access attempt', extra={
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'endpoint': request.endpoint,
                'method': request.method,
                'timestamp': g.get('request_start_time')
            })
        
        # Log API access patterns
        if request.endpoint and request.endpoint.startswith('api.'):
            # Store request info for rate limiting
            g.request_id = secrets.token_hex(8)
            
            app.logger.info(f'API access', extra={
                'request_id': g.request_id,
                'endpoint': request.endpoint,
                'method': request.method,
                'ip': request.remote_addr
            })
    
    def require_api_key(self, f):
        """Decorator to require API key for API endpoints"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
            if not api_key or not self.validate_api_key(api_key):
                return jsonify({'error': 'Invalid or missing API key'}), 401
            return f(*args, **kwargs)
        return decorated_function
    
    def validate_api_key(self, api_key):
        """Validate API key (implement your logic)"""
        # This would check against a database or secure store
        return len(api_key) >= 32
    
    def cors_headers(self, origin_list):
        """Add CORS headers for specific origins"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                origin = request.headers.get('Origin')
                if origin and origin in origin_list:
                    response = f(*args, **kwargs)
                    response.headers['Access-Control-Allow-Origin'] = origin
                    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
                    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
                    response.headers['Access-Control-Allow-Credentials'] = 'true'
                    return response
                return f(*args, **kwargs)
            return decorated_function
        return decorator

# Initialize secure headers
secure_headers = FlaskSecureHeaders()

# Example routes with different security configurations
@app.route('/api/health')
def api_health():
    """Health check endpoint with API security headers"""
    return jsonify({
        'status': 'ok',
        'timestamp': g.get('request_start_time'),
        'security_level': 'api'
    })

@app.route('/api/secure-data')
@secure_headers.require_api_key
def api_secure_data():
    """Protected API endpoint requiring API key"""
    return jsonify({
        'data': 'This is sensitive API data',
        'security_level': 'api_protected'
    })

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard with admin security headers"""
    return jsonify({
        'message': 'Admin dashboard accessed',
        'security_level': 'admin'
    })

@app.route('/healthcare/patient-data')
@secure_headers.cors_headers(['https://ehr.healthcare.org', 'https://portal.healthcare.org'])
def healthcare_patient_data():
    """Healthcare endpoint with CORS and healthcare headers"""
    return jsonify({
        'data': 'Patient data (HIPAA compliant)',
        'security_level': 'healthcare'
    })

@app.route('/public/info')
def public_info():
    """Public endpoint with default security headers"""
    return jsonify({
        'message': 'Public information',
        'security_level': 'public'
    })

# Error handlers with security headers
@app.errorhandler(404)
def not_found_error(error):
    response = jsonify({'error': 'Not found'})
    response.status_code = 404
    secure_headers.add_api_security_headers(response)
    return response

@app.errorhandler(500)
def internal_error(error):
    response = jsonify({'error': 'Internal server error'})
    response.status_code = 500
    secure_headers.add_api_security_headers(response)
    return response

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    app.run(debug=True, host='0.0.0.0', port=5000)
```

## 3. Nginx Configuration for Secure Headers

```nginx
# /etc/nginx/sites-available/secure-application

server {
    listen 80;
    listen [::]:80;
    server_name yourdomain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name yourdomain.com;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/yourdomain.crt;
    ssl_certificate_key /etc/ssl/private/yourdomain.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers Configuration
    
    # Content Security Policy
    add_header Content-Security-Policy "
        default-src 'self';
        script-src 'self' 'unsafe-inline' 'unsafe-eval';
        style-src 'self' 'unsafe-inline';
        img-src 'self' data: https:;
        font-src 'self';
        connect-src 'self' https://api.yourdomain.com;
        frame-ancestors 'none';
        object-src 'none';
        base-uri 'self';
        form-action 'self';
    " always;
    
    # Clickjacking Protection
    add_header X-Frame-Options "DENY" always;
    
    # MIME Type Sniffing Protection
    add_header X-Content-Type-Options "nosniff" always;
    
    # XSS Protection
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Referrer Policy
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # HSTS (HTTP Strict Transport Security)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    # Permissions Policy
    add_header Permissions-Policy "
        geolocation=(),
        microphone=(),
        camera=(),
        payment=(),
        usb=(),
        magnetometer=(),
        gyroscope=(),
        accelerometer=()
    " always;
    
    # Remove Server Information
    server_tokens off;
    more_clear_headers "Server";
    more_clear_headers "X-Powered-By";
    
    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # Root Configuration
    root /var/www/html;
    index index.html index.htm;
    
    # Static Files with Long Cache
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        add_header X-Content-Type-Options "nosniff";
        add_header X-Frame-Options "DENY";
        try_files $uri =404;
    }
    
    # API Endpoints with Enhanced Security
    location /api/ {
        # Rate limiting for API
        limit_req zone=api burst=20 nodelay;
        
        # API-specific security headers
        add_header Cache-Control "no-store, no-cache, must-revalidate, private" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "no-referrer" always;
        
        # CORS headers (if needed)
        add_header Access-Control-Allow-Origin "https://yourdomain.com" always;
        add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE" always;
        add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
        add_header Access-Control-Allow-Credentials "true" always;
        
        # Proxy to backend application
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Security proxy headers
        proxy_set_header X-Forwarded-SSL on;
        proxy_set_header X-Forwarded-Protocol https;
    }
    
    # Admin Endpoints with Enhanced Security
    location /admin/ {
        # Stricter rate limiting
        limit_req zone=login burst=5 nodelay;
        
        # Admin-specific security headers
        add_header Cache-Control "no-store, no-cache, must-revalidate, private, must-revalidate" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        
        # IP Whitelist (example)
        allow 192.168.1.0/24;
        allow 10.0.0.0/8;
        deny all;
        
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Healthcare Endpoints
    location /healthcare/ {
        # Healthcare-specific security headers
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "same-origin" always;
        add_header X-Healthcare-Compliance "HIPAA-compliant" always;
        add_header Cache-Control "no-store, no-cache, must-revalidate, private, no-store" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
        
        # CORS for trusted healthcare domains
        add_header Access-Control-Allow-Origin "https://ehr.healthcare.org" always;
        add_header Access-Control-Allow-Origin "https://portal.healthcare.org" always;
        
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Login Endpoint with Additional Security
    location /api/auth/login {
        # Very strict rate limiting
        limit_req zone=login burst=3 nodelay;
        
        # Enhanced security headers
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Cache-Control "no-store, no-cache, must-revalidate, private" always;
        add_header Pragma "no-cache" always;
        
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Main application
    location / {
        try_files $uri $uri/ @backend;
    }
    
    # Backend application
    location @backend {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
    
    # Block access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    location ~ \.env$ {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Error pages with security headers
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    
    location = /404.html {
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
    }
    
    location = /50x.html {
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
    }
}

# Global security headers (apply to all servers)
# Add to /etc/nginx/nginx.conf in http block

http {
    # Global security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Remove server information globally
    server_tokens off;
    
    # Other nginx configuration...
}
```

## 4. Apache Configuration for Secure Headers

```apache
# /etc/apache2/sites-available/secure-application.conf

<VirtualHost *:80>
    ServerName yourdomain.com
    
    # Redirect to HTTPS
    Redirect permanent / https://yourdomain.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName yourdomain.com
    DocumentRoot /var/www/html
    
    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/yourdomain.crt
    SSLCertificateKeyFile /etc/ssl/private/yourdomain.key
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder off
    SSLSessionTickets off
    
    # Security Headers using mod_headers
    
    # Content Security Policy
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://api.yourdomain.com; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'"
    
    # Clickjacking Protection
    Header always set X-Frame-Options "DENY"
    
    # MIME Type Sniffing Protection
    Header always set X-Content-Type-Options "nosniff"
    
    # XSS Protection
    Header always set X-XSS-Protection "1; mode=block"
    
    # Referrer Policy
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # HSTS (HTTP Strict Transport Security)
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    
    # Permissions Policy
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
    
    # Remove Server Information
    Header unset Server
    Header unset X-Powered-By
    
    # API Location with Enhanced Security
    <LocationMatch "^/api/">
        # API-specific security headers
        Header always set Cache-Control "no-store, no-cache, must-revalidate, private"
        Header always set Pragma "no-cache"
        Header always set Expires "0"
        Header always set X-Frame-Options "DENY"
        Header always set X-Content-Type-Options "nosniff"
        Header always set Referrer-Policy "no-referrer"
        
        # CORS headers
        Header always set Access-Control-Allow-Origin "https://yourdomain.com"
        Header always set Access-Control-Allow-Methods "GET, POST, PUT, DELETE"
        Header always set Access-Control-Allow-Headers "Content-Type, Authorization"
        Header always set Access-Control-Allow-Credentials "true"
        
        # Rate limiting using mod_evasive
        <RequireAll>
            Require all granted
        </RequireAll>
    </LocationMatch>
    
    # Admin Location with Enhanced Security
    <LocationMatch "^/admin/">
        # Admin-specific security headers
        Header always set Cache-Control "no-store, no-cache, must-revalidate, private, must-revalidate"
        Header always set X-Frame-Options "DENY"
        Header always set X-Content-Type-Options "nosniff"
        Header always set X-XSS-Protection "1; mode=block"
        Header always set Referrer-Policy "strict-origin-when-cross-origin"
        Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()"
        
        # IP Whitelist
        <RequireAll>
            Require ip 192.168.1.0/24
            Require ip 10.0.0.0/8
            Require all denied
        </RequireAll>
    </LocationMatch>
    
    # Healthcare Location
    <LocationMatch "^/healthcare/">
        # Healthcare-specific security headers
        Header always set X-Frame-Options "DENY"
        Header always set X-Content-Type-Options "nosniff"
        Header always set X-XSS-Protection "1; mode=block"
        Header always set Referrer-Policy "same-origin"
        Header always set X-Healthcare-Compliance "HIPAA-compliant"
        Header always set Cache-Control "no-store, no-cache, must-revalidate, private, no-store"
        Header always set Pragma "no-cache"
        Header always set Expires "0"
        
        # CORS for trusted healthcare domains
        Header always set Access-Control-Allow-Origin "https://ehr.healthcare.org"
        Header always set Access-Control-Allow-Origin "https://portal.healthcare.org"
    </LocationMatch>
    
    # Static Files with Long Cache
    <LocationMatch "\.(js|css|png|jpg|jpeg|gif|ico|svg)$">
        # Security headers for static files
        Header always set X-Content-Type-Options "nosniff"
        Header always set X-Frame-Options "DENY"
        
        # Cache control for static assets
        <IfModule mod_expires.c>
            ExpiresActive On
            ExpiresDefault "access plus 1 year"
            Header set Cache-Control "public, immutable"
        </IfModule>
    </LocationMatch>
    
    # Block access to sensitive files
    <FilesMatch "^\.">
        Require all denied
    </FilesMatch>
    
    <FilesMatch "\.env$">
        Require all denied
    </FilesMatch>
    
    # Custom error pages with security headers
    ErrorDocument 404 /404.html
    ErrorDocument 500 /50x.html
    
    <Location "/404.html">
        Header always set X-Frame-Options "DENY"
        Header always set X-Content-Type-Options "nosniff"
    </Location>
    
    <Location "/50x.html">
        Header always set X-Frame-Options "DENY"
        Header always set X-Content-Type-Options "nosniff"
    </Location>
    
    # Logging
    ErrorLog ${APACHE_LOG_DIR}/yourdomain_error.log
    CustomLog ${APACHE_LOG_DIR}/yourdomain_access.log combined
    
</VirtualHost>

# Security Configuration in main apache2.conf

# Global security headers
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Remove sensitive headers globally
    Header unset Server
    Header unset X-Powered-By
</IfModule>

# Security configurations
ServerTokens Prod
ServerSignature Off
```

## 5. Security Headers Testing and Validation

```javascript
class SecurityHeadersTester {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.expectedHeaders = {
      // Must-have security headers
      'x-frame-options': ['DENY', 'SAMEORIGIN'],
      'x-content-type-options': ['nosniff'],
      'x-xss-protection': ['1; mode=block'],
      
      // Important security headers
      'strict-transport-security': [/max-age=\d+/],
      'content-security-policy': [/default-src/],
      'referrer-policy': [/strict-origin-when-cross-origin|same-origin/],
      
      // Should not be present headers
      'server': null,  // Should be removed
      'x-powered-by': null  // Should be removed
    };
    
    this.results = [];
  }

  async testAllEndpoints() {
    const endpoints = [
      '/',
      '/api/health',
      '/api/secure-data',
      '/admin/dashboard',
      '/healthcare/patient-data',
      '/public/info'
    ];

    for (const endpoint of endpoints) {
      try {
        const url = new URL(endpoint, this.baseUrl).href;
        const result = await this.testEndpoint(url);
        this.results.push({ endpoint, ...result });
      } catch (error) {
        this.results.push({ 
          endpoint, 
          error: error.message, 
          passed: false 
        });
      }
    }

    return this.generateReport();
  }

  async testEndpoint(url) {
    const response = await fetch(url);
    const headers = {};
    
    // Convert headers to lowercase for case-insensitive comparison
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    const checks = [];
    let passed = true;

    // Test each expected header
    for (const [headerName, expectedValues] of Object.entries(this.expectedHeaders)) {
      const check = this.testHeader(headerName, headers[headerName], expectedValues);
      checks.push(check);
      
      if (!check.passed) {
        passed = false;
      }
    }

    // Test for security vulnerabilities
    const vulnerabilities = this.testVulnerabilities(headers);

    return {
      url,
      status: response.status,
      headers,
      checks,
      vulnerabilities,
      passed: passed && vulnerabilities.length === 0
    };
  }

  testHeader(headerName, actualValue, expectedValues) {
    const result = {
      header: headerName,
      expected: expectedValues,
      actual: actualValue || 'NOT_PRESENT',
      passed: false,
      severity: 'info'
    };

    if (expectedValues === null) {
      // Header should not be present
      result.passed = !actualValue;
      result.severity = actualValue ? 'high' : 'info';
      result.message = actualValue 
        ? `Header "${headerName}" should be removed` 
        : `Header "${headerName}" correctly removed`;
    } else if (Array.isArray(expectedValues)) {
      // Header should match one of the expected values
      result.passed = expectedValues.some(expected => 
        actualValue && actualValue.toLowerCase() === expected.toLowerCase()
      );
      result.severity = result.passed ? 'info' : 'medium';
      result.message = result.passed 
        ? `Header "${headerName}" has correct value` 
        : `Header "${headerName}" should be one of: ${expectedValues.join(', ')}`;
    } else if (expectedValues instanceof RegExp) {
      // Header should match regex pattern
      result.passed = actualValue && expectedValues.test(actualValue);
      result.severity = result.passed ? 'info' : 'medium';
      result.message = result.passed 
        ? `Header "${headerName}" matches expected pattern` 
        : `Header "${headerName}" does not match expected pattern`;
    }

    return result;
  }

  testVulnerabilities(headers) {
    const vulnerabilities = [];

    // Check for CORS wildcard with credentials
    const corsOrigin = headers['access-control-allow-origin'];
    const corsCredentials = headers['access-control-allow-credentials'];
    
    if (corsOrigin === '*' && corsCredentials === 'true') {
      vulnerabilities.push({
        severity: 'high',
        type: 'cors_wildcard_credentials',
        description: 'CORS wildcard (*) with credentials enabled is a security vulnerability',
        evidence: `Access-Control-Allow-Origin: ${corsOrigin}, Access-Control-Allow-Credentials: ${corsCredentials}`
      });
    }

    // Check for exposed sensitive headers
    const sensitivePatterns = [
      { name: 'authorization', pattern: /bearer|basic/i },
      { name: 'api-key', pattern: /x-api-key|api_key/i },
      { name: 'password', pattern: /password|passwd|pwd/i }
    ];

    for (const [headerName, headerValue] of Object.entries(headers)) {
      for (const sensitive of sensitivePatterns) {
        if (sensitive.pattern.test(headerName) && headerValue) {
          vulnerabilities.push({
            severity: 'critical',
            type: 'sensitive_header_exposed',
            description: `Sensitive header "${headerName}" exposed in response`,
            evidence: `${headerName}: ${headerValue.substring(0, 20)}...`
          });
        }
      }
    }

    // Check for information disclosure
    const infoDisclosureHeaders = [
      'x-aspnet-version',
      'x-aspnetmvc-version',
      'x-runtime',
      'x-generator',
      'x-drupal-cache'
    ];

    for (const header of infoDisclosureHeaders) {
      if (headers[header]) {
        vulnerabilities.push({
          severity: 'low',
          type: 'information_disclosure',
          description: `Information disclosure header "${header}" exposed`,
          evidence: `${header}: ${headers[header]}`
        });
      }
    }

    return vulnerabilities;
  }

  generateReport() {
    const totalTests = this.results.length;
    const passedTests = this.results.filter(r => r.passed).length;
    const failedTests = totalTests - passedTests;

    const criticalVulnerabilities = [];
    const highVulnerabilities = [];
    const mediumVulnerabilities = [];
    const lowVulnerabilities = [];

    // Collect all vulnerabilities
    this.results.forEach(result => {
      if (result.vulnerabilities) {
        result.vulnerabilities.forEach(vuln => {
          switch (vuln.severity) {
            case 'critical':
              criticalVulnerabilities.push({ ...vuln, endpoint: result.endpoint });
              break;
            case 'high':
              highVulnerabilities.push({ ...vuln, endpoint: result.endpoint });
              break;
            case 'medium':
              mediumVulnerabilities.push({ ...vuln, endpoint: result.endpoint });
              break;
            case 'low':
              lowVulnerabilities.push({ ...vuln, endpoint: result.endpoint });
              break;
          }
        });
      }
    });

    console.log('\n🛡️  SECURITY HEADERS TEST REPORT');
    console.log('=' .repeat(50));
    
    console.log(`\n📊 Summary:`);
    console.log(`   Total Endpoints Tested: ${totalTests}`);
    console.log(`   Passed: ${passedTests} ✓`);
    console.log(`   Failed: ${failedTests} ✗`);
    
    console.log(`\n🚨 Vulnerabilities Found:`);
    console.log(`   Critical: ${criticalVulnerabilities.length}`);
    console.log(`   High: ${highVulnerabilities.length}`);
    console.log(`   Medium: ${mediumVulnerabilities.length}`);
    console.log(`   Low: ${lowVulnerabilities.length}`);
    
    // Report vulnerabilities by severity
    if (criticalVulnerabilities.length > 0) {
      console.log(`\n🔴 CRITICAL VULNERABILITIES:`);
      criticalVulnerabilities.forEach(vuln => {
        console.log(`   • ${vuln.description} (${vuln.endpoint})`);
        console.log(`     Evidence: ${vuln.evidence}`);
      });
    }
    
    if (highVulnerabilities.length > 0) {
      console.log(`\n🟠 HIGH VULNERABILITIES:`);
      highVulnerabilities.forEach(vuln => {
        console.log(`   • ${vuln.description} (${vuln.endpoint})`);
        console.log(`     Evidence: ${vuln.evidence}`);
      });
    }
    
    if (mediumVulnerabilities.length > 0) {
      console.log(`\n🟡 MEDIUM VULNERABILITIES:`);
      mediumVulnerabilities.forEach(vuln => {
        console.log(`   • ${vuln.description} (${vuln.endpoint})`);
        console.log(`     Evidence: ${vuln.evidence}`);
      });
    }
    
    if (lowVulnerabilities.length > 0) {
      console.log(`\n🔵 LOW VULNERABILITIES:`);
      lowVulnerabilities.forEach(vuln => {
        console.log(`   • ${vuln.description} (${vuln.endpoint})`);
        console.log(`     Evidence: ${vuln.evidence}`);
      });
    }
    
    // Overall risk assessment
    const overallRisk = criticalVulnerabilities.length > 0 ? 'CRITICAL' :
                       highVulnerabilities.length > 0 ? 'HIGH' :
                       mediumVulnerabilities.length > 0 ? 'MEDIUM' :
                       lowVulnerabilities.length > 0 ? 'LOW' : 'GOOD';
    
    console.log(`\n🎯 Overall Risk Level: ${overallRisk}`);
    
    if (overallRisk === 'GOOD') {
      console.log('   ✅ Good security posture! Continue monitoring.');
    } else {
      console.log(`   ⚠️  Action required to address ${overallRisk} risk level.`);
    }
    
    return {
      summary: {
        totalTests,
        passedTests,
        failedTests,
        vulnerabilities: {
          critical: criticalVulnerabilities.length,
          high: highVulnerabilities.length,
          medium: mediumVulnerabilities.length,
          low: lowVulnerabilities.length
        },
        overallRisk
      },
      results: this.results,
      vulnerabilities: {
        critical: criticalVulnerabilities,
        high: highVulnerabilities,
        medium: mediumVulnerabilities,
        low: lowVulnerabilities
      }
    };
  }
}

// Usage example
async function runSecurityHeadersTest() {
  const tester = new SecurityHeadersTester('https://your-secure-app.com');
  const report = await tester.testAllEndpoints();
  
  // Save report to file
  const fs = require('fs');
  fs.writeFileSync('security-headers-report.json', JSON.stringify(report, null, 2));
  
  return report;
}

// Export for use as module
module.exports = SecurityHeadersTester;
```

This comprehensive secure headers implementation provides:

1. **Framework-specific implementations** for Express.js, Flask, Nginx, and Apache
2. **Different security profiles** for various application types (API, admin, healthcare, public)
3. **Dynamic header configuration** based on request context
4. **Security testing and validation** tools
5. **Rate limiting and monitoring** integration
6. **Compliance-specific headers** for healthcare and other regulated industries

The implementation follows security best practices while maintaining operational flexibility and performance considerations.
