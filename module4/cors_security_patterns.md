# CORS Security Patterns


## Overview

This document demonstrates advanced CORS security patterns and configurations for various application architectures and threat scenarios.

## 1. Multi-Tenant CORS Architecture

```javascript
// Multi-tenant CORS implementation with database-driven validation
const express = require('express');
const mysql = require('mysql2/promise');

class MultiTenantCORSManager {
  constructor() {
    this.cache = new Map(); // Cache allowed origins
    this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
  }

  async validateTenantOrigin(origin, tenantId) {
    // Check cache first
    const cacheKey = `${tenantId}:${origin}`;
    if (this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      if (cached.expires > Date.now()) {
        return cached.allowed;
      } else {
        this.cache.delete(cacheKey);
      }
    }

    try {
      const connection = await this.getDbConnection();
      
      // Validate tenant exists and origin is allowed
      const [rows] = await connection.execute(`
        SELECT t.id, t.status, o.domain, o.is_active
        FROM tenants t
        JOIN tenant_origins o ON t.id = o.tenant_id
        WHERE t.id = ? AND o.domain = ? AND t.status = 'active'
      `, [tenantId, new URL(origin).hostname]);
      
      await connection.end();
      
      const allowed = rows.length > 0;
      
      // Cache result
      this.cache.set(cacheKey, {
        allowed,
        expires: Date.now() + this.cacheTimeout
      });
      
      return allowed;
    } catch (error) {
      console.error('Tenant origin validation error:', error);
      return false;
    }
  }

  async getTenantFromRequest(req) {
    // Extract tenant from subdomain, path, or header
    const host = req.get('Host');
    const subdomain = host.split('.')[0];
    
    // Check path-based tenant
    const pathParts = req.path.split('/');
    if (pathParts[1] === 'api' && pathParts[2]) {
      return pathParts[2]; // /api/{tenantId}/...
    }
    
    // Check subdomain-based tenant
    if (subdomain !== 'www' && subdomain !== 'api') {
      return subdomain;
    }
    
    // Check custom header
    const tenantHeader = req.get('X-Tenant-ID');
    if (tenantHeader) {
      return tenantHeader;
    }
    
    return null;
  }

  getMiddleware() {
    return async (req, res, next) => {
      const origin = req.get('Origin');
      
      if (!origin) {
        return next(); // No CORS check needed
      }

      try {
        const tenantId = await this.getTenantFromRequest(req);
        
        if (!tenantId) {
          return res.status(403).json({
            error: 'Tenant identification required'
          });
        }

        const isAllowed = await this.validateTenantOrigin(origin, tenantId);
        
        if (isAllowed) {
          // Set CORS headers for allowed tenant
          res.header('Access-Control-Allow-Origin', origin);
          res.header('Access-Control-Allow-Credentials', 'true');
          res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
          res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Tenant-ID');
          res.header('Access-Control-Max-Age', '3600');
          
          next();
        } else {
          // Log unauthorized CORS attempt
          this.logCorsViolation(req, origin, tenantId);
          
          res.status(403).json({
            error: 'Origin not allowed for this tenant'
          });
        }
      } catch (error) {
        console.error('CORS validation error:', error);
        res.status(500).json({
          error: 'CORS validation failed'
        });
      }
    };
  }

  logCorsViolation(req, origin, tenantId) {
    console.warn('CORS violation detected', {
      timestamp: new Date(),
      origin: origin,
      tenantId: tenantId,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path
    });
  }

  async getDbConnection() {
    return mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME
    });
  }
}

// Usage in Express app
const corsManager = new MultiTenantCORSManager();
app.use(corsManager.getMiddleware());
```

## 2. Conditional CORS with Authentication Context

```javascript
// CORS implementation that varies based on authentication status
const jwt = require('jsonwebtoken');

class AuthenticationAwareCORS {
  constructor() {
    this.publicEndpoints = new Set([
      '/api/health',
      '/api/status',
      '/api/public/'
    ]);
    
    this.restrictedEndpoints = new Set([
      '/api/admin/',
      '/api/internal/'
    ]);
  }

  getMiddleware() {
    return (req, res, next) => {
      const origin = req.get('Origin');
      
      if (!origin) {
        return next();
      }

      // Determine CORS policy based on authentication and endpoint
      const policy = this.determineCorsPolicy(req, origin);
      
      if (policy.allowed) {
        this.setCorsHeaders(res, origin, policy);
        next();
      } else {
        res.status(403).json({
          error: 'CORS policy violation',
          reason: policy.reason
        });
      }
    };
  }

  determineCorsPolicy(req, origin) {
    const isPublicEndpoint = this.isPublicEndpoint(req.path);
    const isRestrictedEndpoint = this.isRestrictedEndpoint(req.path);
    const hasValidAuth = this.hasValidAuthentication(req);
    
    // Public endpoints: Allow specific trusted origins
    if (isPublicEndpoint) {
      return {
        allowed: this.isTrustedPublicOrigin(origin),
        reason: isTrustedPublicOrigin(origin) ? null : 'untrusted_public_origin'
      };
    }
    
    // Restricted endpoints: Require authentication + specific origins
    if (isRestrictedEndpoint) {
      if (!hasValidAuth) {
        return {
          allowed: false,
          reason: 'authentication_required'
        };
      }
      
      return {
        allowed: this.isAdminOrigin(origin),
        reason: this.isAdminOrigin(origin) ? null : 'unauthorized_admin_origin'
      };
    }
    
    // Authenticated user endpoints: Allow authenticated user origins
    if (hasValidAuth) {
      return {
        allowed: this.isUserOrigin(origin, req.user),
        reason: this.isUserOrigin(origin, req.user) ? null : 'unauthorized_user_origin'
      };
    }
    
    // Default: deny
    return {
      allowed: false,
      reason: 'default_deny'
    };
  }

  isPublicEndpoint(path) {
    return Array.from(this.publicEndpoints).some(endpoint => 
      path.startsWith(endpoint)
    );
  }

  isRestrictedEndpoint(path) {
    return Array.from(this.restrictedEndpoints).some(endpoint => 
      path.startsWith(endpoint)
    );
  }

  hasValidAuthentication(req) {
    const token = req.get('Authorization')?.replace('Bearer ', '');
    if (!token) return false;
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      return true;
    } catch (error) {
      return false;
    }
  }

  isTrustedPublicOrigin(origin) {
    const trustedOrigins = [
      'https://help.example.com',
      'https://docs.example.com'
    ];
    
    return trustedOrigins.includes(origin);
  }

  isAdminOrigin(origin) {
    const adminOrigins = [
      'https://admin.example.com',
      'https://secure-admin.example.com'
    ];
    
    return adminOrigins.includes(origin);
  }

  isUserOrigin(origin, user) {
    // Allow user's registered origins
    return user.allowedOrigins?.includes(origin) || false;
  }

  setCorsHeaders(res, origin, policy) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Max-Age', '3600');
  }
}

// Usage
const authAwareCORS = new AuthenticationAwareCORS();
app.use(authAwareCORS.getMiddleware());
```

## 3. CORS with Rate Limiting and Threat Detection

```javascript
const redis = require('redis');
const rateLimit = require('express-rate-limit');

class ThreatAwareCORS {
  constructor() {
    this.redisClient = redis.createClient({
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_PORT
    });
    
    this.threatPatterns = [
      /.*\.tk$/, // Suspicious TLD
      /.*\.ml$/, // Suspicious TLD
      /\d+\.\d+\.\d+\.\d+/, // IP addresses as domain
      /.*\b(exploit|attack|hack|crack)\b.*/i, // Suspicious keywords
    ];
  }

  getMiddleware() {
    return async (req, res, next) => {
      const origin = req.get('Origin');
      
      if (!origin) {
        return next();
      }

      try {
        // Perform threat analysis
        const threatAnalysis = await this.analyzeThreatLevel(req, origin);
        
        if (threatAnalysis.block) {
          await this.logThreatAttempt(req, origin, threatAnalysis);
          return res.status(403).json({
            error: 'Request blocked by security policy',
            threatLevel: threatAnalysis.level
          });
        }
        
        // Apply dynamic rate limiting
        const rateLimitResult = await this.checkDynamicRateLimit(origin);
        
        if (!rateLimitResult.allowed) {
          return res.status(429).json({
            error: 'Too many requests',
            retryAfter: rateLimitResult.retryAfter
          });
        }
        
        // Set CORS headers with threat-aware configuration
        this.setThreatAwareCorsHeaders(res, origin, threatAnalysis);
        
        next();
      } catch (error) {
        console.error('Threat-aware CORS error:', error);
        res.status(500).json({ error: 'Security check failed' });
      }
    };
  }

  async analyzeThreatLevel(req, origin) {
    const originObj = new URL(origin);
    const domain = originObj.hostname.toLowerCase();
    
    let threatScore = 0;
    const indicators = [];
    
    // Check against threat patterns
    this.threatPatterns.forEach((pattern, index) => {
      if (pattern.test(domain)) {
        threatScore += (index + 1) * 10;
        indicators.push(`pattern_match_${index}`);
      }
    });
    
    // Check reputation score
    const reputation = await this.checkDomainReputation(domain);
    if (reputation.score < 50) {
      threatScore += 20;
      indicators.push('low_reputation');
    }
    
    // Check for rapid origin changes
    const originHistory = await this.getOriginHistory(req.ip);
    if (originHistory.differentOrigins > 10) {
      threatScore += 15;
      indicators.push('multiple_origins');
    }
    
    // Check geolocation anomalies
    const geoCheck = await this.checkGeolocation(domain);
    if (geoCheck.suspicious) {
      threatScore += 10;
      indicators.push('suspicious_geolocation');
    }
    
    return {
      block: threatScore > 70,
      level: threatScore > 70 ? 'high' : threatScore > 40 ? 'medium' : 'low',
      score: threatScore,
      indicators: indicators
    };
  }

  async checkDomainReputation(domain) {
    // This would integrate with a threat intelligence service
    // For demo purposes, return a mock score
    const score = Math.floor(Math.random() * 100);
    return { score, provider: 'mock_service' };
  }

  async getOriginHistory(ip) {
    const key = `origin_history:${ip}`;
    const history = await this.redisClient.get(key) || '[]';
    const origins = JSON.parse(history);
    
    return {
      total: origins.length,
      differentOrigins: new Set(origins).size
    };
  }

  async checkGeolocation(domain) {
    // This would integrate with geolocation services
    return { suspicious: false, country: 'US' };
  }

  async checkDynamicRateLimit(origin) {
    const key = `cors_rate_limit:${origin}`;
    const current = await this.redisClient.get(key);
    
    if (!current) {
      await this.redisClient.setex(key, 60, '1'); // 1 request per minute for new origins
      return { allowed: true, retryAfter: 0 };
    }
    
    const count = parseInt(current);
    
    if (count < 60) { // 60 requests per minute
      await this.redisClient.incr(key);
      return { allowed: true, retryAfter: 0 };
    }
    
    return { allowed: false, retryAfter: 60 };
  }

  async logThreatAttempt(req, origin, analysis) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      origin: origin,
      ip: req.ip,
      threatLevel: analysis.level,
      threatScore: analysis.score,
      indicators: analysis.indicators,
      userAgent: req.get('User-Agent'),
      path: req.path
    };
    
    console.warn('CORS threat attempt blocked', logEntry);
    
    // Store in Redis for analysis
    await this.redisClient.lpush('cors_threats', JSON.stringify(logEntry));
    await this.redisClient.ltrim('cors_threats', 0, 999); // Keep last 1000
    
    // Send alert if critical
    if (analysis.level === 'high') {
      await this.sendSecurityAlert(logEntry);
    }
  }

  async sendSecurityAlert(logEntry) {
    // Implementation would send alert to security team
    console.error('CRITICAL CORS THREAT BLOCKED:', logEntry);
  }

  setThreatAwareCorsHeaders(res, origin, threatAnalysis) {
    res.header('Access-Control-Allow-Origin', origin);
    
    // Adjust headers based on threat level
    if (threatAnalysis.level === 'low') {
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
      res.header('Access-Control-Max-Age', '86400'); // 24 hours
    } else if (threatAnalysis.level === 'medium') {
      res.header('Access-Control-Allow-Credentials', 'false');
      res.header('Access-Control-Allow-Methods', 'GET, POST');
      res.header('Access-Control-Max-Age', '3600'); // 1 hour
    } else {
      // High threat - minimal CORS support
      res.header('Access-Control-Allow-Credentials', 'false');
      res.header('Access-Control-Allow-Methods', 'GET');
      res.header('Access-Control-Max-Age', '300'); // 5 minutes
    }
    
    res.header('Access-Control-Allow-Headers', 'Content-Type');
  }
}

// Usage
const threatAwareCORS = new ThreatAwareCORS();
app.use(threatAwareCORS.getMiddleware());
```

## 4. CORS with Content Security Policy Integration

```javascript
const helmet = require('helmet');

class CSPIntegratedCORS {
  constructor() {
    // CORS configurations mapped to CSP policies
    this.corsCspMapping = {
      'healthcare': {
        cors: {
          origin: ['https://ehr.healthcare.org'],
          credentials: true
        },
        csp: {
          directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'", "https://ehr.healthcare.org"],
            imgSrc: ["'self'", "data:", "https:"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            frameSrc: ["'none'"]
          }
        }
      },
      'public': {
        cors: {
          origin: '*',
          credentials: false
        },
        csp: {
          directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            connectSrc: ["'self'"],
            imgSrc: ["'self'", "data:"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            frameSrc: ["'none'"]
          }
        }
      },
      'admin': {
        cors: {
          origin: ['https://admin.healthcare.org'],
          credentials: true
        },
        csp: {
          directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            connectSrc: ["'self'", "https://admin.healthcare.org"],
            imgSrc: ["'self'", "data:"],
            styleSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"]
          }
        }
      }
    };
  }

  getMiddleware() {
    return (req, res, next) => {
      const origin = req.get('Origin');
      
      if (!origin) {
        return next();
      }

      const policyType = this.determinePolicyType(req.path, origin);
      const policy = this.corsCspMapping[policyType];
      
      if (policy) {
        // Apply CORS headers
        this.applyCorsHeaders(res, origin, policy.cors);
        
        // Apply corresponding CSP headers
        this.applyCSPHeaders(res, policy.csp);
        
        next();
      } else {
        res.status(403).json({
          error: 'No security policy found for this resource'
        });
      }
    };
  }

  determinePolicyType(path, origin) {
    // Healthcare API endpoints
    if (path.startsWith('/api/healthcare/')) {
      return 'healthcare';
    }
    
    // Admin endpoints
    if (path.startsWith('/admin/') || 
        origin === 'https://admin.healthcare.org') {
      return 'admin';
    }
    
    // Public endpoints
    if (path.startsWith('/api/public/')) {
      return 'public';
    }
    
    // Default to public
    return 'public';
  }

  applyCorsHeaders(res, origin, corsConfig) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', corsConfig.methods || 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', corsConfig.allowedHeaders || 'Content-Type, Authorization');
    
    if (corsConfig.credentials) {
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Max-Age', '86400');
    } else {
      res.header('Access-Control-Allow-Credentials', 'false');
      res.header('Access-Control-Max-Age', '3600');
    }
  }

  applyCSPHeaders(res, cspConfig) {
    // Generate CSP header value
    const cspValue = this.generateCSPHeader(cspConfig.directives);
    
    res.header('Content-Security-Policy', cspValue);
    res.header('X-Content-Type-Options', 'nosniff');
    res.header('X-Frame-Options', 'DENY');
    res.header('X-XSS-Protection', '1; mode=block');
  }

  generateCSPHeader(directives) {
    return Object.entries(directives)
      .map(([directive, sources]) => {
        const sourceList = Array.isArray(sources) ? sources.join(' ') : sources;
        return `${directive} ${sourceList}`;
      })
      .join('; ');
  }
}

// Enhanced usage with helmet
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

const cspIntegratedCORS = new CSPIntegratedCORS();
app.use(cspIntegratedCORS.getMiddleware());
```

## 5. CORS Testing Framework

```javascript
class CORSTestingFramework {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.testResults = [];
  }

  async testAllScenarios() {
    const scenarios = [
      // Valid healthcare scenarios
      {
        name: 'Healthcare EHR Access',
        origin: 'https://ehr.hospital.org',
        headers: {
          'X-Facility-Code': 'HOSP001',
          'Authorization': 'Bearer valid_token'
        },
        expected: { allowOrigin: true, credentials: true }
      },
      
      // Public API scenarios
      {
        name: 'Public API Access',
        origin: 'https://public.healthapp.com',
        headers: {},
        expected: { allowOrigin: true, credentials: false }
      },
      
      // Admin access scenarios
      {
        name: 'Admin Dashboard Access',
        origin: 'https://admin.healthcare.org',
        headers: {
          'X-Admin-Token': 'valid_admin_token'
        },
        expected: { allowOrigin: true, credentials: true }
      },
      
      // Invalid scenarios
      {
        name: 'Unauthorized Origin',
        origin: 'https://malicious-site.com',
        headers: {},
        expected: { allowOrigin: false }
      },
      
      // Edge cases
      {
        name: 'No Origin Header',
        origin: null,
        headers: {},
        expected: { allowOrigin: true } // Allow non-browser clients
      }
    ];

    for (const scenario of scenarios) {
      const result = await this.testScenario(scenario);
      this.testResults.push(result);
    }

    return this.generateReport();
  }

  async testScenario(scenario) {
    const testUrl = `${this.baseUrl}/api/healthcare/patients/test`;
    
    const config = {
      method: 'GET',
      url: testUrl,
      validateStatus: () => true,
      headers: {}
    };

    if (scenario.origin) {
      config.headers['Origin'] = scenario.origin;
    }

    // Add additional headers
    Object.assign(config.headers, scenario.headers);

    try {
      const response = await axios(config);
      
      const result = {
        scenario: scenario.name,
        origin: scenario.origin,
        status: response.status,
        allowOrigin: response.headers['access-control-allow-origin'],
        allowCredentials: response.headers['access-control-allow-credentials'],
        allowMethods: response.headers['access-control-allow-methods'],
        allowHeaders: response.headers['access-control-allow-headers'],
        expected: scenario.expected,
        passed: false,
        issues: []
      };

      // Validate results
      if (scenario.expected.allowOrigin) {
        if (!result.allowOrigin) {
          result.issues.push('Expected origin to be allowed');
        } else {
          result.passed = true;
        }
      } else {
        if (result.allowOrigin) {
          result.issues.push('Expected origin to be blocked');
        } else {
          result.passed = true;
        }
      }

      if (scenario.expected.credentials !== undefined) {
        const actualCredentials = result.allowCredentials === 'true';
        if (actualCredentials !== scenario.expected.credentials) {
          result.issues.push(`Expected credentials: ${scenario.expected.credentials}, got: ${actualCredentials}`);
          result.passed = false;
        }
      }

      return result;
    } catch (error) {
      return {
        scenario: scenario.name,
        origin: scenario.origin,
        error: error.message,
        passed: false,
        issues: [`Request failed: ${error.message}`]
      };
    }
  }

  generateReport() {
    const total = this.testResults.length;
    const passed = this.testResults.filter(r => r.passed).length;
    const failed = total - passed;

    console.log('\n=== CORS Security Pattern Test Report ===');
    console.log(`Total tests: ${total}`);
    console.log(`Passed: ${passed} ✓`);
    console.log(`Failed: ${failed} ✗`);
    console.log(`Success rate: ${((passed / total) * 100).toFixed(1)}%`);

    console.log('\n=== Detailed Results ===');
    this.testResults.forEach((result, index) => {
      const status = result.passed ? '✓ PASS' : '✗ FAIL';
      console.log(`\n${index + 1}. ${status} - ${result.scenario}`);
      console.log(`   Origin: ${result.origin || 'null'}`);
      console.log(`   Status: ${result.status}`);
      
      if (result.allowOrigin) {
        console.log(`   Allowed Origin: ${result.allowOrigin}`);
        console.log(`   Credentials: ${result.allowCredentials}`);
      }
      
      if (result.issues.length > 0) {
        console.log(`   Issues:`);
        result.issues.forEach(issue => console.log(`     - ${issue}`));
      }
    });

    // Security recommendations
    console.log('\n=== Security Recommendations ===');
    if (failed > 0) {
      console.log('❌ Some security tests failed. Review CORS configuration.');
    }
    
    const unauthorizedPassed = this.testResults.find(r => 
      r.scenario === 'Unauthorized Origin' && r.passed
    );
    
    if (unauthorizedPassed) {
      console.log('✅ Unauthorized origins properly blocked.');
    } else {
      console.log('❌ Unauthorized origins may be allowed - security risk!');
    }

    return {
      summary: { total, passed, failed, successRate: (passed / total) * 100 },
      results: this.testResults,
      recommendations: this.generateRecommendations()
    };
  }

  generateRecommendations() {
    const recommendations = [];
    
    const failed = this.testResults.filter(r => !r.passed);
    if (failed.length > 0) {
      recommendations.push('Review and fix failed CORS tests');
    }
    
    const unauthorizedOrigin = this.testResults.find(r => 
      r.scenario === 'Unauthorized Origin'
    );
    
    if (!unauthorizedOrigin || !unauthorizedOrigin.passed) {
      recommendations.push('Implement stricter origin validation');
    }
    
    const noOrigin = this.testResults.find(r => r.scenario === 'No Origin Header');
    if (noOrigin && !noOrigin.passed) {
      recommendations.push('Allow non-browser clients that don\'t send Origin header');
    }
    
    return recommendations;
  }
}

// Export for testing
module.exports = CORSTestingFramework;

// Usage example
// const tester = new CORSTestingFramework('http://localhost:3000');
// const report = await tester.testAllScenarios();
```

## Summary

These CORS security patterns demonstrate:

1. **Multi-tenant architecture support** with database-driven origin validation
2. **Authentication-aware CORS** that adjusts policies based on user context
3. **Threat detection and response** with dynamic rate limiting
4. **Content Security Policy integration** for comprehensive web security
5. **Comprehensive testing framework** for validating CORS implementations

Each pattern addresses specific security challenges while maintaining operational flexibility and performance considerations.
