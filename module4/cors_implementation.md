# CORS Implementation Examples

**Author:** MiniMax Agent  
**Date:** 2025-11-15

## Overview

This document contains practical CORS implementation examples for different scenarios, demonstrating secure configurations and common patterns.

## 1. Basic CORS Configuration (Node.js/Express)

```javascript
const express = require('express');
const cors = require('cors');

const app = express();

// Option 1: Simple CORS configuration (not recommended for production)
app.use(cors()); // Allows all origins - SECURITY RISK

// Option 2: Restrictive CORS configuration (recommended)
const corsOptions = {
  origin: ['https://trusted-domain.com', 'https://admin.trusted-domain.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true, // Allow cookies
  maxAge: 86400 // Cache preflight for 24 hours
};

app.use(cors(corsOptions));

// Option 3: Dynamic CORS configuration
const corsOptionsDynamic = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'https://myapp.com',
      'https://admin.myapp.com',
      'https://partner.healthcare.org'
    ];
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true,
  maxAge: 86400
};

app.use(cors(corsOptionsDynamic));

app.get('/api/users', (req, res) => {
  res.json({ users: [] });
});

app.listen(3000);
```

## 2. CORS Configuration with Database-Driven Origin Validation

```javascript
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');

const app = express();

// Database connection for allowed origins
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: 'security_config'
};

// Dynamic CORS with database lookup
const corsOptionsDb = {
  origin: async function (origin, callback) {
    try {
      const connection = await mysql.createConnection(dbConfig);
      
      // Allow requests with no origin
      if (!origin) return callback(null, true);
      
      // Query database for allowed origins
      const [rows] = await connection.execute(
        'SELECT domain, is_active, max_age FROM allowed_origins WHERE is_active = 1'
      );
      
      await connection.end();
      
      const allowedOrigins = rows.map(row => row.domain);
      
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Origin not allowed by CORS policy'));
      }
    } catch (error) {
      console.error('CORS origin validation error:', error);
      callback(error);
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 3600 // 1 hour
};

app.use(cors(corsOptionsDb));
```

## 3. CORS Implementation with Security Headers

```javascript
const helmet = require('helmet');
const express = require('express');

const app = express();

// Security headers configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

// CORS with additional security
const secureCorsOptions = {
  origin: function (origin, callback) {
    const allowedDomains = [
      'https://healthcare-portal.com',
      'https://mobile.healthcare-portal.com'
    ];
    
    if (!origin || allowedDomains.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Cross-origin requests not allowed'));
    }
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  credentials: true,
  maxAge: 86400
};

app.use(cors(secureCorsOptions));

// Additional security middleware
app.use((req, res, next) => {
  // Remove server information
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  
  // Set security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  next();
});
```

## 4. CORS for Healthcare API (HIPAA Compliant)

```javascript
const express = require('express');
const rateLimit = require('express-rate-limit');
const auditLogger = require('./audit-logger');

const app = express();

// Rate limiting for CORS violations
const corsViolationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 CORS requests per windowMs
  message: 'Too many CORS requests from this IP',
  standardHeaders: true,
  legacyHeaders: false
});

// Healthcare-specific CORS configuration
const healthcareCorsOptions = {
  origin: async function (origin, callback) {
    // Audit CORS attempt
    auditLogger.log({
      event: 'cors_origin_check',
      origin: origin,
      timestamp: new Date(),
      ip: this.request?.ip
    });
    
    // Strict origin validation for healthcare data
    const allowedOrigins = [
      'https://ehr.hospital.org',
      'https://portal.healthsystem.com',
      'https://mobile.healthapp.com'
    ];
    
    // Additional validation for partner organizations
    if (origin) {
      const domain = new URL(origin).hostname;
      const [rows] = await db.execute(
        'SELECT partner_id, verification_status FROM trusted_partners WHERE domain = ?',
        [domain]
      );
      
      if (rows.length > 0 && rows[0].verification_status === 'verified') {
        callback(null, true);
      } else {
        auditLogger.log({
          event: 'cors_origin_rejected',
          origin: origin,
          partner_id: rows[0]?.partner_id,
          reason: 'unverified_domain'
        });
        callback(new Error('Healthcare data access requires verified partner domain'));
      }
    } else {
      callback(null, true); // Allow non-browser clients
    }
  },
  methods: ['GET', 'POST', 'PUT'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Patient-ID',
    'X-Facility-Code'
  ],
  credentials: true,
  maxAge: 1800 // 30 minutes for healthcare data
};

// Apply CORS with monitoring
app.use('/api/healthcare/', cors(healthcareCorsOptions), corsViolationLimiter);

// Healthcare API endpoints
app.get('/api/healthcare/patients/:id', authenticateHealthcareUser, (req, res) => {
  const patientId = req.params.id;
  const facilityCode = req.headers['x-facility-code'];
  
  // Log patient data access
  auditLogger.log({
    event: 'patient_data_access',
    patient_id: patientId,
    facility_code: facilityCode,
    user_id: req.user.id,
    timestamp: new Date()
  });
  
  // Return patient data
  res.json({
    patient: { id: patientId, name: 'John Doe' },
    access_logged: true
  });
});
```

## 5. CORS Preflight Request Handling

```javascript
const express = require('express');

const app = express();

// Custom preflight handler
app.options('*', (req, res) => {
  const origin = req.headers.origin;
  const method = req.headers['access-control-request-method'];
  const headers = req.headers['access-control-request-headers'];
  
  // Log preflight requests for monitoring
  console.log('Preflight request:', {
    origin: origin,
    method: method,
    headers: headers,
    timestamp: new Date()
  });
  
  // Set CORS headers for preflight
  res.header('Access-Control-Allow-Origin', origin);
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', headers);
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Max-Age', '86400');
  
  res.status(204).send();
});

// CORS configuration for complex scenarios
const complexCorsOptions = {
  origin: function(origin, callback) {
    // Allow localhost for development
    if (process.env.NODE_ENV === 'development' && !origin) {
      return callback(null, true);
    }
    
    const allowedOrigins = [
      'https://app.example.com',
      'https://admin.example.com'
    ];
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Custom-Header',
    'Accept'
  ],
  credentials: true,
  maxAge: 3600
};

app.use(cors(complexCorsOptions));
```

## 6. CORS Testing and Validation Script

```javascript
const axios = require('axios');

class CORSTester {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.results = [];
  }

  async testCORS(origin, method = 'GET', headers = {}) {
    const testUrl = `${this.baseUrl}/api/test`;
    
    try {
      const response = await axios({
        method: method,
        url: testUrl,
        headers: {
          'Origin': origin,
          ...headers
        },
        validateStatus: () => true // Don't throw on error status codes
      });
      
      const result = {
        origin: origin,
        method: method,
        status: response.status,
        allowOrigin: response.headers['access-control-allow-origin'],
        allowMethods: response.headers['access-control-allow-methods'],
        allowHeaders: response.headers['access-control-allow-headers'],
        allowCredentials: response.headers['access-control-allow-credentials'],
        passed: false
      };
      
      // Check if CORS headers are present
      if (response.headers['access-control-allow-origin']) {
        if (response.headers['access-control-allow-origin'] === origin ||
            response.headers['access-control-allow-origin'] === '*') {
          result.passed = true;
        }
      }
      
      this.results.push(result);
      return result;
    } catch (error) {
      console.error(`CORS test failed for ${origin}:`, error.message);
      return {
        origin: origin,
        method: method,
        error: error.message,
        passed: false
      };
    }
  }

  async runAllTests() {
    const testCases = [
      // Valid origins
      ['https://trusted-domain.com', 'GET'],
      ['https://admin.trusted-domain.com', 'POST'],
      
      // Invalid origins
      ['https://malicious-site.com', 'GET'],
      ['https://phishing-site.org', 'POST'],
      
      // Edge cases
      [null, 'GET'], // No origin
      ['http://localhost:3000', 'GET'] // Local development
    ];

    for (const [origin, method] of testCases) {
      await this.testCORS(origin, method);
      await new Promise(resolve => setTimeout(resolve, 100)); // Rate limiting
    }
    
    return this.results;
  }

  generateReport() {
    const total = this.results.length;
    const passed = this.results.filter(r => r.passed).length;
    const failed = total - passed;
    
    console.log('\n=== CORS Test Report ===');
    console.log(`Total tests: ${total}`);
    console.log(`Passed: ${passed}`);
    console.log(`Failed: ${failed}`);
    
    console.log('\nDetailed Results:');
    this.results.forEach(result => {
      const status = result.passed ? '✓ PASS' : '✗ FAIL';
      console.log(`${status} - ${result.origin || 'null'} (${result.method})`);
      if (result.error) {
        console.log(`  Error: ${result.error}`);
      }
    });
    
    return {
      summary: { total, passed, failed },
      results: this.results
    };
  }
}

// Usage example
async function runCORSTests() {
  const tester = new CORSTester('http://localhost:3000');
  await tester.runAllTests();
  const report = tester.generateReport();
  
  // Save report to file
  const fs = require('fs');
  fs.writeFileSync('cors-test-report.json', JSON.stringify(report, null, 2));
}

// Uncomment to run tests
// runCORSTests();
```

## 7. CORS Security Monitoring

```javascript
const winston = require('winston');
const express = require('express');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'cors-audit.log' }),
    new winston.transports.Console()
  ]
});

class CORSSecurityMonitor {
  static logCorsRequest(req, origin, isAllowed) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      origin: origin,
      url: req.originalUrl,
      method: req.method,
      isAllowed: isAllowed,
      headers: {
        origin: req.get('Origin'),
        referer: req.get('Referer')
      }
    };
    
    if (!isAllowed) {
      logger.warn('CORS request blocked', logEntry);
      this.alertOnBlockedRequest(logEntry);
    } else {
      logger.info('CORS request allowed', logEntry);
    }
  }
  
  static async alertOnBlockedRequest(logEntry) {
    // Alert on multiple blocked requests from same origin
    const recentBlocks = await this.getRecentBlocks(logEntry.origin);
    
    if (recentBlocks.length > 10) {
      logger.error('Multiple CORS blocks detected', {
        origin: logEntry.origin,
        blockCount: recentBlocks.length,
        timeWindow: '1 hour'
      });
      
      // Send alert to security team
      await this.sendSecurityAlert(logEntry.origin, recentBlocks.length);
    }
  }
  
  static async getRecentBlocks(origin) {
    // Implementation would query recent blocks from database
    return [];
  }
  
  static async sendSecurityAlert(origin, count) {
    // Implementation would send alert via email, Slack, etc.
    console.log(`SECURITY ALERT: ${count} CORS blocks from ${origin}`);
  }
}

// Integration with Express
app.use((req, res, next) => {
  const origin = req.get('Origin');
  if (origin) {
    res.on('finish', () => {
      const isAllowed = res.getHeader('Access-Control-Allow-Origin') !== undefined;
      CORSSecurityMonitor.logCorsRequest(req, origin, isAllowed);
    });
  }
  next();
});
```

## Best Practices Summary

1. **Always validate origins dynamically** in production environments
2. **Never use wildcards (*) with credentials enabled**
3. **Log CORS violations for security monitoring**
4. **Use rate limiting for CORS endpoints**
5. **Implement database-driven origin management for multi-tenant applications**
6. **Regular security audits of CORS configuration**
7. **Monitor and alert on suspicious CORS patterns**

## Common Pitfalls

1. **Using wildcard origins with credentials**
2. **Not handling preflight requests properly**
3. **Insufficient logging of CORS violations**
4. **Hardcoding allowed origins in code**
5. **Not considering subdomains and variations**
6. **Overly permissive CORS configurations**
7. **Not implementing CORS monitoring and alerting**

This implementation guide provides practical examples for securing CORS configurations across different application scenarios while maintaining proper security controls.
