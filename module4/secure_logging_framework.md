# Secure Logging Framework Implementation


## Overview

This document provides a comprehensive secure logging framework that implements structured logging, security event monitoring, and compliance requirements while protecting sensitive information.

## 1. Basic Structured Logging Framework

```javascript
const winston = require('winston');
const crypto = require('crypto');
const path = require('path');

class SecureLogger {
  constructor(options = {}) {
    this.options = {
      serviceName: options.serviceName || 'application',
      environment: options.environment || 'development',
      logLevel: options.logLevel || 'info',
      sensitiveFields: options.sensitiveFields || [
        'password', 'apiKey', 'secret', 'token', 'credential',
        'ssn', 'socialSecurityNumber', 'creditCard', 'cvv',
        'bankAccount', 'routingNumber'
      ],
      hashAlgorithm: options.hashAlgorithm || 'sha256',
      ...options
    };
    
    this.requestId = crypto.randomBytes(8).toString('hex');
    this.correlationId = null;
    this.auditLog = [];
    
    this.setupLogger();
  }

  setupLogger() {
    // Define log formats
    this.consoleFormat = winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json(),
      winston.format.colorize({ all: true })
    );

    this.fileFormat = winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    );

    // Create logger configuration
    const transports = [];

    // Console transport
    if (this.options.enableConsole !== false) {
      transports.push(
        new winston.transports.Console({
          level: this.options.logLevel,
          format: this.consoleFormat
        })
      );
    }

    // File transports
    if (this.options.enableFile !== false) {
      // Application logs
      transports.push(
        new winston.transports.File({
          filename: path.join('logs', 'application.log'),
          level: this.options.logLevel,
          format: this.fileFormat,
          maxsize: 5242880, // 5MB
          maxFiles: 10
        })
      );

      // Error logs
      transports.push(
        new winston.transports.File({
          filename: path.join('logs', 'error.log'),
          level: 'error',
          format: this.fileFormat,
          maxsize: 5242880, // 5MB
          maxFiles: 5
        })
      );

      // Security logs (separate from application logs)
      if (this.options.enableSecurityLogs !== false) {
        transports.push(
          new winston.transports.File({
            filename: path.join('logs', 'security.log'),
            level: 'info',
            format: this.fileFormat,
            maxsize: 5242880, // 5MB
            maxFiles: 20 // Keep more security logs
          })
        );
      }

      // Audit logs for compliance
      if (this.options.enableAuditLogs !== false) {
        transports.push(
          new winston.transports.File({
            filename: path.join('logs', 'audit.log'),
            level: 'info',
            format: this.fileFormat,
            maxsize: 10485760, // 10MB
            maxFiles: 50 // Keep audit logs longer
          })
        );
      }
    }

    // Create logger
    this.logger = winston.createLogger({
      level: this.options.logLevel,
      format: this.fileFormat,
      transports: transports,
      exitOnError: false
    });

    // Add custom log levels for security
    this.logger.addLevels({
      critical: 0,
      alert: 1,
      security: 2,
      audit: 3,
      warn: 4,
      info: 5,
      debug: 6
    });
  }

  // Set correlation ID for request tracing
  setCorrelationId(correlationId) {
    this.correlationId = correlationId;
  }

  // Generate request ID if not set
  generateRequestId() {
    this.requestId = crypto.randomBytes(8).toString('hex');
    return this.requestId;
  }

  // Sanitize sensitive data from objects
  sanitizeData(obj) {
    if (!obj || typeof obj !== 'object') {
      return obj;
    }

    const sanitized = { ...obj };

    this.options.sensitiveFields.forEach(field => {
      if (sanitized.hasOwnProperty(field)) {
        // Hash the sensitive value instead of storing it
        sanitized[field] = this.hashValue(sanitized[field]);
        sanitized[`${field}_redacted`] = true;
      }
    });

    // Recursively sanitize nested objects
    Object.keys(sanitized).forEach(key => {
      if (typeof sanitized[key] === 'object' && sanitized[key] !== null) {
        sanitized[key] = this.sanitizeData(sanitized[key]);
      }
    });

    return sanitized;
  }

  // Hash sensitive values
  hashValue(value) {
    if (!value) return '';
    return crypto.createHash(this.options.hashAlgorithm)
      .update(String(value))
      .digest('hex');
  }

  // Base logging method
  log(level, message, data = {}, options = {}) {
    const sanitizedData = this.sanitizeData(data);
    
    const logEntry = {
      timestamp: new Date().toISOString(),
      level: level,
      message: message,
      service: this.options.serviceName,
      environment: this.options.environment,
      requestId: this.requestId,
      correlationId: this.correlationId,
      ...sanitizedData,
      ...options
    };

    this.logger.log(level, logEntry);
    return logEntry;
  }

  // Convenience methods for different log levels
  critical(message, data = {}, options = {}) {
    return this.log('critical', message, data, options);
  }

  alert(message, data = {}, options = {}) {
    return this.log('alert', message, data, options);
  }

  security(message, data = {}, options = {}) {
    return this.log('security', message, data, options);
  }

  audit(message, data = {}, options = {}) {
    return this.log('audit', message, data, options);
  }

  warn(message, data = {}, options = {}) {
    return this.log('warn', message, data, options);
  }

  info(message, data = {}, options = {}) {
    return this.log('info', message, data, options);
  }

  debug(message, data = {}, options = {}) {
    return this.log('debug', message, data, options);
  }

  // Security-specific logging methods
  logAuthAttempt(username, success, details = {}) {
    const sanitizedUsername = this.hashValue(username);
    
    return this.security('Authentication attempt', {
      username: sanitizedUsername,
      username_redacted: true,
      success: success,
      ip: details.ip,
      userAgent: details.userAgent,
      userId: details.userId,
      timestamp: details.timestamp
    });
  }

  logDataAccess(operation, resource, userId, details = {}) {
    return this.audit('Data access', {
      operation: operation, // read, write, delete, update
      resource: resource,
      userId: userId,
      ip: details.ip,
      userAgent: details.userAgent,
      dataSize: details.dataSize,
      success: details.success !== false,
      timestamp: details.timestamp
    });
  }

  logSecurityEvent(eventType, severity, details = {}) {
    return this.security('Security event', {
      eventType: eventType,
      severity: severity, // low, medium, high, critical
      ip: details.ip,
      userAgent: details.userAgent,
      userId: details.userId,
      resource: details.resource,
      action: details.action,
      result: details.result,
      timestamp: details.timestamp
    });
  }

  logComplianceEvent(eventType, regulation, details = {}) {
    return this.audit('Compliance event', {
      eventType: eventType,
      regulation: regulation, // GDPR, HIPAA, PCI DSS, etc.
      userId: details.userId,
      dataSubject: details.dataSubject,
      action: details.action,
      legalBasis: details.legalBasis,
      timestamp: details.timestamp
    });
  }

  logError(error, context = {}) {
    const errorData = {
      error: {
        message: error.message,
        stack: error.stack,
        code: error.code,
        name: error.name
      },
      context: this.sanitizeData(context),
      severity: 'high'
    };

    return this.error('Application error', errorData);
  }

  // Request logging middleware
  getRequestLoggerMiddleware() {
    return (req, res, next) => {
      const startTime = Date.now();
      
      // Generate or use existing request ID
      req.requestId = this.generateRequestId();
      this.setCorrelationId(req.headers['x-correlation-id'] || req.requestId);

      // Log request
      this.info('HTTP request received', {
        method: req.method,
        url: req.url,
        path: req.path,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        headers: this.sanitizeData(req.headers),
        query: this.sanitizeData(req.query),
        body: this.sanitizeData(req.body),
        requestId: req.requestId,
        correlationId: this.correlationId
      });

      // Override res.json to log response
      const originalJson = res.json;
      res.json = function(data) {
        const duration = Date.now() - startTime;
        
        this.info('HTTP request completed', {
          method: req.method,
          url: req.url,
          path: req.path,
          statusCode: res.statusCode,
          duration: duration,
          responseSize: JSON.stringify(data).length,
          requestId: req.requestId,
          correlationId: this.correlationId
        });

        return originalJson.call(this, data);
      }.bind(this);

      next();
    };
  }

  // Error handling middleware
  getErrorLoggerMiddleware() {
    return (error, req, res, next) => {
      const errorData = {
        error: {
          message: error.message,
          stack: error.stack,
          code: error.code,
          name: error.name
        },
        request: {
          method: req.method,
          url: req.url,
          path: req.path,
          headers: this.sanitizeData(req.headers),
          body: this.sanitizeData(req.body),
          query: this.sanitizeData(req.query),
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          requestId: req.requestId,
          correlationId: this.correlationId
        }
      };

      this.error('Unhandled error', errorData);
      next(error);
    };
  }

  // Performance logging
  logPerformance(operation, duration, details = {}) {
    const severity = duration > 5000 ? 'warn' : 
                   duration > 1000 ? 'info' : 'debug';

    return this.log(severity, 'Performance metric', {
      operation: operation,
      duration: duration,
      ...details,
      timestamp: details.timestamp || new Date().toISOString()
    });
  }

  // Get audit trail for compliance reporting
  getAuditTrail(filters = {}) {
    // This would typically query a database or log aggregation system
    // For demo purposes, return recent audit entries
    return this.auditLog.filter(entry => {
      if (filters.userId && entry.userId !== filters.userId) return false;
      if (filters.startDate && new Date(entry.timestamp) < new Date(filters.startDate)) return false;
      if (filters.endDate && new Date(entry.timestamp) > new Date(filters.endDate)) return false;
      if (filters.eventType && entry.eventType !== filters.eventType) return false;
      return true;
    });
  }

  // Health check for logging system
  checkHealth() {
    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: this.options.serviceName,
      checks: {}
    };

    // Check if logger is working
    try {
      this.info('Health check', { check: 'logger_functionality' });
      health.checks.logger = 'healthy';
    } catch (error) {
      health.status = 'unhealthy';
      health.checks.logger = `error: ${error.message}`;
    }

    // Check disk space for file logging
    if (this.options.enableFile !== false) {
      // This would check actual disk space
      health.checks.diskSpace = 'healthy'; // Placeholder
    }

    return health;
  }
}

// Export for use
module.exports = SecureLogger;

// Usage examples
const logger = new SecureLogger({
  serviceName: 'healthcare-api',
  environment: 'production',
  logLevel: 'info',
  enableConsole: true,
  enableFile: true,
  enableSecurityLogs: true,
  enableAuditLogs: true
});

// Use as middleware
// app.use(logger.getRequestLoggerMiddleware());
// app.use(logger.getErrorLoggerMiddleware());

// Log security events
logger.logAuthAttempt('user@example.com', false, {
  ip: '192.168.1.100',
  userAgent: 'Mozilla/5.0...',
  timestamp: new Date()
});

// Log data access
logger.logDataAccess('read', 'patient_records', 'usr_123', {
  ip: '192.168.1.100',
  dataSize: 1024,
  success: true,
  timestamp: new Date()
});

// Log performance
logger.logPerformance('database_query', 1500, {
  query: 'SELECT * FROM patients',
  recordsAffected: 100
});

console.log('Secure logging framework initialized');
```

## 2. Advanced Security Event Logging

```javascript
const EventEmitter = require('events');
const fs = require('fs').promises;
const path = require('path');

class SecurityEventLogger extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      logDirectory: options.logDirectory || './security-logs',
      retentionDays: options.retentionDays || 90,
      alertThresholds: {
        failedLogins: 5,
        suspiciousRequests: 10,
        dataExports: 1
      },
      ...options
    };
    
    this.eventCounts = new Map();
    this.alertQueue = [];
    
    this.setupDirectories();
    this.setupEventHandlers();
  }

  async setupDirectories() {
    try {
      await fs.mkdir(this.options.logDirectory, { recursive: true });
    } catch (error) {
      console.error('Failed to create log directory:', error);
    }
  }

  setupEventHandlers() {
    this.on('authentication_failure', this.handleAuthFailure.bind(this));
    this.on('authorization_denied', this.handleAuthDenied.bind(this));
    this.on('data_access', this.handleDataAccess.bind(this));
    this.on('suspicious_activity', this.handleSuspiciousActivity.bind(this));
    this.on('security_violation', this.handleSecurityViolation.bind(this));
  }

  // Authentication event handlers
  async handleAuthFailure(event) {
    await this.logSecurityEvent({
      eventType: 'AUTHENTICATION_FAILURE',
      severity: this.calculateSeverity('auth_failure', event),
      details: {
        username: event.username,
        ip: event.ip,
        userAgent: event.userAgent,
        attemptCount: event.attemptCount,
        timestamp: event.timestamp
      }
    });

    // Check threshold for alerting
    const count = this.incrementEventCount('auth_failure', event.ip);
    if (count >= this.options.alertThresholds.failedLogins) {
      await this.triggerAlert('EXCESSIVE_AUTHENTICATION_FAILURES', {
        ip: event.ip,
        count: count,
        username: event.username
      });
    }
  }

  async handleAuthDenied(event) {
    await this.logSecurityEvent({
      eventType: 'AUTHORIZATION_DENIED',
      severity: 'medium',
      details: {
        userId: event.userId,
        resource: event.resource,
        action: event.action,
        ip: event.ip,
        userAgent: event.userAgent,
        timestamp: event.timestamp
      }
    });
  }

  // Data access event handlers
  async handleDataAccess(event) {
    const severity = this.calculateDataAccessSeverity(event);
    
    await this.logSecurityEvent({
      eventType: 'DATA_ACCESS',
      severity: severity,
      details: {
        userId: event.userId,
        resource: event.resource,
        action: event.action,
        dataType: event.dataType,
        recordCount: event.recordCount,
        ip: event.ip,
        userAgent: event.userAgent,
        success: event.success,
        timestamp: event.timestamp
      }
    });

    // Check for suspicious data access patterns
    if (event.action === 'export' && event.recordCount > 1000) {
      this.emit('suspicious_activity', {
        type: 'large_data_export',
        userId: event.userId,
        resource: event.resource,
        recordCount: event.recordCount,
        timestamp: event.timestamp
      });
    }
  }

  // Suspicious activity handlers
  async handleSuspiciousActivity(event) {
    await this.logSecurityEvent({
      eventType: 'SUSPICIOUS_ACTIVITY',
      severity: 'high',
      details: {
        activityType: event.type,
        userId: event.userId,
        ip: event.ip,
        userAgent: event.userAgent,
        metadata: event.metadata,
        timestamp: event.timestamp
      }
    });

    const count = this.incrementEventCount('suspicious_activity', event.ip);
    if (count >= this.options.alertThresholds.suspiciousRequests) {
      await this.triggerAlert('EXCESSIVE_SUSPICIOUS_ACTIVITY', {
        ip: event.ip,
        count: count,
        activityType: event.type
      });
    }
  }

  // Security violation handlers
  async handleSecurityViolation(event) {
    await this.logSecurityEvent({
      eventType: 'SECURITY_VIOLATION',
      severity: 'critical',
      details: {
        violationType: event.type,
        userId: event.userId,
        ip: event.ip,
        userAgent: event.userAgent,
        description: event.description,
        timestamp: event.timestamp
      }
    });

    // Immediate alert for security violations
    await this.triggerAlert('SECURITY_VIOLATION_DETECTED', {
      violationType: event.type,
      ip: event.ip,
      userId: event.userId
    });
  }

  // Main logging method
  async logSecurityEvent(event) {
    const logEntry = {
      eventId: this.generateEventId(),
      timestamp: new Date().toISOString(),
      ...event,
      processedAt: new Date().toISOString()
    };

    // Write to security log file
    const logFile = path.join(
      this.options.logDirectory,
      `security-${new Date().toISOString().split('T')[0]}.log`
    );

    const logLine = JSON.stringify(logEntry) + '\n';
    
    try {
      await fs.appendFile(logFile, logLine, 'utf8');
    } catch (error) {
      console.error('Failed to write security log:', error);
    }

    // Emit event for further processing
    this.emit(event.eventType, event);
    
    return logEntry;
  }

  // Helper methods
  calculateSeverity(eventType, event) {
    // Calculate severity based on event type and context
    switch (eventType) {
      case 'auth_failure':
        return event.attemptCount > 3 ? 'high' : 'medium';
      case 'data_access':
        return this.calculateDataAccessSeverity(event);
      default:
        return 'medium';
    }
  }

  calculateDataAccessSeverity(event) {
    if (event.dataType === 'pii' || event.dataType === 'financial') {
      if (event.recordCount > 100) return 'high';
      if (event.recordCount > 10) return 'medium';
      return 'low';
    }
    
    if (event.action === 'delete' || event.action === 'export') {
      return 'medium';
    }
    
    return 'low';
  }

  incrementEventCount(eventType, identifier) {
    const key = `${eventType}:${identifier}`;
    const current = this.eventCounts.get(key) || 0;
    const newCount = current + 1;
    this.eventCounts.set(key, newCount);
    
    // Clean up old counts periodically
    if (this.eventCounts.size > 10000) {
      this.cleanupEventCounts();
    }
    
    return newCount;
  }

  cleanupEventCounts() {
    const now = Date.now();
    const keysToDelete = [];
    
    for (const [key, count] of this.eventCounts) {
      // Remove entries older than 1 hour
      if (count < now - 3600000) {
        keysToDelete.push(key);
      }
    }
    
    keysToDelete.forEach(key => this.eventCounts.delete(key));
  }

  async triggerAlert(alertType, details) {
    const alert = {
      alertId: this.generateEventId(),
      alertType: alertType,
      timestamp: new Date().toISOString(),
      details: details,
      acknowledged: false
    };

    this.alertQueue.push(alert);
    
    // Log the alert
    console.warn(`🚨 SECURITY ALERT: ${alertType}`, details);
    
    // In a real implementation, this would send notifications
    // await this.sendAlertNotifications(alert);
    
    return alert;
  }

  generateEventId() {
    return require('crypto').randomBytes(12).toString('hex');
  }

  // Public methods for emitting events
  logAuthenticationFailure(username, ip, userAgent, attemptCount = 1) {
    this.emit('authentication_failure', {
      username,
      ip,
      userAgent,
      attemptCount,
      timestamp: new Date().toISOString()
    });
  }

  logAuthorizationDenied(userId, resource, action, ip, userAgent) {
    this.emit('authorization_denied', {
      userId,
      resource,
      action,
      ip,
      userAgent,
      timestamp: new Date().toISOString()
    });
  }

  logDataAccess(userId, resource, action, dataType, recordCount, success, ip, userAgent) {
    this.emit('data_access', {
      userId,
      resource,
      action,
      dataType,
      recordCount,
      success,
      ip,
      userAgent,
      timestamp: new Date().toISOString()
    });
  }

  logSuspiciousActivity(type, userId, ip, userAgent, metadata = {}) {
    this.emit('suspicious_activity', {
      type,
      userId,
      ip,
      userAgent,
      metadata,
      timestamp: new Date().toISOString()
    });
  }

  logSecurityViolation(type, userId, ip, userAgent, description) {
    this.emit('security_violation', {
      type,
      userId,
      ip,
      userAgent,
      description,
      timestamp: new Date().toISOString()
    });
  }

  // Get security metrics and reports
  async getSecurityMetrics(timeRange = '24h') {
    // This would typically aggregate data from log files or database
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - this.parseTimeRange(timeRange));
    
    return {
      timeRange: timeRange,
      startTime: startTime.toISOString(),
      endTime: endTime.toISOString(),
      metrics: {
        totalEvents: 0,
        authFailures: 0,
        dataAccessEvents: 0,
        suspiciousActivities: 0,
        securityViolations: 0,
        topIPs: [],
        topUsers: []
      }
    };
  }

  parseTimeRange(timeRange) {
    const match = timeRange.match(/(\d+)([hdwm])/);
    if (!match) return 24 * 60 * 60 * 1000; // Default to 24h
    
    const value = parseInt(match[1]);
    const unit = match[2];
    
    switch (unit) {
      case 'h': return value * 60 * 60 * 1000;
      case 'd': return value * 24 * 60 * 60 * 1000;
      case 'w': return value * 7 * 24 * 60 * 60 * 1000;
      case 'm': return value * 30 * 24 * 60 * 60 * 1000;
      default: return 24 * 60 * 60 * 1000;
    }
  }
}

// Usage example
const securityLogger = new SecurityLogger({
  logDirectory: './security-logs',
  retentionDays: 90,
  alertThresholds: {
    failedLogins: 3,
    suspiciousRequests: 5,
    dataExports: 1
  }
});

// Log security events
securityLogger.logAuthenticationFailure('user@example.com', '192.168.1.100', 'Mozilla/5.0...', 1);
securityLogger.logDataAccess('usr_123', 'patient_records', 'read', 'pii', 5, true, '192.168.1.100', 'Mozilla/5.0...');
securityLogger.logSuspiciousActivity('rapid_data_access', 'usr_123', '192.168.1.100', 'Mozilla/5.0...', { 
  accessPattern: 'unusual_volume' 
});

module.exports = SecurityEventLogger;
```

## 3. Compliance Logging for Healthcare (HIPAA)

```javascript
class HIPAALogger extends SecureLogger {
  constructor(options = {}) {
    super({
      ...options,
      serviceName: options.serviceName || 'hipaa-compliant-app',
      enableAuditLogs: true,
      retentionDays: options.retentionDays || 2555, // 7 years for HIPAA
      sensitiveFields: [
        ...options.sensitiveFields || [],
        'ssn', 'socialSecurityNumber', 'medicalRecordNumber', 'patientId',
        'diagnosis', 'medication', 'treatment', 'insuranceNumber',
        'bloodType', 'geneticInformation', 'mentalHealth', 'substanceAbuse'
      ]
    });
    
    this.hipaaEvents = [];
    this.patientAccessLog = new Map();
  }

  // HIPAA-specific logging methods
  logPatientDataAccess(patientId, userId, action, details = {}) {
    const event = {
      eventType: 'PATIENT_DATA_ACCESS',
      hipaaCategory: 'access',
      patientId: this.hashValue(patientId),
      userId: userId,
      action: action, // view, edit, delete, export
      timestamp: new Date().toISOString(),
      details: this.sanitizeHIPAAData(details)
    };

    // Log to audit trail
    this.audit('Patient data accessed', event);
    
    // Track patient access for minimum necessary analysis
    this.trackPatientAccess(patientId, userId, action);
    
    return event;
  }

  logPHIAccess(patientId, phiType, userId, details = {}) {
    const event = {
      eventType: 'PHI_ACCESS',
      hipaaCategory: 'phi_access',
      patientId: this.hashValue(patientId),
      phiType: phiType, // demographic, medical, billing, etc.
      userId: userId,
      timestamp: new Date().toISOString(),
      details: this.sanitizeHIPAAData(details)
    };

    this.audit('Protected Health Information accessed', event);
    return event;
  }

  logDisclosure(patientId, disclosedTo, purpose, userId, details = {}) {
    const event = {
      eventType: 'PHI_DISCLOSURE',
      hipaaCategory: 'disclosure',
      patientId: this.hashValue(patientId),
      disclosedTo: this.hashValue(disclosedTo),
      purpose: purpose,
      userId: userId,
      timestamp: new Date().toISOString(),
      details: this.sanitizeHIPAAData(details)
    };

    this.audit('PHI disclosure made', event);
    return event;
  }

  logMinimumNecessary(patientId, userId, requestedData, approvedData) {
    const event = {
      eventType: 'MINIMUM_NECESSARY',
      hipaaCategory: 'access_control',
      patientId: this.hashValue(patientId),
      userId: userId,
      requestedData: requestedData,
      approvedData: approvedData,
      reduction: approvedData.length / requestedData.length,
      timestamp: new Date().toISOString()
    };

    this.audit('Minimum necessary principle applied', event);
    return event;
  }

  logBreachIncident(incidentType, patientIds, details = {}) {
    const event = {
      eventType: 'POTENTIAL_BREACH',
      hipaaCategory: 'security_incident',
      incidentType: incidentType, // unauthorized_access, theft, loss, etc.
      affectedPatients: patientIds.map(id => this.hashValue(id)),
      patientCount: patientIds.length,
      timestamp: new Date().toISOString(),
      details: this.sanitizeHIPAAData(details),
      requiresNotification: true
    };

    this.critical('Potential HIPAA breach detected', event);
    return event;
  }

  // Sanitize HIPAA-specific data
  sanitizeHIPAAData(data) {
    const hipaaFields = [
      'medicalRecordNumber', 'patientName', 'patientAddress',
      'phoneNumber', 'emailAddress', 'dateOfBirth', 'age',
      'gender', 'race', 'ethnicity', 'religion', 'bloodType',
      'diagnosis', 'symptoms', 'medication', 'treatment',
      'labResults', 'radiology', 'mentalHealthNotes', 'substanceAbuse',
      'geneticInformation', 'biometricData', 'insuranceNumber'
    ];

    const sanitized = this.sanitizeData(data);
    
    hipaaFields.forEach(field => {
      if (sanitized.hasOwnProperty(field)) {
        sanitized[field] = this.hashValue(sanitized[field]);
        sanitized[`${field}_redacted`] = true;
        sanitized[`${field}_phi`] = true;
      }
    });

    return sanitized;
  }

  // Track patient access for analysis
  trackPatientAccess(patientId, userId, action) {
    const key = `${patientId}:${userId}`;
    
    if (!this.patientAccessLog.has(key)) {
      this.patientAccessLog.set(key, []);
    }
    
    const accessLog = this.patientAccessLog.get(key);
    accessLog.push({
      action: action,
      timestamp: new Date().toISOString()
    });
    
    // Keep only last 100 accesses per patient-user combination
    if (accessLog.length > 100) {
      accessLog.shift();
    }
  }

  // Generate HIPAA compliance report
  async generateHIPAAReport(timeRange = '30d') {
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - this.parseTimeRange(timeRange));
    
    const report = {
      reportId: this.generateRequestId(),
      generatedAt: new Date().toISOString(),
      timeRange: timeRange,
      startTime: startTime.toISOString(),
      endTime: endTime.toISOString(),
      compliance: {
        patientAccessLogs: await this.getPatientAccessLogs(timeRange),
        phiDisclosures: await this.getPHIDisclosures(timeRange),
        minimumNecessary: await this.getMinimumNecessaryLogs(timeRange),
        securityIncidents: await this.getSecurityIncidents(timeRange),
        userAccessReview: await this.getUserAccessReview(timeRange)
      },
      metrics: {
        totalPatientAccesses: 0,
        uniquePatientsAccessed: 0,
        uniqueUsers: 0,
        phiDisclosures: 0,
        securityIncidents: 0,
        complianceScore: 0
      }
    };
    
    // Calculate metrics
    this.calculateHIPAAComplianceMetrics(report);
    
    return report;
  }

  async getPatientAccessLogs(timeRange) {
    // This would query actual logs
    return [
      {
        patientId: 'hashed_id_1',
        userId: 'usr_123',
        accessCount: 25,
        actions: ['view', 'edit'],
        timeRange: timeRange
      }
    ];
  }

  async getPHIDisclosures(timeRange) {
    return [];
  }

  async getMinimumNecessaryLogs(timeRange) {
    return [];
  }

  async getSecurityIncidents(timeRange) {
    return [];
  }

  async getUserAccessReview(timeRange) {
    return [];
  }

  calculateHIPAAComplianceMetrics(report) {
    const patientAccess = report.compliance.patientAccessLogs;
    
    report.metrics.totalPatientAccesses = patientAccess.reduce(
      (sum, log) => sum + log.accessCount, 0
    );
    
    report.metrics.uniquePatientsAccessed = patientAccess.length;
    report.metrics.uniqueUsers = new Set(patientAccess.map(log => log.userId)).size;
    
    // Calculate compliance score based on various factors
    let score = 100;
    
    // Deduct points for security incidents
    score -= report.compliance.securityIncidents.length * 10;
    
    // Deduct points for missing audit trails
    if (report.metrics.totalPatientAccesses === 0) {
      score -= 20;
    }
    
    report.metrics.complianceScore = Math.max(0, score);
  }

  // HIPAA audit trail for external auditors
  async generateAuditTrail(patientId, timeRange = '1y') {
    const auditTrail = {
      patientId: this.hashValue(patientId),
      timeRange: timeRange,
      entries: []
    };

    // Get all access logs for this patient
    for (const [key, accessLog] of this.patientAccessLog) {
      const [storedPatientId, userId] = key.split(':');
      
      if (storedPatientId === patientId) {
        auditTrail.entries.push({
          userId: userId,
          accesses: accessLog,
          totalAccesses: accessLog.length
        });
      }
    }

    return auditTrail;
  }

  // Breach notification logging
  logBreachNotification(patientId, notificationMethod, sentAt, details = {}) {
    const event = {
      eventType: 'BREACH_NOTIFICATION',
      hipaaCategory: 'breach_notification',
      patientId: this.hashValue(patientId),
      notificationMethod: notificationMethod, // mail, email, phone
      sentAt: sentAt,
      timestamp: new Date().toISOString(),
      details: details
    };

    this.audit('Breach notification sent', event);
    return event;
  }

  parseTimeRange(timeRange) {
    const match = timeRange.match(/(\d+)([hdwmy])/);
    if (!match) return 30 * 24 * 60 * 60 * 1000; // Default to 30 days
    
    const value = parseInt(match[1]);
    const unit = match[2];
    
    switch (unit) {
      case 'h': return value * 60 * 60 * 1000;
      case 'd': return value * 24 * 60 * 60 * 1000;
      case 'w': return value * 7 * 24 * 60 * 60 * 1000;
      case 'm': return value * 30 * 24 * 60 * 60 * 1000;
      case 'y': return value * 365 * 24 * 60 * 60 * 1000;
      default: return 30 * 24 * 60 * 60 * 1000;
    }
  }
}

// Usage example
const hipaaLogger = new HIPAALogger({
  serviceName: 'hipaa-medical-records',
  environment: 'production',
  logLevel: 'info'
});

// Log HIPAA-specific events
hipaaLogger.logPatientDataAccess('pat_123', 'usr_456', 'view', {
  department: 'cardiology',
  reason: 'routine_exam'
});

hipaaLogger.logPHIAccess('pat_123', 'medical', 'dr_smith', {
  diagnosisCodes: ['I10', 'E11.9'],
  medications: ['metformin', 'lisinopril']
});

hipaaLogger.logMinimumNecessary('pat_123', 'usr_456', 
  ['full_medical_history', 'billing', 'insurance'], 
  ['current_medications', 'recent_visits']
);

console.log('HIPAA logging framework initialized');
```

This comprehensive secure logging framework provides:

1. **Structured logging** with sanitization of sensitive data
2. **Security event monitoring** with alerting capabilities  
3. **Compliance logging** specifically for healthcare (HIPAA)
4. **Audit trails** for regulatory requirements
5. **Performance monitoring** and metrics collection
6. **Request correlation** and tracing capabilities
7. **Flexible configuration** for different environments and requirements

The framework ensures that sensitive information is properly protected while maintaining comprehensive logging for security, compliance, and operational needs.
