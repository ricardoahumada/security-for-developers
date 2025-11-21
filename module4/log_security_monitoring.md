# Log Security Monitoring and Alerting

**Author:** MiniMax Agent  
**Date:** 2025-11-15

## Overview

This document provides advanced security monitoring and alerting capabilities for log data, including real-time threat detection, compliance monitoring, and automated incident response.

## 1. Real-Time Security Event Monitoring

```javascript
const EventEmitter = require('events');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

class LogSecurityMonitor extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      logFile: options.logFile || './logs/security.log',
      alertThresholds: {
        failedLogins: {
          count: 5,
          window: 600000, // 10 minutes
          severity: 'high'
        },
        privilegeEscalation: {
          count: 1,
          window: 0,
          severity: 'critical'
        },
        dataExfiltration: {
          count: 1,
          window: 0,
          severity: 'critical'
        },
        suspiciousRequests: {
          count: 100,
          window: 300000, // 5 minutes
          severity: 'medium'
        }
      },
      alertChannels: {
        email: options.emailAlerts || false,
        slack: options.slackAlerts || false,
        webhook: options.webhookAlerts || false
      },
      alertCooldown: 300000, // 5 minutes
      ...options
    };

    this.eventBuffer = new Map(); // Store recent events for correlation
    this.alertHistory = new Map(); // Track sent alerts to prevent spam
    this.threatPatterns = this.initializeThreatPatterns();
    this.monitoringActive = false;
    
    this.startMonitoring();
  }

  initializeThreatPatterns() {
    return {
      sqlInjection: {
        pattern: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b.*\b(OR|AND)\b.*=)/i,
        severity: 'high',
        description: 'Potential SQL injection attempt detected'
      },
      xssAttempt: {
        pattern: /<script|javascript:|onerror=|onload=|alert\(/i,
        severity: 'medium',
        description: 'Potential XSS attempt detected'
      },
      pathTraversal: {
        pattern: /\.\.\/|\.\.\\|%2e%2e%2f/i,
        severity: 'high',
        description: 'Potential path traversal attempt detected'
      },
      commandInjection: {
        pattern: /[;&|`$()]/,
        severity: 'high',
        description: 'Potential command injection attempt detected'
      },
      authenticationBypass: {
        pattern: /admin.*or.*1.*=.*1|true.*or.*true/i,
        severity: 'critical',
        description: 'Potential authentication bypass attempt'
      },
      sensitiveFileAccess: {
        pattern: /(password|secret|key|config|\.env)/i,
        severity: 'medium',
        description: 'Access to sensitive file detected'
      }
    };
  }

  startMonitoring() {
    if (this.monitoringActive) return;
    
    this.monitoringActive = true;
    console.log('🔍 Starting log security monitoring...');
    
    // Start monitoring interval
    this.monitoringInterval = setInterval(() => {
      this.performThreatAnalysis();
      this.cleanupOldEvents();
    }, 30000); // Run every 30 seconds
    
    // Monitor log file for new entries
    this.startLogFileMonitoring();
  }

  async startLogFileMonitoring() {
    try {
      await fs.access(this.options.logFile);
      this.watchLogFile();
    } catch (error) {
      console.warn(`Log file ${this.options.logFile} not found, will create when needed`);
    }
  }

  async watchLogFile() {
    // In a real implementation, you might use libraries like 'chokidar' or 'tail'
    // For this example, we'll simulate log monitoring
    setInterval(async () => {
      await this.processLogEntries();
    }, 5000); // Check for new entries every 5 seconds
  }

  async processLogEntries() {
    try {
      // In a real implementation, this would read new entries from the log file
      // For demo purposes, we'll simulate some log entries
      const simulatedLogEntry = this.generateSimulatedLogEntry();
      await this.analyzeLogEntry(simulatedLogEntry);
    } catch (error) {
      console.error('Error processing log entries:', error);
    }
  }

  generateSimulatedLogEntry() {
    const events = [
      {
        timestamp: new Date().toISOString(),
        level: 'info',
        message: 'User login attempt',
        userId: 'user123',
        ip: '192.168.1.100',
        userAgent: 'Mozilla/5.0...',
        details: { success: false, attempts: 1 }
      },
      {
        timestamp: new Date().toISOString(),
        level: 'security',
        message: 'SQL injection attempt detected',
        ip: '192.168.1.200',
        userAgent: 'sqlmap/1.0',
        details: { 
          attackType: 'sql_injection',
          payload: "admin' OR '1'='1' --",
          target: '/api/login'
        }
      },
      {
        timestamp: new Date().toISOString(),
        level: 'audit',
        message: 'Large data export',
        userId: 'user456',
        ip: '192.168.1.150',
        details: {
          resource: 'customer_data',
          recordsExported: 50000,
          timestamp: new Date()
        }
      }
    ];

    // Randomly return one of the simulated events
    return events[Math.floor(Math.random() * events.length)];
  }

  async analyzeLogEntry(logEntry) {
    const eventId = this.generateEventId();
    
    // Store event for correlation analysis
    this.storeEvent(eventId, logEntry);
    
    // Perform threat pattern analysis
    const threatMatches = this.analyzeThreatPatterns(logEntry);
    
    if (threatMatches.length > 0) {
      for (const match of threatMatches) {
        await this.handleThreatDetection(eventId, logEntry, match);
      }
    }
    
    // Perform threshold analysis
    await this.performThresholdAnalysis(logEntry);
    
    // Perform correlation analysis
    await this.performCorrelationAnalysis(logEntry);
    
    // Emit event for further processing
    this.emit('logEntryAnalyzed', {
      eventId,
      logEntry,
      threats: threatMatches
    });
  }

  analyzeThreatPatterns(logEntry) {
    const matches = [];
    
    for (const [patternName, pattern] of Object.entries(this.threatPatterns)) {
      if (pattern.pattern.test(logEntry.message) || 
          (logEntry.details && pattern.pattern.test(JSON.stringify(logEntry.details)))) {
        
        matches.push({
          pattern: patternName,
          severity: pattern.severity,
          description: pattern.description,
          match: logEntry.message.match(pattern.pattern)
        });
      }
    }
    
    return matches;
  }

  async handleThreatDetection(eventId, logEntry, threatMatch) {
    const alert = {
      alertId: this.generateEventId(),
      timestamp: new Date().toISOString(),
      severity: threatMatch.severity,
      type: 'THREAT_DETECTION',
      pattern: threatMatch.pattern,
      description: threatMatch.description,
      eventId: eventId,
      logEntry: logEntry,
      recommendedActions: this.getRecommendedActions(threatMatch.pattern)
    };
    
    // Store alert
    this.storeAlert(alert);
    
    // Send alert if not in cooldown
    if (!this.isInAlertCooldown(alert.type, alert.severity)) {
      await this.sendAlert(alert);
      this.updateAlertCooldown(alert.type, alert.severity);
    }
    
    // Log the detection
    console.warn(`🚨 THREAT DETECTED: ${threatMatch.description}`, {
      severity: threatMatch.severity,
      ip: logEntry.ip,
      timestamp: logEntry.timestamp
    });
  }

  async performThresholdAnalysis(logEntry) {
    const thresholds = this.options.alertThresholds;
    
    // Analyze failed login attempts
    if (logEntry.message && logEntry.message.includes('login') && 
        logEntry.details && logEntry.details.success === false) {
      
      const recentFailures = this.getRecentEvents('failed_login', logEntry.ip, 
        thresholds.failedLogins.window);
      
      if (recentFailures.length >= thresholds.failedLogins.count) {
        await this.triggerAlert('EXCESSIVE_LOGIN_FAILURES', {
          ip: logEntry.ip,
          failureCount: recentFailures.length,
          timeWindow: thresholds.failedLogins.window,
          severity: thresholds.failedLogins.severity
        });
      }
    }
    
    // Analyze data exfiltration attempts
    if (logEntry.message && logEntry.message.includes('export') && 
        logEntry.details && logEntry.details.recordsExported > 1000) {
      
      await this.triggerAlert('LARGE_DATA_EXPORT', {
        userId: logEntry.userId,
        ip: logEntry.ip,
        recordsExported: logEntry.details.recordsExported,
        resource: logEntry.details.resource,
        severity: thresholds.dataExfiltration.severity
      });
    }
  }

  async performCorrelationAnalysis(logEntry) {
    const correlationRules = [
      {
        name: 'impossible_travel',
        description: 'User activities from geographically distant locations in short time',
        condition: (events) => this.detectImpossibleTravel(events),
        severity: 'high'
      },
      {
        name: 'privilege_escalation_sequence',
        description: 'Sequence of events leading to privilege escalation',
        condition: (events) => this.detectPrivilegeEscalation(events),
        severity: 'critical'
      },
      {
        name: 'data_breach_pattern',
        description: 'Pattern indicating potential data breach',
        condition: (events) => this.detectDataBreachPattern(events),
        severity: 'critical'
      }
    ];
    
    const recentEvents = this.getRecentEvents(null, null, 300000); // Last 5 minutes
    
    for (const rule of correlationRules) {
      if (rule.condition(recentEvents)) {
        await this.triggerAlert('CORRELATION_RULE_TRIGGERED', {
          rule: rule.name,
          description: rule.description,
          severity: rule.severity,
          relatedEvents: recentEvents.slice(-10) // Last 10 events
        });
      }
    }
  }

  detectImpossibleTravel(events) {
    const userLocations = new Map();
    
    for (const event of events) {
      if (event.logEntry.ip && event.logEntry.userId) {
        const location = this.getLocationFromIP(event.logEntry.ip);
        if (location) {
          const userId = event.logEntry.userId;
          if (userLocations.has(userId)) {
            const lastLocation = userLocations.get(userId);
            const timeDiff = new Date(event.logEntry.timestamp) - 
                           new Date(lastLocation.timestamp);
            
            // If travel time is less than physically possible
            if (timeDiff < 3600000 && // Less than 1 hour
                this.calculateDistance(lastLocation, location) > 1000) { // More than 1000km
              return true;
            }
          }
          userLocations.set(userId, { location, timestamp: event.logEntry.timestamp });
        }
      }
    }
    
    return false;
  }

  detectPrivilegeEscalation(events) {
    const escalationIndicators = ['admin_access', 'privilege_change', 'role_escalation'];
    
    for (const event of events) {
      for (const indicator of escalationIndicators) {
        if (event.logEntry.message && 
            event.logEntry.message.toLowerCase().includes(indicator)) {
          return true;
        }
      }
    }
    
    return false;
  }

  detectDataBreachPattern(events) {
    const breachPattern = {
      dataAccess: 0,
      dataExport: 0,
      unauthorizedAccess: 0
    };
    
    for (const event of events) {
      const message = event.logEntry.message.toLowerCase();
      
      if (message.includes('data access') || message.includes('patient record')) {
        breachPattern.dataAccess++;
      }
      
      if (message.includes('export') || message.includes('download')) {
        breachPattern.dataExport++;
      }
      
      if (message.includes('unauthorized') || message.includes('denied')) {
        breachPattern.unauthorizedAccess++;
      }
    }
    
    // Trigger if multiple breach indicators in short time
    return breachPattern.dataAccess > 10 || 
           breachPattern.dataExport > 1 || 
           breachPattern.unauthorizedAccess > 5;
  }

  getRecommendedActions(threatPattern) {
    const actionMap = {
      sqlInjection: [
        'Block IP address temporarily',
        'Implement WAF rules',
        'Review application logs',
        'Update input validation'
      ],
      xssAttempt: [
        'Review CSP headers',
        'Update output encoding',
        'Implement XSS protection'
      ],
      pathTraversal: [
        'Review file access controls',
        'Implement path normalization',
        'Add access restrictions'
      ],
      commandInjection: [
        'Review command execution',
        'Implement input validation',
        'Use parameterized commands'
      ],
      authenticationBypass: [
        'Review authentication logic',
        'Implement proper session management',
        'Add additional authentication layers'
      ]
    };
    
    return actionMap[threatPattern] || [
      'Investigate the source',
      'Review security controls',
      'Monitor for similar patterns'
    ];
  }

  // Alert management
  async sendAlert(alert) {
    console.log(`📢 Sending alert: ${alert.type} (${alert.severity})`);
    
    const alertPromises = [];
    
    if (this.options.alertChannels.email) {
      alertPromises.push(this.sendEmailAlert(alert));
    }
    
    if (this.options.alertChannels.slack) {
      alertPromises.push(this.sendSlackAlert(alert));
    }
    
    if (this.options.alertChannels.webhook) {
      alertPromises.push(this.sendWebhookAlert(alert));
    }
    
    await Promise.all(alertPromises);
  }

  async sendEmailAlert(alert) {
    // Implementation would use nodemailer or similar
    console.log(`📧 Email alert sent for ${alert.type}`);
  }

  async sendSlackAlert(alert) {
    // Implementation would use Slack webhook
    const message = {
      text: `🚨 Security Alert: ${alert.type}`,
      attachments: [{
        color: alert.severity === 'critical' ? 'danger' : 
               alert.severity === 'high' ? 'warning' : 'good',
        fields: [
          { title: 'Severity', value: alert.severity, short: true },
          { title: 'Timestamp', value: alert.timestamp, short: true },
          { title: 'Description', value: alert.description, short: false }
        ]
      }]
    };
    
    console.log(`💬 Slack alert sent for ${alert.type}`);
  }

  async sendWebhookAlert(alert) {
    // Implementation would send HTTP POST to webhook URL
    console.log(`🔗 Webhook alert sent for ${alert.type}`);
  }

  async triggerAlert(type, details) {
    const alert = {
      alertId: this.generateEventId(),
      timestamp: new Date().toISOString(),
      type: type,
      severity: details.severity || 'medium',
      details: details,
      recommendedActions: this.getRecommendedActions(type)
    };
    
    await this.sendAlert(alert);
    this.storeAlert(alert);
    
    return alert;
  }

  // Event and alert storage
  storeEvent(eventId, logEntry) {
    const key = `${eventId}:${Date.now()}`;
    this.eventBuffer.set(key, {
      eventId,
      logEntry,
      timestamp: new Date()
    });
  }

  storeAlert(alert) {
    const alertKey = `${alert.type}:${alert.severity}`;
    this.alertHistory.set(alertKey, {
      ...alert,
      sentAt: new Date()
    });
  }

  isInAlertCooldown(type, severity) {
    const alertKey = `${type}:${severity}`;
    const lastAlert = this.alertHistory.get(alertKey);
    
    if (!lastAlert) return false;
    
    const timeSinceLastAlert = Date.now() - lastAlert.sentAt.getTime();
    return timeSinceLastAlert < this.options.alertCooldown;
  }

  updateAlertCooldown(type, severity) {
    // Already handled in isInAlertCooldown and storeAlert
  }

  getRecentEvents(eventType, ip, windowMs) {
    const cutoff = new Date(Date.now() - windowMs);
    const recentEvents = [];
    
    for (const [key, event] of this.eventBuffer) {
      if (event.timestamp > cutoff) {
        if (!eventType || key.includes(eventType)) {
          if (!ip || event.logEntry.ip === ip) {
            recentEvents.push(event);
          }
        }
      }
    }
    
    return recentEvents.sort((a, b) => b.timestamp - a.timestamp);
  }

  cleanupOldEvents() {
    const cutoff = new Date(Date.now() - 3600000); // 1 hour
    
    for (const [key, event] of this.eventBuffer) {
      if (event.timestamp < cutoff) {
        this.eventBuffer.delete(key);
      }
    }
  }

  performThreatAnalysis() {
    // Analyze buffered events for complex threats
    const events = Array.from(this.eventBuffer.values());
    
    // Detect attack campaigns
    this.detectAttackCampaigns(events);
    
    // Detect insider threats
    this.detectInsiderThreats(events);
  }

  detectAttackCampaigns(events) {
    // Group events by IP and analyze patterns
    const ipGroups = new Map();
    
    for (const event of events) {
      const ip = event.logEntry.ip;
      if (ip) {
        if (!ipGroups.has(ip)) {
          ipGroups.set(ip, []);
        }
        ipGroups.get(ip).push(event);
      }
    }
    
    for (const [ip, ipEvents] of ipGroups) {
      if (ipEvents.length > 20) { // More than 20 events from same IP
        this.triggerAlert('POTENTIAL_ATTACK_CAMPAIGN', {
          ip: ip,
          eventCount: ipEvents.length,
          timeWindow: this.calculateTimeWindow(ipEvents),
          severity: 'high',
          firstEvent: ipEvents[0].timestamp,
          lastEvent: ipEvents[ipEvents.length - 1].timestamp
        });
      }
    }
  }

  detectInsiderThreats(events) {
    // Look for legitimate user accounts showing malicious behavior
    const userGroups = new Map();
    
    for (const event of events) {
      const userId = event.logEntry.userId;
      if (userId) {
        if (!userGroups.has(userId)) {
          userGroups.set(userId, []);
        }
        userGroups.get(userId).push(event);
      }
    }
    
    for (const [userId, userEvents] of userGroups) {
      // Check for unusual activity patterns
      const hasPrivilegeEscalation = userEvents.some(e => 
        e.logEntry.message.toLowerCase().includes('admin') ||
        e.logEntry.message.toLowerCase().includes('privilege')
      );
      
      const hasDataExfiltration = userEvents.some(e => 
        e.logEntry.message.toLowerCase().includes('export') ||
        e.logEntry.message.toLowerCase().includes('download')
      );
      
      if (hasPrivilegeEscalation && hasDataExfiltration) {
        this.triggerAlert('POTENTIAL_INSIDER_THREAT', {
          userId: userId,
          privilegesAbused: userEvents.filter(e => 
            e.logEntry.message.toLowerCase().includes('admin')).length,
          dataAccessed: userEvents.filter(e => 
            e.logEntry.message.toLowerCase().includes('data')).length,
          severity: 'critical'
        });
      }
    }
  }

  calculateTimeWindow(events) {
    const times = events.map(e => new Date(e.timestamp).getTime());
    return Math.max(...times) - Math.min(...times);
  }

  getLocationFromIP(ip) {
    // In a real implementation, this would use IP geolocation
    // For demo purposes, return mock locations
    const mockLocations = {
      '192.168.1.100': { lat: 40.7128, lng: -74.0060 }, // NYC
      '192.168.1.200': { lat: 34.0522, lng: -118.2437 }, // LA
      '192.168.1.150': { lat: 41.8781, lng: -87.6298 } // Chicago
    };
    
    return mockLocations[ip] || null;
  }

  calculateDistance(location1, location2) {
    // Haversine formula for distance calculation
    const R = 6371; // Earth's radius in kilometers
    const dLat = (location2.lat - location1.lat) * Math.PI / 180;
    const dLng = (location2.lng - location1.lng) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(location1.lat * Math.PI / 180) * Math.cos(location2.lat * Math.PI / 180) *
              Math.sin(dLng/2) * Math.sin(dLng/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
  }

  generateEventId() {
    return crypto.randomBytes(12).toString('hex');
  }

  // Public API
  getMonitoringStatus() {
    return {
      monitoringActive: this.monitoringActive,
      eventBufferSize: this.eventBuffer.size,
      alertHistorySize: this.alertHistory.size,
      threatPatternsLoaded: Object.keys(this.threatPatterns).length,
      uptime: process.uptime()
    };
  }

  getThreatIntelligence() {
    const threatCounts = {};
    
    for (const [key, alert] of this.alertHistory) {
      if (!threatCounts[alert.type]) {
        threatCounts[alert.type] = 0;
      }
      threatCounts[alert.type]++;
    }
    
    return {
      totalAlerts: this.alertHistory.size,
      threatCounts: threatCounts,
      recentThreats: Array.from(this.alertHistory.values())
        .sort((a, b) => b.sentAt - a.sentAt)
        .slice(0, 10)
    };
  }

  stopMonitoring() {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringActive = false;
      console.log('🛑 Log security monitoring stopped');
    }
  }
}

// Usage example
const monitor = new LogSecurityMonitor({
  logFile: './logs/security.log',
  emailAlerts: false,
  slackAlerts: true,
  webhookAlerts: false
});

// Listen for monitoring events
monitor.on('logEntryAnalyzed', (data) => {
  console.log(`Log entry analyzed: ${data.eventId}`);
});

// Get monitoring status
console.log('Monitoring status:', monitor.getMonitoringStatus());

// Get threat intelligence
console.log('Threat intelligence:', monitor.getThreatIntelligence());

module.exports = LogSecurityMonitor;
```

## 2. Compliance Monitoring Dashboard

```javascript
const fs = require('fs').promises;
const path = require('path');

class ComplianceMonitor {
  constructor(options = {}) {
    this.options = {
      logDirectory: options.logDirectory || './logs',
      complianceFrameworks: options.complianceFrameworks || ['HIPAA', 'PCI DSS', 'GDPR'],
      reportingInterval: options.reportingInterval || 24 * 60 * 60 * 1000, // 24 hours
      retentionPeriod: options.retentionPeriod || 7 * 365 * 24 * 60 * 60 * 1000, // 7 years
      ...options
    };

    this.complianceRules = this.initializeComplianceRules();
    this.violationLog = [];
    this.complianceScores = new Map();
    
    this.startComplianceMonitoring();
  }

  initializeComplianceRules() {
    return {
      HIPAA: {
        rules: [
          {
            id: 'H001',
            description: 'Access to PHI must be logged',
            severity: 'high',
            check: (logEntry) => {
              return logEntry.message.toLowerCase().includes('phi') || 
                     logEntry.message.toLowerCase().includes('patient');
            },
            remediation: 'Implement PHI access logging for all data access'
          },
          {
            id: 'H002',
            description: 'Failed login attempts must be monitored',
            severity: 'medium',
            check: (logEntry) => {
              return logEntry.message.toLowerCase().includes('login') && 
                     logEntry.details && logEntry.details.success === false;
            },
            remediation: 'Monitor and alert on excessive failed login attempts'
          },
          {
            id: 'H003',
            description: 'Data encryption status must be verified',
            severity: 'high',
            check: (logEntry) => {
              return logEntry.message.toLowerCase().includes('encryption') && 
                     logEntry.message.toLowerCase().includes('failed');
            },
            remediation: 'Verify encryption implementations and certificates'
          }
        ]
      },
      'PCI DSS': {
        rules: [
          {
            id: 'P001',
            description: 'Credit card data access must be logged',
            severity: 'critical',
            check: (logEntry) => {
              return logEntry.message.toLowerCase().includes('credit_card') ||
                     logEntry.message.toLowerCase().includes('pan') ||
                     logEntry.message.toLowerCase().includes('payment');
            },
            remediation: 'Implement comprehensive logging for all cardholder data access'
          },
          {
            id: 'P002',
            description: 'Authentication events must be logged',
            severity: 'high',
            check: (logEntry) => {
              return logEntry.message.toLowerCase().includes('authentication') ||
                     logEntry.message.toLowerCase().includes('login');
            },
            remediation: 'Ensure all authentication events are properly logged'
          }
        ]
      },
      GDPR: {
        rules: [
          {
            id: 'G001',
            description: 'Personal data access must be logged',
            severity: 'high',
            check: (logEntry) => {
              return logEntry.message.toLowerCase().includes('personal_data') ||
                     logEntry.message.toLowerCase().includes('pii');
            },
            remediation: 'Implement logging for all personal data access'
          },
          {
            id: 'G002',
            description: 'Data deletion requests must be tracked',
            severity: 'medium',
            check: (logEntry) => {
              return logEntry.message.toLowerCase().includes('delete') &&
                     logEntry.message.toLowerCase().includes('personal');
            },
            remediation: 'Track and log all personal data deletion requests'
          }
        ]
      }
    };
  }

  startComplianceMonitoring() {
    console.log('📋 Starting compliance monitoring...');
    
    // Run initial compliance check
    this.performComplianceCheck();
    
    // Schedule regular compliance checks
    setInterval(() => {
      this.performComplianceCheck();
    }, this.options.reportingInterval);
  }

  async performComplianceCheck() {
    console.log('🔍 Performing compliance check...');
    
    const checkResults = {
      timestamp: new Date().toISOString(),
      frameworks: {}
    };

    for (const framework of this.options.complianceFrameworks) {
      checkResults.frameworks[framework] = await this.checkFrameworkCompliance(framework);
    }

    // Calculate overall compliance score
    checkResults.overallScore = this.calculateOverallComplianceScore(checkResults.frameworks);
    
    // Log compliance check results
    await this.logComplianceResults(checkResults);
    
    // Generate reports if needed
    if (checkResults.overallScore < 85) {
      await this.generateComplianceAlert(checkResults);
    }

    return checkResults;
  }

  async checkFrameworkCompliance(framework) {
    const frameworkRules = this.complianceRules[framework];
    if (!frameworkRules) {
      return { score: 0, violations: [], status: 'unknown' };
    }

    const violations = [];
    let totalChecks = 0;
    let passedChecks = 0;

    // Read recent log files
    const logFiles = await this.getRecentLogFiles();
    
    for (const logFile of logFiles) {
      const logContent = await fs.readFile(logFile, 'utf8');
      const logEntries = this.parseLogEntries(logContent);

      for (const rule of frameworkRules.rules) {
        totalChecks++;
        const ruleViolations = this.checkRule(logEntries, rule);
        
        if (ruleViolations.length === 0) {
          passedChecks++;
        } else {
          violations.push(...ruleViolations.map(v => ({
            ...v,
            ruleId: rule.id,
            framework: framework,
            severity: rule.severity,
            remediation: rule.remediation
          })));
        }
      }
    }

    const score = totalChecks > 0 ? (passedChecks / totalChecks) * 100 : 100;
    const status = score >= 95 ? 'compliant' : score >= 85 ? 'mostly_compliant' : 'non_compliant';

    return {
      score: Math.round(score),
      violations: violations,
      status: status,
      totalChecks: totalChecks,
      passedChecks: passedChecks
    };
  }

  checkRule(logEntries, rule) {
    const violations = [];

    for (const logEntry of logEntries) {
      try {
        const parsedEntry = JSON.parse(logEntry);
        if (rule.check(parsedEntry)) {
          violations.push({
            timestamp: parsedEntry.timestamp,
            message: parsedEntry.message,
            details: parsedEntry.details,
            evidence: parsedEntry
          });
        }
      } catch (error) {
        // Skip malformed log entries
        continue;
      }
    }

    return violations;
  }

  async getRecentLogFiles() {
    try {
      const files = await fs.readdir(this.options.logDirectory);
      const logFiles = files.filter(file => file.endsWith('.log'));
      
      // Sort by modification time, most recent first
      const fileStats = await Promise.all(
        logFiles.map(async file => {
          const stats = await fs.stat(path.join(this.options.logDirectory, file));
          return { file, mtime: stats.mtime };
        })
      );
      
      return fileStats
        .sort((a, b) => b.mtime - a.mtime)
        .slice(0, 7) // Last 7 days
        .map(f => path.join(this.options.logDirectory, f.file));
    } catch (error) {
      console.warn('Could not read log directory:', error.message);
      return [];
    }
  }

  parseLogEntries(logContent) {
    return logContent.split('\n').filter(line => line.trim());
  }

  calculateOverallComplianceScore(frameworks) {
    const scores = Object.values(frameworks).map(f => f.score);
    return scores.length > 0 ? 
      Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length) : 0;
  }

  async logComplianceResults(results) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      type: 'compliance_check',
      results: results,
      overallScore: results.overallScore
    };

    const logFile = path.join(this.options.logDirectory, 'compliance.log');
    
    try {
      await fs.appendFile(logFile, JSON.stringify(logEntry) + '\n', 'utf8');
    } catch (error) {
      console.error('Failed to write compliance log:', error);
    }
  }

  async generateComplianceAlert(results) {
    const alert = {
      alertId: this.generateId(),
      timestamp: new Date().toISOString(),
      type: 'COMPLIANCE_VIOLATION',
      severity: results.overallScore < 70 ? 'critical' : 'high',
      overallScore: results.overallScore,
      frameworks: results.frameworks,
      recommendedActions: this.getComplianceRecommendations(results)
    };

    // Store violation
    this.violationLog.push(alert);
    
    // Send alert
    await this.sendComplianceAlert(alert);
    
    // Generate detailed report
    await this.generateDetailedComplianceReport(results);
  }

  getComplianceRecommendations(results) {
    const recommendations = [];
    
    for (const [framework, data] of Object.entries(results.frameworks)) {
      if (data.score < 85) {
        recommendations.push({
          framework: framework,
          score: data.score,
          actions: data.violations.map(v => v.remediation)
        });
      }
    }
    
    return recommendations;
  }

  async sendComplianceAlert(alert) {
    console.warn('🚨 COMPLIANCE ALERT:', {
      overallScore: alert.overallScore,
      severity: alert.severity,
      timestamp: alert.timestamp
    });
  }

  async generateDetailedComplianceReport(results) {
    const report = {
      reportId: this.generateId(),
      generatedAt: new Date().toISOString(),
      reportType: 'compliance_violation',
      results: results,
      executiveSummary: this.generateExecutiveSummary(results),
      detailedFindings: this.generateDetailedFindings(results),
      remediationPlan: this.generateRemediationPlan(results)
    };

    const reportFile = path.join(
      this.options.logDirectory,
      `compliance_report_${new Date().toISOString().split('T')[0]}.json`
    );

    try {
      await fs.writeFile(reportFile, JSON.stringify(report, null, 2));
      console.log(`📊 Compliance report generated: ${reportFile}`);
    } catch (error) {
      console.error('Failed to generate compliance report:', error);
    }
  }

  generateExecutiveSummary(results) {
    return {
      overallCompliance: results.overallScore,
      status: results.overallScore >= 95 ? 'compliant' : 'needs_improvement',
      keyFindings: this.getKeyFindings(results),
      nextReviewDate: new Date(Date.now() + this.options.reportingInterval).toISOString()
    };
  }

  getKeyFindings(results) {
    const findings = [];
    
    for (const [framework, data] of Object.entries(results.frameworks)) {
      if (data.score < 95) {
        findings.push({
          framework: framework,
          score: data.score,
          violationCount: data.violations.length,
          criticalViolations: data.violations.filter(v => v.severity === 'critical').length
        });
      }
    }
    
    return findings;
  }

  generateDetailedFindings(results) {
    const findings = {};
    
    for (const [framework, data] of Object.entries(results.frameworks)) {
      findings[framework] = {
        score: data.score,
        status: data.status,
        totalViolations: data.violations.length,
        violationsBySeverity: {
          critical: data.violations.filter(v => v.severity === 'critical').length,
          high: data.violations.filter(v => v.severity === 'high').length,
          medium: data.violations.filter(v => v.severity === 'medium').length,
          low: data.violations.filter(v => v.severity === 'low').length
        },
        specificViolations: data.violations.slice(0, 10) // Top 10 violations
      };
    }
    
    return findings;
  }

  generateRemediationPlan(results) {
    const plan = {
      immediate: [],
      shortTerm: [],
      longTerm: []
    };
    
    for (const [framework, data] of Object.entries(results.frameworks)) {
      for (const violation of data.violations) {
        const action = {
          framework: framework,
          ruleId: violation.ruleId,
          description: violation.remediation,
          severity: violation.severity,
          targetDate: this.calculateTargetDate(violation.severity)
        };
        
        if (violation.severity === 'critical') {
          plan.immediate.push(action);
        } else if (violation.severity === 'high') {
          plan.shortTerm.push(action);
        } else {
          plan.longTerm.push(action);
        }
      }
    }
    
    return plan;
  }

  calculateTargetDate(severity) {
    const days = severity === 'critical' ? 1 : 
                severity === 'high' ? 7 : 
                severity === 'medium' ? 30 : 90;
    
    return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
  }

  generateId() {
    return require('crypto').randomBytes(8).toString('hex');
  }

  // Public API
  getComplianceStatus() {
    return {
      monitoringActive: true,
      frameworksMonitored: this.options.complianceFrameworks,
      lastCheck: this.violationLog.length > 0 ? 
        this.violationLog[this.violationLog.length - 1].timestamp : null,
      totalViolations: this.violationLog.length,
      frameworks: this.options.complianceFrameworks
    };
  }

  async getComplianceReport(timeRange = '30d') {
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - this.parseTimeRange(timeRange));
    
    const filteredViolations = this.violationLog.filter(v => 
      new Date(v.timestamp) >= startTime && new Date(v.timestamp) <= endTime
    );
    
    return {
      timeRange: timeRange,
      startTime: startTime.toISOString(),
      endTime: endTime.toISOString(),
      totalViolations: filteredViolations.length,
      violationsBySeverity: {
        critical: filteredViolations.filter(v => v.severity === 'critical').length,
        high: filteredViolations.filter(v => v.severity === 'high').length,
        medium: filteredViolations.filter(v => v.severity === 'medium').length,
        low: filteredViolations.filter(v => v.severity === 'low').length
      },
      frameworks: this.options.complianceFrameworks,
      detailedViolations: filteredViolations
    };
  }

  parseTimeRange(timeRange) {
    const match = timeRange.match(/(\d+)([hdwmy])/);
    if (!match) return 30 * 24 * 60 * 60 * 1000;
    
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
const complianceMonitor = new ComplianceMonitor({
  logDirectory: './logs',
  complianceFrameworks: ['HIPAA', 'PCI DSS', 'GDPR'],
  reportingInterval: 24 * 60 * 60 * 1000 // Daily checks
});

// Check compliance status
console.log('Compliance status:', complianceMonitor.getComplianceStatus());

module.exports = ComplianceMonitor;
```

## 3. Log Aggregation and Analysis

```javascript
const { createReadStream } = require('fs');
const readline = require('readline');

class LogAggregator {
  constructor(options = {}) {
    this.options = {
      logSources: options.logSources || ['./logs/application.log', './logs/security.log'],
      analysisRules: options.analysisRules || this.getDefaultAnalysisRules(),
      aggregationWindow: options.aggregationWindow || 60 * 60 * 1000, // 1 hour
      ...options
    };
    
    this.aggregatedData = new Map();
    this.analysisResults = new Map();
  }

  getDefaultAnalysisRules() {
    return [
      {
        name: 'error_rate_analysis',
        description: 'Analyze error rates over time',
        analyze: (logEntry) => logEntry.level === 'error',
        aggregate: (matches) => {
          const errors = matches.length;
          const timeWindow = matches.length > 1 ? 
            new Date(matches[matches.length - 1].timestamp) - new Date(matches[0].timestamp) : 0;
          return {
            errorCount: errors,
            errorRate: errors / (timeWindow / 1000), // errors per second
            timeWindow: timeWindow
          };
        }
      },
      {
        name: 'security_event_analysis',
        description: 'Analyze security events',
        analyze: (logEntry) => logEntry.level === 'security',
        aggregate: (matches) => {
          const eventTypes = {};
          matches.forEach(match => {
            const type = match.details?.eventType || 'unknown';
            eventTypes[type] = (eventTypes[type] || 0) + 1;
          });
          return {
            totalEvents: matches.length,
            eventTypes: eventTypes,
            severity: this.calculateSeverity(matches)
          };
        }
      },
      {
        name: 'performance_analysis',
        description: 'Analyze performance metrics',
        analyze: (logEntry) => logEntry.message?.includes('performance'),
        aggregate: (matches) => {
          const durations = matches.map(m => m.details?.duration || 0);
          return {
            averageResponseTime: durations.reduce((a, b) => a + b, 0) / durations.length,
            maxResponseTime: Math.max(...durations),
            minResponseTime: Math.min(...durations),
            samples: durations.length
          };
        }
      }
    ];
  }

  async aggregateLogs() {
    console.log('📊 Starting log aggregation...');
    
    for (const logSource of this.options.logSources) {
      await this.processLogSource(logSource);
    }
    
    await this.performAnalysis();
    
    console.log('✅ Log aggregation completed');
  }

  async processLogSource(logSource) {
    try {
      const fileStream = createReadStream(logSource);
      const rl = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity
      });

      for await (const line of rl) {
        if (line.trim()) {
          try {
            const logEntry = JSON.parse(line);
            await this.processLogEntry(logEntry, logSource);
          } catch (error) {
            // Skip malformed lines
            continue;
          }
        }
      }
    } catch (error) {
      console.warn(`Could not process log source ${logSource}:`, error.message);
    }
  }

  async processLogEntry(logEntry, logSource) {
    const timestamp = new Date(logEntry.timestamp);
    const windowKey = this.getWindowKey(timestamp);
    
    if (!this.aggregatedData.has(windowKey)) {
      this.aggregatedData.set(windowKey, {
        timestamp: timestamp,
        logEntries: [],
        logSource: logSource
      });
    }
    
    this.aggregatedData.get(windowKey).logEntries.push(logEntry);
  }

  getWindowKey(timestamp) {
    const windowStart = new Date(
      Math.floor(timestamp.getTime() / this.options.aggregationWindow) * 
      this.options.aggregationWindow
    );
    return windowStart.toISOString();
  }

  async performAnalysis() {
    for (const [windowKey, data] of this.aggregatedData) {
      const results = {};
      
      for (const rule of this.options.analysisRules) {
        const matches = data.logEntries.filter(rule.analyze);
        
        if (matches.length > 0) {
          results[rule.name] = {
            description: rule.description,
            result: rule.aggregate(matches),
            matchCount: matches.length,
            timestamp: windowKey
          };
        }
      }
      
      this.analysisResults.set(windowKey, results);
    }
  }

  calculateSeverity(logEntries) {
    const severityCount = { critical: 0, high: 0, medium: 0, low: 0 };
    
    logEntries.forEach(entry => {
      const severity = entry.details?.severity || entry.level;
      if (severityCount.hasOwnProperty(severity)) {
        severityCount[severity]++;
      } else {
        severityCount.low++;
      }
    });
    
    // Return overall severity based on highest severity present
    if (severityCount.critical > 0) return 'critical';
    if (severityCount.high > 0) return 'high';
    if (severityCount.medium > 0) return 'medium';
    return 'low';
  }

  generateReport() {
    const report = {
      generatedAt: new Date().toISOString(),
      timeRange: {
        start: Array.from(this.analysisResults.keys()).sort()[0],
        end: Array.from(this.analysisResults.keys()).sort().slice(-1)[0]
      },
      summary: this.generateSummary(),
      details: Object.fromEntries(this.analysisResults),
      recommendations: this.generateRecommendations()
    };
    
    return report;
  }

  generateSummary() {
    const totalWindows = this.analysisResults.size;
    const totalEvents = Array.from(this.analysisResults.values())
      .reduce((sum, results) => {
        return sum + Object.values(results)
          .reduce((windowSum, analysis) => windowSum + analysis.matchCount, 0);
      }, 0);
    
    return {
      totalTimeWindows: totalWindows,
      totalAnalyzedEvents: totalEvents,
      analysisRules: this.options.analysisRules.length,
      logSources: this.options.logSources.length
    };
  }

  generateRecommendations() {
    const recommendations = [];
    
    // Analyze patterns and generate recommendations
    for (const [windowKey, results] of this.analysisResults) {
      // Error rate recommendations
      if (results.error_rate_analysis) {
        const errorRate = results.error_rate_analysis.result.errorRate;
        if (errorRate > 1) { // More than 1 error per second
          recommendations.push({
            type: 'performance',
            severity: 'high',
            message: `High error rate detected: ${errorRate.toFixed(2)} errors/second`,
            window: windowKey,
            action: 'Investigate error patterns and implement error handling improvements'
          });
        }
      }
      
      // Security event recommendations
      if (results.security_event_analysis) {
        const securityResult = results.security_event_analysis.result;
        if (securityResult.severity === 'critical' || securityResult.severity === 'high') {
          recommendations.push({
            type: 'security',
            severity: securityResult.severity,
            message: `High-severity security events detected: ${securityResult.totalEvents}`,
            window: windowKey,
            action: 'Review security incidents and strengthen security controls'
          });
        }
      }
      
      // Performance recommendations
      if (results.performance_analysis) {
        const perfResult = results.performance_analysis.result;
        if (perfResult.averageResponseTime > 2000) { // More than 2 seconds
          recommendations.push({
            type: 'performance',
            severity: 'medium',
            message: `High average response time: ${perfResult.averageResponseTime.toFixed(2)}ms`,
            window: windowKey,
            action: 'Optimize application performance and investigate bottlenecks'
          });
        }
      }
    }
    
    return recommendations;
  }

  // Public API
  getAggregatedData(timeRange = '24h') {
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - this.parseTimeRange(timeRange));
    
    const filteredData = new Map();
    
    for (const [windowKey, data] of this.aggregatedData) {
      const windowTime = new Date(windowKey);
      if (windowTime >= startTime && windowTime <= endTime) {
        filteredData.set(windowKey, data);
      }
    }
    
    return Object.fromEntries(filteredData);
  }

  getAnalysisResults(timeRange = '24h') {
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - this.parseTimeRange(timeRange));
    
    const filteredResults = new Map();
    
    for (const [windowKey, results] of this.analysisResults) {
      const windowTime = new Date(windowKey);
      if (windowTime >= startTime && windowTime <= endTime) {
        filteredResults.set(windowKey, results);
      }
    }
    
    return Object.fromEntries(filteredResults);
  }

  parseTimeRange(timeRange) {
    const match = timeRange.match(/(\d+)([hdwmy])/);
    if (!match) return 24 * 60 * 60 * 1000;
    
    const value = parseInt(match[1]);
    const unit = match[2];
    
    switch (unit) {
      case 'h': return value * 60 * 60 * 1000;
      case 'd': return value * 24 * 60 * 60 * 1000;
      case 'w': return value * 7 * 24 * 60 * 60 * 1000;
      case 'm': return value * 30 * 24 * 60 * 60 * 1000;
      case 'y': return value * 365 * 24 * 60 * 60 * 1000;
      default: return 24 * 60 * 60 * 1000;
    }
  }
}

// Usage example
const aggregator = new LogAggregator({
  logSources: ['./logs/application.log', './logs/security.log', './logs/audit.log'],
  aggregationWindow: 60 * 60 * 1000 // 1 hour windows
});

// Run aggregation
aggregator.aggregateLogs().then(() => {
  const report = aggregator.generateReport();
  console.log('Aggregation report:', report);
  
  // Save report to file
  const fs = require('fs');
  fs.writeFileSync('log-aggregation-report.json', JSON.stringify(report, null, 2));
});

module.exports = LogAggregator;
```

This comprehensive log security monitoring and alerting system provides:

1. **Real-time threat detection** with pattern matching and correlation analysis
2. **Automated alert management** with cooldown periods and multiple notification channels
3. **Compliance monitoring** for HIPAA, PCI DSS, and GDPR with violation tracking
4. **Log aggregation and analysis** with performance metrics and recommendations
5. **Security event correlation** for insider threat and attack campaign detection
6. **Comprehensive reporting** for security operations and compliance teams

The system enables proactive security monitoring while maintaining operational efficiency and regulatory compliance requirements.
