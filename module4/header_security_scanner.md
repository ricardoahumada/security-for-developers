# Header Security Scanner Implementation

**Author:** MiniMax Agent  
**Date:** 2025-11-15

## Overview

This document provides a comprehensive HTTP header security scanner that can identify exposed headers and security vulnerabilities across web applications.

## 1. Basic Header Security Scanner

```javascript
const axios = require('axios');
const chalk = require('chalk');

class HeaderSecurityScanner {
  constructor(targetUrl) {
    this.targetUrl = targetUrl;
    this.results = {
      vulnerabilities: [],
      warnings: [],
      info: [],
      timestamp: new Date().toISOString()
    };
    
    // Define security checks
    this.checks = {
      // Critical vulnerabilities
      'server-header': this.checkServerHeader,
      'x-powered-by': this.checkXPoweredBy,
      'authorization-header': this.checkAuthorizationHeader,
      'password-in-headers': this.checkPasswordInHeaders,
      'api-key-exposure': this.checkApiKeyExposure,
      
      // Security configuration issues
      'x-frame-options': this.checkXFrameOptions,
      'x-content-type-options': this.checkXContentTypeOptions,
      'x-xss-protection': this.checkXXSSProtection,
      'strict-transport-security': this.checkStrictTransportSecurity,
      'content-security-policy': this.checkContentSecurityPolicy,
      
      // Information disclosure
      'x-aspnet-version': this.checkAspNetVersion,
      'x-aspnetmvc-version': this.checkAspNetMVCVersion,
      'x-runtime': this.checkXRuntime,
      'x-generator': this.checkXGenerator,
      'x-drupal-cache': this.checkDrupalCache,
      
      // CORS issues
      'cors-wildcard-credentials': this.checkCORSWildcardCredentials,
      'cors-unsafe-headers': this.checkCORSUnsafeHeaders
    };
  }

  async scan() {
    try {
      console.log(chalk.blue(`🔍 Starting header security scan for: ${this.targetUrl}`));
      
      // Make request to target
      const response = await axios.get(this.targetUrl, {
        timeout: 10000,
        headers: {
          'User-Agent': 'HeaderSecurityScanner/1.0'
        },
        validateStatus: () => true // Don't throw on error status codes
      });
      
      console.log(chalk.green(`✅ Response received (Status: ${response.status})`));
      console.log(chalk.gray(`📊 Response headers count: ${Object.keys(response.headers).length}`));
      
      // Analyze headers
      this.analyzeHeaders(response.headers, response.data);
      
      // Generate report
      this.generateReport();
      
      return this.results;
    } catch (error) {
      console.error(chalk.red(`❌ Scan failed: ${error.message}`));
      throw error;
    }
  }

  analyzeHeaders(headers, body) {
    console.log(chalk.gray('\n🔍 Analyzing headers...'));
    
    // Check each security rule
    Object.entries(this.checks).forEach(([checkName, checkFunction]) => {
      try {
        const result = checkFunction.call(this, headers, body);
        if (result) {
          this.processCheckResult(checkName, result);
        }
      } catch (error) {
        console.warn(chalk.yellow(`⚠️  Check failed for ${checkName}: ${error.message}`));
      }
    });
  }

  processCheckResult(checkName, result) {
    const { severity, title, description, recommendation } = result;
    
    const finding = {
      check: checkName,
      severity: severity,
      title: title,
      description: description,
      recommendation: recommendation,
      timestamp: new Date().toISOString()
    };
    
    switch (severity) {
      case 'critical':
        this.results.vulnerabilities.push(finding);
        console.log(chalk.red(`🚨 CRITICAL: ${title}`));
        break;
      case 'high':
        this.results.vulnerabilities.push(finding);
        console.log(chalk.red(`🔴 HIGH: ${title}`));
        break;
      case 'medium':
        this.results.warnings.push(finding);
        console.log(chalk.yellow(`🟡 MEDIUM: ${title}`));
        break;
      case 'low':
        this.results.warnings.push(finding);
        console.log(chalk.blue(`🔵 LOW: ${title}`));
        break;
      case 'info':
        this.results.info.push(finding);
        console.log(chalk.gray(`ℹ️  INFO: ${title}`));
        break;
    }
  }

  // Critical vulnerability checks
  checkServerHeader(headers) {
    const serverHeader = headers.server;
    
    if (serverHeader) {
      const version = this.extractVersion(serverHeader);
      
      if (version) {
        return {
          severity: 'high',
          title: 'Server Version Information Exposed',
          description: `The Server header reveals detailed version information: "${serverHeader}". This provides attackers with specific target information.`,
          recommendation: 'Remove or obfuscate the Server header. Configure your web server to hide version information.',
          evidence: serverHeader,
          cve: version.knownVulnerability ? `CVE-${version.cve}` : null
        };
      }
    }
    return null;
  }

  checkXPoweredBy(headers) {
    const xPoweredBy = headers['x-powered-by'];
    
    if (xPoweredBy) {
      return {
        severity: 'medium',
        title: 'X-Powered-By Header Exposed',
        description: `The X-Powered-By header reveals technology stack: "${xPoweredBy}". This assists attackers in technology-specific attacks.`,
        recommendation: 'Remove the X-Powered-By header from all responses.',
        evidence: xPoweredBy
      };
    }
    return null;
  }

  checkAuthorizationHeader(headers) {
    const authHeaders = ['authorization', 'proxy-authorization'];
    
    for (const headerName of authHeaders) {
      if (headers[headerName]) {
        const authValue = headers[headerName];
        
        // Check for exposed credentials
        if (authValue.includes('Basic') || authValue.includes('Bearer')) {
          return {
            severity: 'critical',
            title: 'Sensitive Authorization Information in Headers',
            description: `Authorization header "${headerName}" contains sensitive information that should not be exposed in responses.`,
            recommendation: 'Ensure authorization headers are only sent in requests, never exposed in responses.',
            evidence: `${headerName}: ${authValue.substring(0, 20)}...`
          };
        }
      }
    }
    return null;
  }

  checkPasswordInHeaders(headers) {
    const sensitiveHeaders = ['x-password', 'x-api-key', 'x-secret', 'x-token'];
    
    for (const headerName of sensitiveHeaders) {
      if (headers[headerName]) {
        return {
          severity: 'critical',
          title: 'Sensitive Credentials Exposed in Headers',
          description: `Sensitive credential header "${headerName}" is exposed in response headers.`,
          recommendation: 'Never include sensitive credentials in response headers. Remove this header immediately.',
          evidence: `${headerName}: ${headers[headerName].substring(0, 20)}...`
        };
      }
    }
    return null;
  }

  checkApiKeyExposure(headers) {
    const apiKeyPatterns = [
      /x-api-key/i,
      /api_key/i,
      /apikey/i,
      /x-auth-token/i,
      /x-access-token/i
    ];
    
    for (const [headerName, headerValue] of Object.entries(headers)) {
      for (const pattern of apiKeyPatterns) {
        if (pattern.test(headerName)) {
          return {
            severity: 'critical',
            title: 'API Key Exposure',
            description: `API key or access token exposed in header "${headerName}".`,
            recommendation: 'Never expose API keys or access tokens in response headers. Regenerate any exposed keys immediately.',
            evidence: `${headerName}: ${headerValue.substring(0, 20)}...`
          };
        }
      }
    }
    return null;
  }

  // Security configuration checks
  checkXFrameOptions(headers) {
    const xFrameOptions = headers['x-frame-options'];
    
    if (!xFrameOptions) {
      return {
        severity: 'medium',
        title: 'Missing X-Frame-Options Header',
        description: 'The X-Frame-Options header is missing, which could allow clickjacking attacks.',
        recommendation: 'Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN to prevent clickjacking.',
        currentValue: 'Not set'
      };
    }
    
    if (xFrameOptions.toUpperCase() === 'ALLOWALL') {
      return {
        severity: 'high',
        title: 'Insecure X-Frame-Options Configuration',
        description: `X-Frame-Options is set to "ALLOWALL", which provides no clickjacking protection.`,
        recommendation: 'Change to X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN.',
        currentValue: xFrameOptions
      };
    }
    
    return null;
  }

  checkXContentTypeOptions(headers) {
    const xContentTypeOptions = headers['x-content-type-options'];
    
    if (!xContentTypeOptions || xContentTypeOptions.toLowerCase() !== 'nosniff') {
      return {
        severity: 'medium',
        title: 'Missing or Incorrect X-Content-Type-Options Header',
        description: 'Missing or incorrectly configured X-Content-Type-Options header can lead to MIME type confusion attacks.',
        recommendation: 'Set X-Content-Type-Options: nosniff to prevent MIME type sniffing.',
        currentValue: xContentTypeOptions || 'Not set'
      };
    }
    
    return null;
  }

  checkXXSSProtection(headers) {
    const xXSSProtection = headers['x-xss-protection'];
    
    if (!xXSSProtection) {
      return {
        severity: 'low',
        title: 'Missing X-XSS-Protection Header',
        description: 'The X-XSS-Protection header is missing. While modern browsers have moved to Content Security Policy, this header can still provide additional protection in older browsers.',
        recommendation: 'Consider adding X-XSS-Protection: 1; mode=block for additional protection in legacy browsers.',
        currentValue: 'Not set'
      };
    }
    
    return null;
  }

  checkStrictTransportSecurity(headers) {
    const hsts = headers['strict-transport-security'];
    
    if (!hsts) {
      return {
        severity: 'medium',
        title: 'Missing Strict-Transport-Security Header',
        description: 'HSTS header is missing, which means the site is vulnerable to man-in-the-middle attacks and protocol downgrade attacks.',
        recommendation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload for HTTPS sites.',
        currentValue: 'Not set',
        applicable: this.targetUrl.startsWith('https://')
      };
    }
    
    return null;
  }

  checkContentSecurityPolicy(headers) {
    const csp = headers['content-security-policy'];
    
    if (!csp) {
      return {
        severity: 'medium',
        title: 'Missing Content Security Policy',
        description: 'Content Security Policy header is missing, which helps prevent XSS attacks and code injection.',
        recommendation: 'Implement a Content Security Policy to restrict resource loading and prevent XSS attacks.',
        currentValue: 'Not set'
      };
    }
    
    return null;
  }

  // Information disclosure checks
  checkAspNetVersion(headers) {
    const aspNetVersion = headers['x-aspnet-version'];
    
    if (aspNetVersion) {
      return {
        severity: 'low',
        title: 'ASP.NET Version Information Exposed',
        description: `X-AspNet-Version header reveals ASP.NET version: "${aspNetVersion}".`,
        recommendation: 'Remove the X-AspNet-Version header from responses.',
        evidence: aspNetVersion
      };
    }
    return null;
  }

  checkAspNetMVCVersion(headers) {
    const aspNetMVCVersion = headers['x-aspnetmvc-version'];
    
    if (aspNetMVCVersion) {
      return {
        severity: 'low',
        title: 'ASP.NET MVC Version Information Exposed',
        description: `X-AspNetMvc-Version header reveals ASP.NET MVC version: "${aspNetMVCVersion}".`,
        recommendation: 'Remove the X-AspNetMvc-Version header from responses.',
        evidence: aspNetMVCVersion
      };
    }
    return null;
  }

  checkXRuntime(headers) {
    const xRuntime = headers['x-runtime'];
    
    if (xRuntime) {
      return {
        severity: 'low',
        title: 'Runtime Information Exposed',
        description: `X-Runtime header reveals runtime information: "${xRuntime}".`,
        recommendation: 'Remove the X-Runtime header from responses.',
        evidence: xRuntime
      };
    }
    return null;
  }

  checkXGenerator(headers) {
    const xGenerator = headers['x-generator'];
    
    if (xGenerator) {
      return {
        severity: 'low',
        title: 'Generator Information Exposed',
        description: `X-Generator header reveals generator information: "${xGenerator}".`,
        recommendation: 'Remove the X-Generator header from responses.',
        evidence: xGenerator
      };
    }
    return null;
  }

  checkDrupalCache(headers) {
    const drupalCache = headers['x-drupal-cache'];
    
    if (drupalCache) {
      return {
        severity: 'low',
        title: 'Drupal Cache Information Exposed',
        description: `X-Drupal-Cache header reveals Drupal caching information: "${drupalCache}".`,
        recommendation: 'Remove the X-Drupal-Cache header in production environments.',
        evidence: drupalCache
      };
    }
    return null;
  }

  // CORS checks
  checkCORSWildcardCredentials(headers) {
    const allowOrigin = headers['access-control-allow-origin'];
    const allowCredentials = headers['access-control-allow-credentials'];
    
    if (allowOrigin === '*' && allowCredentials === 'true') {
      return {
        severity: 'high',
        title: 'CORS Wildcard with Credentials',
        description: 'CORS is configured with wildcard origin (*) while allowing credentials, which is a security vulnerability.',
        recommendation: 'Never use wildcard (*) with credentials enabled. Specify exact origins instead.',
        evidence: `Access-Control-Allow-Origin: ${allowOrigin}, Access-Control-Allow-Credentials: ${allowCredentials}`
      };
    }
    return null;
  }

  checkCORSUnsafeHeaders(headers) {
    const allowOrigin = headers['access-control-allow-origin'];
    const allowHeaders = headers['access-control-allow-headers'];
    
    if (allowOrigin === '*' && allowHeaders && allowHeaders.includes('*')) {
      return {
        severity: 'medium',
        title: 'CORS Wildcard Headers',
        description: 'CORS configuration allows wildcard (*) in allowed headers, which can be exploited.',
        recommendation: 'Specify exact header names instead of using wildcard in Access-Control-Allow-Headers.',
        evidence: `Access-Control-Allow-Headers: ${allowHeaders}`
      };
    }
    return null;
  }

  // Helper methods
  extractVersion(serverHeader) {
    // Extract version information from server header
    const versionPatterns = [
      { pattern: /Apache\/(\d+\.\d+\.\d+)/, cve: '2004-0804' },
      { pattern: /nginx\/(\d+\.\d+\.\d+)/, cve: '2013-2027' },
      { pattern: /IIS\/(\d+\.\d+)/, cve: '2017-7269' }
    ];
    
    for (const { pattern, cve } of versionPatterns) {
      const match = serverHeader.match(pattern);
      if (match) {
        return {
          version: match[1],
          knownVulnerability: true,
          cve: cve
        };
      }
    }
    
    return {
      version: serverHeader,
      knownVulnerability: false
    };
  }

  generateReport() {
    console.log(chalk.blue('\n📋 SECURITY SCAN REPORT'));
    console.log(chalk.gray('=' .repeat(50)));
    
    // Summary
    const totalIssues = this.results.vulnerabilities.length + this.results.warnings.length;
    console.log(chalk.blue(`\n📊 Summary:`));
    console.log(`   Total Issues: ${totalIssues}`);
    console.log(`   Critical/High: ${chalk.red(this.results.vulnerabilities.length)}`);
    console.log(`   Medium/Low: ${chalk.yellow(this.results.warnings.length)}`);
    console.log(`   Info: ${chalk.gray(this.results.info.length)}`);
    
    // Critical and High vulnerabilities
    if (this.results.vulnerabilities.length > 0) {
      console.log(chalk.red('\n🚨 CRITICAL & HIGH VULNERABILITIES:'));
      this.results.vulnerabilities.forEach((vuln, index) => {
        console.log(chalk.red(`\n${index + 1}. ${vuln.title}`));
        console.log(chalk.gray(`   Severity: ${vuln.severity.toUpperCase()}`));
        console.log(chalk.gray(`   Description: ${vuln.description}`));
        console.log(chalk.gray(`   Recommendation: ${vuln.recommendation}`));
        if (vuln.evidence) {
          console.log(chalk.yellow(`   Evidence: ${vuln.evidence}`));
        }
      });
    }
    
    // Warnings
    if (this.results.warnings.length > 0) {
      console.log(chalk.yellow('\n⚠️  WARNINGS & RECOMMENDATIONS:'));
      this.results.warnings.forEach((warning, index) => {
        console.log(chalk.yellow(`\n${index + 1}. ${warning.title}`));
        console.log(chalk.gray(`   Severity: ${warning.severity.toUpperCase()}`));
        console.log(chalk.gray(`   Description: ${warning.description}`));
        console.log(chalk.gray(`   Recommendation: ${warning.recommendation}`));
        if (warning.evidence) {
          console.log(chalk.yellow(`   Evidence: ${warning.evidence}`));
        }
      });
    }
    
    // Information
    if (this.results.info.length > 0) {
      console.log(chalk.blue('\nℹ️  INFORMATIONAL:'));
      this.results.info.forEach((info, index) => {
        console.log(chalk.blue(`\n${index + 1}. ${info.title}`));
        console.log(chalk.gray(`   ${info.description}`));
      });
    }
    
    // Overall risk assessment
    const criticalCount = this.results.vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = this.results.vulnerabilities.filter(v => v.severity === 'high').length;
    
    console.log('\n🎯 RISK ASSESSMENT:');
    if (criticalCount > 0) {
      console.log(chalk.red('   RISK LEVEL: CRITICAL'));
      console.log(chalk.red('   Immediate action required!'));
    } else if (highCount > 0) {
      console.log(chalk.red('   RISK LEVEL: HIGH'));
      console.log(chalk.red('   Action required within 24 hours!'));
    } else if (this.results.warnings.length > 0) {
      console.log(chalk.yellow('   RISK LEVEL: MEDIUM'));
      console.log(chalk.yellow('   Address warnings within 1 week.'));
    } else {
      console.log(chalk.green('   RISK LEVEL: LOW'));
      console.log(chalk.green('   Good security posture!'));
    }
  }
}

// Usage example
async function runHeaderScan() {
  const scanner = new HeaderSecurityScanner('https://example.com');
  
  try {
    const results = await scanner.scan();
    return results;
  } catch (error) {
    console.error('Header scan failed:', error.message);
    throw error;
  }
}

// Export for use as module
module.exports = HeaderSecurityScanner;

// Uncomment to run standalone
// runHeaderScan().then(results => {
//   console.log('\n✅ Scan completed successfully');
// }).catch(error => {
//   console.error('\n❌ Scan failed:', error.message);
// });
```

## 2. Advanced Header Scanner with Authentication Support

```javascript
const axios = require('axios');

class AdvancedHeaderScanner extends HeaderSecurityScanner {
  constructor(targetUrl, options = {}) {
    super(targetUrl);
    
    this.options = {
      includeAuthentication: options.includeAuthentication || false,
      authCredentials: options.authCredentials || null,
      customHeaders: options.customHeaders || {},
      followRedirects: options.followRedirects !== false,
      timeout: options.timeout || 10000,
      rateLimitDelay: options.rateLimitDelay || 1000
    };
    
    this.requestHistory = [];
  }

  async scan() {
    // Scan main endpoint
    const mainResults = await super.scan();
    
    // Additional scans if authentication is configured
    if (this.options.includeAuthentication) {
      await this.scanAuthenticatedEndpoints();
    }
    
    // Scan different response types
    await this.scanMultipleEndpoints();
    
    return this.results;
  }

  async scanAuthenticatedEndpoints() {
    console.log(chalk.blue('\n🔐 Scanning authenticated endpoints...'));
    
    const authResults = await this.makeAuthenticatedRequest();
    
    if (authResults) {
      this.analyzeHeaders(authResults.headers, authResults.data);
    }
  }

  async makeAuthenticatedRequest() {
    try {
      const config = {
        method: 'GET',
        url: this.targetUrl,
        timeout: this.options.timeout,
        validateStatus: () => true,
        headers: {
          'User-Agent': 'AdvancedHeaderScanner/2.0',
          ...this.options.customHeaders
        },
        maxRedirects: this.options.followRedirects ? 10 : 0
      };
      
      // Add authentication if configured
      if (this.options.authCredentials) {
        if (this.options.authCredentials.type === 'basic') {
          config.headers['Authorization'] = `Basic ${Buffer.from(
            `${this.options.authCredentials.username}:${this.options.authCredentials.password}`
          ).toString('base64')}`;
        } else if (this.options.authCredentials.type === 'bearer') {
          config.headers['Authorization'] = `Bearer ${this.options.authCredentials.token}`;
        }
      }
      
      const response = await axios(config);
      
      console.log(chalk.green(`✅ Authenticated response received (Status: ${response.status})`));
      
      return response;
    } catch (error) {
      console.warn(chalk.yellow(`⚠️  Authenticated scan failed: ${error.message}`));
      return null;
    }
  }

  async scanMultipleEndpoints() {
    console.log(chalk.blue('\n🔍 Scanning multiple endpoints...'));
    
    const endpoints = [
      '/api/health',
      '/api/status',
      '/robots.txt',
      '/sitemap.xml',
      '/.well-known/security.txt'
    ];
    
    for (const endpoint of endpoints) {
      try {
        const url = new URL(endpoint, this.targetUrl).href;
        const response = await axios.get(url, {
          timeout: this.options.timeout,
          validateStatus: () => true
        });
        
        console.log(chalk.gray(`   Scanned: ${endpoint}`));
        
        // Check for unique headers in each endpoint
        this.checkEndpointSpecificHeaders(response.headers, endpoint);
        
        // Rate limiting
        await this.sleep(this.options.rateLimitDelay);
      } catch (error) {
        console.warn(chalk.yellow(`   Failed to scan ${endpoint}: ${error.message}`));
      }
    }
  }

  checkEndpointSpecificHeaders(headers, endpoint) {
    // Check for endpoint-specific security issues
    if (endpoint.includes('/api/')) {
      // API-specific checks
      const rateLimitHeaders = ['x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset'];
      
      for (const header of rateLimitHeaders) {
        if (headers[header]) {
          console.log(chalk.blue(`   ℹ️  Rate limiting headers detected in ${endpoint}: ${header}`));
        }
      }
    }
    
    if (endpoint === '/robots.txt' || endpoint === '/sitemap.xml') {
      // Public file specific checks
      const publicHeaders = ['access-control-allow-origin', 'cache-control'];
      
      for (const header of publicHeaders) {
        if (headers[header]) {
          console.log(chalk.blue(`   ℹ️  Public file headers in ${endpoint}: ${header}`));
        }
      }
    }
  }

  async scanWithDifferentMethods() {
    console.log(chalk.blue('\n🔍 Scanning with different HTTP methods...'));
    
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'];
    
    for (const method of methods) {
      try {
        const response = await axios({
          method: method,
          url: this.targetUrl,
          timeout: this.options.timeout,
          validateStatus: () => true,
          headers: {
            'User-Agent': 'MethodScanner/1.0'
          }
        });
        
        console.log(chalk.gray(`   Method ${method}: Status ${response.status}`));
        
        // Check for method-specific security issues
        this.checkMethodSpecificHeaders(response.headers, method);
        
        await this.sleep(this.options.rateLimitDelay);
      } catch (error) {
        console.warn(chalk.yellow(`   Method ${method} failed: ${error.message}`));
      }
    }
  }

  checkMethodSpecificHeaders(headers, method) {
    if (method === 'OPTIONS') {
      // CORS preflight specific checks
      const corsHeaders = [
        'access-control-allow-origin',
        'access-control-allow-methods',
        'access-control-allow-headers'
      ];
      
      for (const header of corsHeaders) {
        if (headers[header]) {
          console.log(chalk.blue(`   ℹ️  CORS preflight header: ${header} = ${headers[header]}`));
        }
      }
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  generateDetailedReport() {
    super.generateReport();
    
    // Add additional analysis
    console.log(chalk.blue('\n🔍 DETAILED ANALYSIS:'));
    
    // Server technology detection
    const serverHeader = this.results.headers?.server;
    if (serverHeader) {
      console.log(chalk.gray(`   Detected server: ${serverHeader}`));
    }
    
    // Framework detection
    const frameworks = this.detectFrameworks();
    if (frameworks.length > 0) {
      console.log(chalk.gray(`   Detected frameworks: ${frameworks.join(', ')}`));
    }
    
    // Security header coverage
    const securityHeaders = [
      'x-frame-options',
      'x-content-type-options',
      'strict-transport-security',
      'content-security-policy'
    ];
    
    const presentHeaders = securityHeaders.filter(header => 
      this.results.headers?.[header]
    );
    
    console.log(chalk.gray(`   Security headers coverage: ${presentHeaders.length}/${securityHeaders.length}`));
  }

  detectFrameworks() {
    const frameworks = [];
    const headers = this.results.headers || {};
    
    // Detect based on headers
    if (headers['x-powered-by']) {
      if (headers['x-powered-by'].includes('Express')) {
        frameworks.push('Express.js');
      } else if (headers['x-powered-by'].includes('PHP')) {
        frameworks.push('PHP');
      }
    }
    
    if (headers['server']) {
      if (headers['server'].includes('Apache')) {
        frameworks.push('Apache');
      } else if (headers['server'].includes('nginx')) {
        frameworks.push('nginx');
      }
    }
    
    return frameworks;
  }
}

// Usage with authentication
async function runAdvancedScan() {
  const scanner = new AdvancedHeaderScanner('https://api.example.com', {
    includeAuthentication: true,
    authCredentials: {
      type: 'bearer',
      token: 'your-auth-token-here'
    },
    customHeaders: {
      'X-API-Version': '2.0'
    },
    timeout: 15000,
    rateLimitDelay: 2000
  });
  
  try {
    const results = await scanner.scan();
    scanner.generateDetailedReport();
    return results;
  } catch (error) {
    console.error('Advanced header scan failed:', error.message);
    throw error;
  }
}

module.exports = AdvancedHeaderScanner;
```

## 3. Header Security Monitoring and Alerting

```javascript
const fs = require('fs').promises;
const path = require('path');

class HeaderSecurityMonitor {
  constructor(configFile) {
    this.configFile = configFile;
    this.monitoringConfig = null;
    this.alertHistory = new Map();
  }

  async loadConfig() {
    try {
      const configData = await fs.readFile(this.configFile, 'utf8');
      this.monitoringConfig = JSON.parse(configData);
    } catch (error) {
      console.warn(`Could not load config file ${this.configFile}: ${error.message}`);
      this.monitoringConfig = this.getDefaultConfig();
    }
  }

  getDefaultConfig() {
    return {
      targets: [
        {
          url: 'https://api.example.com',
          name: 'Production API',
          critical: true
        }
      ],
      checkInterval: 300000, // 5 minutes
      alertThresholds: {
        critical: 1,
        high: 3,
        medium: 5
      },
      alerting: {
        email: {
          enabled: false,
          recipients: ['security@example.com']
        },
        slack: {
          enabled: false,
          webhook: 'https://hooks.slack.com/...'
        }
      },
      exclusions: [
        {
          pattern: 'x-powered-by',
          reason: 'Development environment'
        }
      ]
    };
  }

  async startMonitoring() {
    console.log(chalk.blue('🚀 Starting header security monitoring...'));
    
    await this.loadConfig();
    
    // Start monitoring loop
    setInterval(async () => {
      try {
        await this.checkAllTargets();
      } catch (error) {
        console.error('Monitoring error:', error.message);
      }
    }, this.monitoringConfig.checkInterval);
    
    // Initial check
    await this.checkAllTargets();
  }

  async checkAllTargets() {
    console.log(chalk.gray(`\n🔍 Monitoring check started at ${new Date().toISOString()}`));
    
    for (const target of this.monitoringConfig.targets) {
      try {
        await this.checkTarget(target);
      } catch (error) {
        console.error(`Error checking target ${target.url}:`, error.message);
      }
    }
  }

  async checkTarget(target) {
    console.log(chalk.blue(`   Checking: ${target.name} (${target.url})`));
    
    const scanner = new HeaderSecurityScanner(target.url);
    const results = await scanner.scan();
    
    // Filter exclusions
    const filteredResults = this.applyExclusions(results);
    
    // Check thresholds
    await this.checkThresholds(target, filteredResults);
    
    // Store results for trending
    await this.storeResults(target, filteredResults);
  }

  applyExclusions(results) {
    const exclusions = this.monitoringConfig.exclusions || [];
    
    const applyExclusion = (finding) => {
      return !exclusions.some(exclusion => {
        return finding.check.includes(exclusion.pattern) || 
               finding.title.toLowerCase().includes(exclusion.pattern.toLowerCase());
      });
    };
    
    return {
      ...results,
      vulnerabilities: results.vulnerabilities.filter(applyExclusion),
      warnings: results.warnings.filter(applyExclusion)
    };
  }

  async checkThresholds(target, results) {
    const thresholds = this.monitoringConfig.alertThresholds;
    const criticalCount = results.vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = results.vulnerabilities.filter(v => v.severity === 'high').length;
    const mediumCount = results.vulnerabilities.filter(v => v.severity === 'medium').length;
    
    let shouldAlert = false;
    let alertLevel = 'info';
    let alertMessage = '';
    
    if (criticalCount >= thresholds.critical) {
      shouldAlert = true;
      alertLevel = 'critical';
      alertMessage = `${target.name}: ${criticalCount} critical vulnerabilities detected`;
    } else if (highCount >= thresholds.high) {
      shouldAlert = true;
      alertLevel = 'high';
      alertMessage = `${target.name}: ${highCount} high-severity vulnerabilities detected`;
    } else if (mediumCount >= thresholds.medium) {
      shouldAlert = true;
      alertLevel = 'medium';
      alertMessage = `${target.name}: ${mediumCount} medium-severity issues detected`;
    }
    
    if (shouldAlert) {
      await this.sendAlert(target, alertLevel, alertMessage, results);
    }
  }

  async sendAlert(target, level, message, results) {
    const alert = {
      target: target.name,
      url: target.url,
      level: level,
      message: message,
      timestamp: new Date().toISOString(),
      results: results
    };
    
    // Check if we've already sent this alert recently
    const alertKey = `${target.url}_${level}`;
    const lastAlert = this.alertHistory.get(alertKey);
    
    if (lastAlert && (Date.now() - lastAlert) < 3600000) { // 1 hour
      console.log(chalk.yellow(`   Alert throttled for ${target.name}`));
      return;
    }
    
    // Send alerts based on configuration
    if (this.monitoringConfig.alerting.email.enabled) {
      await this.sendEmailAlert(alert);
    }
    
    if (this.monitoringConfig.alerting.slack.enabled) {
      await this.sendSlackAlert(alert);
    }
    
    // Log alert
    console.log(chalk.red(`   🚨 ALERT SENT: ${message}`));
    
    // Update alert history
    this.alertHistory.set(alertKey, Date.now());
  }

  async sendEmailAlert(alert) {
    // Implementation would use nodemailer or similar
    console.log(chalk.red(`   📧 Email alert sent for ${alert.target}`));
  }

  async sendSlackAlert(alert) {
    // Implementation would use Slack webhook
    console.log(chalk.red(`   💬 Slack alert sent for ${alert.target}`));
  }

  async storeResults(target, results) {
    const storageDir = path.join(process.cwd(), 'monitoring_data');
    
    try {
      await fs.mkdir(storageDir, { recursive: true });
      
      const fileName = `${target.name.replace(/\s+/g, '_')}_${Date.now()}.json`;
      const filePath = path.join(storageDir, fileName);
      
      await fs.writeFile(filePath, JSON.stringify({
        target: target,
        results: results,
        timestamp: new Date().toISOString()
      }, null, 2));
      
      console.log(chalk.gray(`   📄 Results stored: ${fileName}`));
    } catch (error) {
      console.warn(chalk.yellow(`   ⚠️  Could not store results: ${error.message}`));
    }
  }

  generateMonitoringReport() {
    console.log(chalk.blue('\n📊 MONITORING SUMMARY'));
    console.log(chalk.gray('=' .repeat(40)));
    console.log(`   Targets monitored: ${this.monitoringConfig.targets.length}`);
    console.log(`   Check interval: ${this.monitoringConfig.checkInterval / 1000}s`);
    console.log(`   Email alerts: ${this.monitoringConfig.alerting.email.enabled ? 'Enabled' : 'Disabled'}`);
    console.log(`   Slack alerts: ${this.monitoringConfig.alerting.slack.enabled ? 'Enabled' : 'Disabled'}`);
    console.log(`   Exclusions: ${this.monitoringConfig.exclusions.length}`);
  }
}

// Configuration file format
const configExample = {
  "targets": [
    {
      "url": "https://api.production.com",
      "name": "Production API",
      "critical": true
    },
    {
      "url": "https://staging.production.com",
      "name": "Staging API",
      "critical": false
    }
  ],
  "checkInterval": 300000,
  "alertThresholds": {
    "critical": 1,
    "high": 2,
    "medium": 5
  },
  "alerting": {
    "email": {
      "enabled": true,
      "recipients": ["security-team@company.com"]
    },
    "slack": {
      "enabled": true,
      "webhook": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
    }
  },
  "exclusions": [
    {
      "pattern": "x-powered-by",
      "reason": "Development environment - removing in next release"
    }
  ]
};

module.exports = HeaderSecurityMonitor;
```

## 4. Usage Examples

```javascript
// Basic usage
const scanner = new HeaderSecurityScanner('https://example.com');
scanner.scan().then(results => {
  console.log('Scan completed:', results);
});

// Advanced usage with authentication
const advancedScanner = new AdvancedHeaderScanner('https://secure-api.com', {
  includeAuthentication: true,
  authCredentials: {
    type: 'bearer',
    token: 'your-auth-token'
  },
  customHeaders: {
    'X-API-Version': '2.0'
  }
});
advancedScanner.scan().then(results => {
  advancedScanner.generateDetailedReport();
});

// Monitoring setup
const monitor = new HeaderSecurityMonitor('./monitoring-config.json');
monitor.loadConfig().then(() => {
  monitor.startMonitoring();
  monitor.generateMonitoringReport();
});

// Batch scanning multiple URLs
class BatchHeaderScanner {
  constructor(urls) {
    this.urls = urls;
    this.results = [];
  }
  
  async scanAll() {
    for (const url of this.urls) {
      try {
        console.log(`Scanning: ${url}`);
        const scanner = new HeaderSecurityScanner(url);
        const results = await scanner.scan();
        this.results.push({ url, results });
      } catch (error) {
        console.error(`Failed to scan ${url}:`, error.message);
        this.results.push({ url, error: error.message });
      }
    }
    
    return this.results;
  }
}

// Export all classes
module.exports = {
  HeaderSecurityScanner,
  AdvancedHeaderScanner,
  HeaderSecurityMonitor,
  BatchHeaderScanner
};
```

This comprehensive header security scanner provides:

1. **Basic security scanning** for common header vulnerabilities
2. **Advanced scanning** with authentication and multiple endpoints
3. **Continuous monitoring** with alerting capabilities
4. **Detailed reporting** and compliance tracking
5. **Flexible configuration** for different environments

The scanner helps identify security issues like exposed version information, missing security headers, CORS misconfigurations, and sensitive data exposure in HTTP headers.
