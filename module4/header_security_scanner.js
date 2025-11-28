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

  // Helper function to make HTTP requests (works in browser environment)
  async makeRequest(url) {
    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'User-Agent': 'HeaderSecurityScanner/1.0'
        },
        mode: 'cors'
      });
      
      const headers = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      
      let data = '';
      try {
        data = await response.text();
      } catch (e) {
        data = '';
      }
      
      return {
        status: response.status,
        headers: headers,
        data: data
      };
    } catch (error) {
      console.error(`Request failed: ${error.message}`);
      throw error;
    }
  }

  async scan() {
    try {
      console.log(`🔍 Starting header security scan for: ${this.targetUrl}`);
      
      // Make request to target
      const response = await this.makeRequest(this.targetUrl);
      
      console.log(`✅ Response received (Status: ${response.status})`);
      console.log(`📊 Response headers count: ${Object.keys(response.headers).length}`);
      
      // Analyze headers
      this.analyzeHeaders(response.headers, response.data);
      
      // Generate report
      this.generateReport();
      
      return this.results;
    } catch (error) {
      console.error(`❌ Scan failed: ${error.message}`);
      throw error;
    }
  }

  analyzeHeaders(headers, body) {
    console.log(`\n🔍 Analyzing headers...`);
    
    // Check each security rule
    Object.entries(this.checks).forEach(([checkName, checkFunction]) => {
      try {
        const result = checkFunction.call(this, headers, body);
        if (result) {
          this.processCheckResult(checkName, result);
        }
      } catch (error) {
        console.warn(`⚠️  Check failed for ${checkName}: ${error.message}`);
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
        console.log(`🚨 CRITICAL: ${title}`);
        break;
      case 'high':
        this.results.vulnerabilities.push(finding);
        console.log(`🔴 HIGH: ${title}`);
        break;
      case 'medium':
        this.results.warnings.push(finding);
        console.log(`🟡 MEDIUM: ${title}`);
        break;
      case 'low':
        this.results.warnings.push(finding);
        console.log(`🔵 LOW: ${title}`);
        break;
      case 'info':
        this.results.info.push(finding);
        console.log(`ℹ️  INFO: ${title}`);
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
    console.log(`\n📋 SECURITY SCAN REPORT`);
    console.log(`==================================================`);
    
    // Summary
    const totalIssues = this.results.vulnerabilities.length + this.results.warnings.length;
    console.log(`\n📊 Summary:`);
    console.log(`   Total Issues: ${totalIssues}`);
    console.log(`   Critical/High: ${this.results.vulnerabilities.length}`);
    console.log(`   Medium/Low: ${this.results.warnings.length}`);
    console.log(`   Info: ${this.results.info.length}`);
    
    // Critical and High vulnerabilities
    if (this.results.vulnerabilities.length > 0) {
      console.log(`\n🚨 CRITICAL & HIGH VULNERABILITIES:`);
      this.results.vulnerabilities.forEach((vuln, index) => {
        console.log(`\n${index + 1}. ${vuln.title}`);
        console.log(`   Severity: ${vuln.severity.toUpperCase()}`);
        console.log(`   Description: ${vuln.description}`);
        console.log(`   Recommendation: ${vuln.recommendation}`);
        if (vuln.evidence) {
          console.log(`   Evidence: ${vuln.evidence}`);
        }
      });
    }
    
    // Warnings
    if (this.results.warnings.length > 0) {
      console.log(`\n⚠️  WARNINGS & RECOMMENDATIONS:`);
      this.results.warnings.forEach((warning, index) => {
        console.log(`\n${index + 1}. ${warning.title}`);
        console.log(`   Severity: ${warning.severity.toUpperCase()}`);
        console.log(`   Description: ${warning.description}`);
        console.log(`   Recommendation: ${warning.recommendation}`);
        if (warning.evidence) {
          console.log(`   Evidence: ${warning.evidence}`);
        }
      });
    }
    
    // Information
    if (this.results.info.length > 0) {
      console.log(`\nℹ️  INFORMATIONAL:`);
      this.results.info.forEach((info, index) => {
        console.log(`\n${index + 1}. ${info.title}`);
        console.log(`   ${info.description}`);
      });
    }
    
    // Overall risk assessment
    const criticalCount = this.results.vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = this.results.vulnerabilities.filter(v => v.severity === 'high').length;
    
    console.log(`\n🎯 RISK ASSESSMENT:`);
    if (criticalCount > 0) {
      console.log(`   RISK LEVEL: CRITICAL`);
      console.log(`   Immediate action required!`);
    } else if (highCount > 0) {
      console.log(`   RISK LEVEL: HIGH`);
      console.log(`   Action required within 24 hours!`);
    } else if (this.results.warnings.length > 0) {
      console.log(`   RISK LEVEL: MEDIUM`);
      console.log(`   Address warnings within 1 week.`);
    } else {
      console.log(`   RISK LEVEL: LOW`);
      console.log(`   Good security posture!`);
    }
  }
}

// Example usage function
async function runHeaderScan(targetUrl = 'https://example.com') {
  console.log('Header Security Scanner - Playcode.io Compatible Version\n');
  
  const scanner = new HeaderSecurityScanner(targetUrl);
  
  try {
    const results = await scanner.scan();
    console.log('\n✅ Scan completed successfully');
    return results;
  } catch (error) {
    console.error('\n❌ Scan failed:', error.message);
    throw error;
  }
}

// Export for use as module
if (typeof module !== 'undefined' && module.exports) {
  module.exports = HeaderSecurityScanner;
}

// Uncomment to run standalone
runHeaderScan('https://playcode.io');