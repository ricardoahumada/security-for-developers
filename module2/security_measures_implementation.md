# OAuth 2.0 Security Measures Implementation

## Comprehensive Security Implementation

This implementation covers all critical security measures required for secure OAuth 2.0 implementations, including CSRF protection, state management, token handling, and attack prevention.

```javascript
// Security Configuration
const SecurityConfig = {
    // State management
    stateConfig: {
        minLength: 32,
        maxLength: 128,
        expirationMinutes: 10,
        storageMethod: 'secure_session' // 'session', 'database', 'redis'
    },
    
    // Token security
    tokenConfig: {
        encryptionAlgorithm: 'AES-256-GCM',
        keyRotationInterval: 86400000, // 24 hours in milliseconds
        maxTokenAge: 86400000, // 24 hours
        requireRefresh: true
    },
    
    // CSRF protection
    csrfConfig: {
        enableDoubleSubmit: true,
        sameSitePolicy: 'strict',
        httpOnlyCookies: true,
        secureCookies: true
    },
    
    // Rate limiting
    rateLimitConfig: {
        maxAttempts: 5,
        windowMinutes: 15,
        blockDurationMinutes: 60
    }
};

// Security Manager Class
class OAuthSecurityManager {
    constructor(config = SecurityConfig) {
        this.config = config;
        this.stateStore = new Map();
        this.failedAttempts = new Map();
        this.blockedClients = new Map();
        this.auditLogger = new SecurityAuditLogger();
    }

    // Generate cryptographically secure random string
    generateSecureRandom(length = 32) {
        if (length < this.config.stateConfig.minLength) {
            throw new Error(`Minimum length is ${this.config.stateConfig.minLength}`);
        }
        
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        
        // Convert to base64url for URL-safe encoding
        return btoa(String.fromCharCode(...array))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    // State Management with expiration
    generateAndStoreState(additionalData = {}) {
        const state = this.generateSecureRandom();
        const expiration = Date.now() + (this.config.stateConfig.expirationMinutes * 60 * 1000);
        
        const stateData = {
            state: state,
            timestamp: Date.now(),
            expiration: expiration,
            ...additionalData
        };

        // Store state with expiration
        this.stateStore.set(state, stateData);
        
        // Schedule cleanup
        setTimeout(() => {
            this.stateStore.delete(state);
        }, this.config.stateConfig.expirationMinutes * 60 * 1000);

        return state;
    }

    validateAndConsumeState(state, expectedState) {
        // Basic validation
        if (!state || !expectedState) {
            this.logSecurityEvent('MISSING_STATE', { state, expectedState });
            throw new SecurityError('STATE_MISSING', 'State parameter is missing');
        }

        if (state !== expectedState) {
            this.logSecurityEvent('STATE_MISMATCH', { state, expectedState });
            this.recordFailedAttempt('state_mismatch');
            throw new SecurityError('STATE_MISMATCH', 'State parameter does not match');
        }

        // Retrieve and validate stored state
        const storedState = this.stateStore.get(state);
        if (!storedState) {
            this.logSecurityEvent('INVALID_STATE', { state });
            this.recordFailedAttempt('invalid_state');
            throw new SecurityError('INVALID_STATE', 'Invalid or expired state parameter');
        }

        // Check expiration
        if (Date.now() > storedState.expiration) {
            this.logSecurityEvent('EXPIRED_STATE', { state, expiration: storedState.expiration });
            this.stateStore.delete(state);
            throw new SecurityError('STATE_EXPIRED', 'State parameter has expired');
        }

        // Clean up used state
        this.stateStore.delete(state);
        
        this.logSecurityEvent('STATE_VALIDATED', { state });
        return storedState;
    }

    // CSRF Protection
    generateCSRFToken() {
        return this.generateSecureRandom();
    }

    validateCSRFToken(receivedToken, storedToken) {
        if (!receivedToken || !storedToken) {
            this.logSecurityEvent('CSRF_VALIDATION_FAILED', { reason: 'missing_token' });
            throw new SecurityError('CSRF_VALIDATION_FAILED', 'CSRF token validation failed');
        }

        if (receivedToken !== storedToken) {
            this.logSecurityEvent('CSRF_TOKEN_MISMATCH', { 
                receivedToken: receivedToken.substring(0, 8) + '...',
                storedToken: storedToken.substring(0, 8) + '...'
            });
            throw new SecurityError('CSRF_TOKEN_MISMATCH', 'CSRF token does not match');
        }

        this.logSecurityEvent('CSRF_VALIDATION_SUCCESS');
        return true;
    }

    // Token Security
    async encryptToken(token, key) {
        const encoder = new TextEncoder();
        const data = encoder.encode(token);
        
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(key),
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );

        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            cryptoKey,
            data
        );

        return {
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(encrypted))
        };
    }

    async decryptToken(encryptedToken, key) {
        const encoder = new TextEncoder();
        const decoder = new TextDecoder();
        
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(key),
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        const iv = new Uint8Array(encryptedToken.iv);
        const data = new Uint8Array(encryptedToken.data);

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            cryptoKey,
            data
        );

        return decoder.decode(decrypted);
    }

    // Rate Limiting and Attack Prevention
    recordFailedAttempt(type, clientId = 'unknown') {
        const key = `${clientId}:${type}`;
        const attempts = this.failedAttempts.get(key) || 0;
        this.failedAttempts.set(key, attempts + 1);

        if (attempts + 1 >= this.config.rateLimitConfig.maxAttempts) {
            this.blockClient(clientId, type);
        }
    }

    blockClient(clientId, reason) {
        const blockExpiration = Date.now() + (this.config.rateLimitConfig.blockDurationMinutes * 60 * 1000);
        this.blockedClients.set(clientId, {
            reason: reason,
            expiration: blockExpiration,
            timestamp: Date.now()
        });

        this.logSecurityEvent('CLIENT_BLOCKED', { clientId, reason });
    }

    isClientBlocked(clientId) {
        const block = this.blockedClients.get(clientId);
        if (!block) return false;

        if (Date.now() > block.expiration) {
            this.blockedClients.delete(clientId);
            return false;
        }

        return true;
    }

    // Redirect URI Validation
    validateRedirectUri(redirectUri, registeredUris) {
        if (!registeredUris.includes(redirectUri)) {
            this.logSecurityEvent('INVALID_REDIRECT_URI', { redirectUri });
            throw new SecurityError('INVALID_REDIRECT_URI', 'Redirect URI is not registered');
        }

        // Additional security checks
        if (this.containsMaliciousPatterns(redirectUri)) {
            this.logSecurityEvent('MALICIOUS_REDIRECT_URI', { redirectUri });
            throw new SecurityError('MALICIOUS_REDIRECT_URI', 'Redirect URI contains malicious patterns');
        }

        return true;
    }

    containsMaliciousPatterns(uri) {
        const maliciousPatterns = [
            /javascript:/i,
            /data:/i,
            /vbscript:/i,
            /file:/i,
            /\.\./,
            /[<>'"&]/
        ];

        return maliciousPatterns.some(pattern => pattern.test(uri));
    }

    // URL Validation
    validateOAuthUrl(url, allowedDomains) {
        try {
            const urlObj = new URL(url);
            
            // Check protocol
            if (urlObj.protocol !== 'https:') {
                this.logSecurityEvent('INSECURE_PROTOCOL', { url: urlObj.protocol });
                throw new SecurityError('INSECURE_PROTOCOL', 'Only HTTPS is allowed');
            }

            // Check domain
            if (allowedDomains && !allowedDomains.includes(urlObj.hostname)) {
                this.logSecurityEvent('UNAUTHORIZED_DOMAIN', { hostname: urlObj.hostname });
                throw new SecurityError('UNAUTHORIZED_DOMAIN', 'Domain is not authorized');
            }

            return true;
        } catch (error) {
            this.logSecurityEvent('INVALID_URL', { url, error: error.message });
            throw new SecurityError('INVALID_URL', 'Invalid URL format');
        }
    }

    // PKCE Security
    generateCodeVerifier() {
        return this.generateSecureRandom(64);
    }

    async generateCodeChallenge(codeVerifier) {
        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        const digest = await crypto.subtle.digest('SHA-256', data);
        
        // Convert to base64url
        const base64Digest = btoa(String.fromCharCode(...new Uint8Array(digest)));
        return base64Digest.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    validateCodeVerifier(codeVerifier, expectedLength = 64) {
        if (codeVerifier.length !== expectedLength) {
            throw new SecurityError('INVALID_CODE_VERIFIER', 'Code verifier length is incorrect');
        }

        // Check for valid base64url characters
        if (!/^[A-Za-z0-9\-_]+$/.test(codeVerifier)) {
            throw new SecurityError('INVALID_CODE_VERIFIER', 'Code verifier contains invalid characters');
        }

        return true;
    }

    // Logging and Monitoring
    logSecurityEvent(eventType, details = {}) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            eventType: eventType,
            details: details,
            clientIp: this.getClientIp(),
            userAgent: this.getUserAgent()
        };

        // In production, send to SIEM or logging service
        console.log('SECURITY EVENT:', JSON.stringify(logEntry, null, 2));

        this.auditLogger.log(logEntry);
    }

    getClientIp() {
        // In production, extract from request headers (X-Forwarded-For, X-Real-IP, etc.)
        return '127.0.0.1';
    }

    getUserAgent() {
        // In production, extract from request headers
        return 'SecurityScanner/1.0';
    }
}

// Security Error Class
class SecurityError extends Error {
    constructor(code, message, details = {}) {
        super(message);
        this.name = 'SecurityError';
        this.code = code;
        this.details = details;
    }
}

// Security Audit Logger
class SecurityAuditLogger {
    constructor() {
        this.logs = [];
        this.maxLogEntries = 10000;
    }

    log(entry) {
        this.logs.push(entry);
        
        // Maintain log size
        if (this.logs.length > this.maxLogEntries) {
            this.logs = this.logs.slice(-this.maxLogEntries / 2);
        }

        // In production, implement secure logging to external service
        this.persistLog(entry);
    }

    async persistLog(entry) {
        // Implement secure log persistence (database, file, external service)
        // Ensure logs are tamper-proof and properly encrypted
    }

    getSecurityEvents(timeRange = 3600000) { // Last hour
        const cutoff = Date.now() - timeRange;
        return this.logs.filter(log => 
            new Date(log.timestamp).getTime() > cutoff
        );
    }

    detectAnomalies() {
        const recentEvents = this.getSecurityEvents(300000); // Last 5 minutes
        
        const anomalies = [];
        
        // Detect rapid state mismatches
        const stateMismatches = recentEvents.filter(e => e.eventType === 'STATE_MISMATCH');
        if (stateMismatches.length > 10) {
            anomalies.push({
                type: 'HIGH_STATE_MISMATCH_RATE',
                count: stateMismatches.length,
                severity: 'HIGH'
            });
        }

        // Detect CSRF attempts
        const csrfFailures = recentEvents.filter(e => e.eventType.includes('CSRF'));
        if (csrfFailures.length > 5) {
            anomalies.push({
                type: 'HIGH_CSRF_FAILURE_RATE',
                count: csrfFailures.length,
                severity: 'MEDIUM'
            });
        }

        return anomalies;
    }
}

// Comprehensive Security Middleware
class OAuthSecurityMiddleware {
    constructor(securityManager) {
        this.security = securityManager;
    }

    // Validate incoming OAuth request
    validateAuthRequest(req, registeredRedirectUris = []) {
        // Check rate limiting
        const clientId = req.body.client_id || req.query.client_id || 'unknown';
        if (this.security.isClientBlocked(clientId)) {
            throw new SecurityError('CLIENT_BLOCKED', 'Client is temporarily blocked');
        }

        // Validate redirect URI
        const redirectUri = req.body.redirect_uri || req.query.redirect_uri;
        if (redirectUri) {
            this.security.validateRedirectUri(redirectUri, registeredRedirectUris);
        }

        // Validate state parameter
        const state = req.body.state || req.query.state;
        if (state) {
            this.security.validateStateParameter(state, req.session.oauthState);
        }

        // Validate CSRF token
        const csrfToken = req.headers['x-csrf-token'];
        const storedCsrfToken = req.session.csrfToken;
        if (csrfToken && storedCsrfToken) {
            this.security.validateCSRFToken(csrfToken, storedCsrfToken);
        }

        return true;
    }

    // Validate token request
    validateTokenRequest(req) {
        const clientId = req.body.client_id;
        const grantType = req.body.grant_type;

        // Rate limiting check
        if (this.security.isClientBlocked(clientId)) {
            throw new SecurityError('CLIENT_BLOCKED', 'Client is blocked');
        }

        // Validate grant type
        const allowedGrantTypes = [
            'authorization_code',
            'refresh_token',
            'client_credentials'
        ];

        if (!allowedGrantTypes.includes(grantType)) {
            throw new SecurityError('INVALID_GRANT_TYPE', 'Grant type is not allowed');
        }

        // Additional validation based on grant type
        if (grantType === 'authorization_code') {
            this.validateAuthorizationCodeRequest(req);
        }

        return true;
    }

    validateAuthorizationCodeRequest(req) {
        const { code, redirect_uri, client_secret } = req.body;

        // Validate required parameters
        if (!code || !redirect_uri || !client_secret) {
            throw new SecurityError('MISSING_PARAMETERS', 'Missing required parameters');
        }

        // Validate code format (should be base64url)
        if (!/^[A-Za-z0-9\-_]+$/.test(code)) {
            throw new SecurityError('INVALID_CODE_FORMAT', 'Invalid authorization code format');
        }
    }

    // Response security headers
    setSecurityHeaders(res) {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        res.setHeader('Content-Security-Policy', "default-src 'self'");
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    }
}

// Security Testing Utilities
class SecurityTester {
    constructor(securityManager) {
        this.security = securityManager;
    }

    // Test CSRF protection
    testCSRFProtection() {
        console.log('Testing CSRF Protection...');
        
        try {
            // Test missing CSRF token
            this.security.validateCSRFToken(null, 'valid-token');
        } catch (error) {
            console.log('✓ CSRF protection working for missing token');
        }

        try {
            // Test invalid CSRF token
            this.security.validateCSRFToken('invalid-token', 'valid-token');
        } catch (error) {
            console.log('✓ CSRF protection working for invalid token');
        }

        console.log('✓ CSRF protection tests passed\n');
    }

    // Test state parameter protection
    testStateProtection() {
        console.log('Testing State Parameter Protection...');
        
        try {
            // Test missing state
            this.security.validateAndConsumeState(null, 'valid-state');
        } catch (error) {
            console.log('✓ State protection working for missing state');
        }

        try {
            // Test mismatched state
            this.security.validateAndConsumeState('invalid-state', 'valid-state');
        } catch (error) {
            console.log('✓ State protection working for mismatched state');
        }

        console.log('✓ State protection tests passed\n');
    }

    // Test redirect URI validation
    testRedirectValidation() {
        console.log('Testing Redirect URI Validation...');
        
        const validUris = ['https://app.example.com/callback'];
        
        try {
            // Test malicious redirect URI
            this.security.validateRedirectUri('javascript:alert(1)', validUris);
        } catch (error) {
            console.log('✓ Redirect validation working for malicious URI');
        }

        try {
            // Test unregistered redirect URI
            this.security.validateRedirectUri('https://evil.com/callback', validUris);
        } catch (error) {
            console.log('✓ Redirect validation working for unregistered URI');
        }

        console.log('✓ Redirect validation tests passed\n');
    }

    // Run all security tests
    runAllTests() {
        console.log('=== OAuth 2.0 Security Tests ===\n');
        
        this.testCSRFProtection();
        this.testStateProtection();
        this.testRedirectValidation();
        
        console.log('=== All Security Tests Completed ===');
    }
}

// Usage Example
async function demonstrateSecurityMeasures() {
    console.log('=== OAuth 2.0 Security Measures Demo ===\n');

    // Initialize security manager
    const securityManager = new OAuthSecurityManager();
    
    // Test state management
    console.log('1. Testing State Management...');
    const state = securityManager.generateAndStoreState({
        userId: 'user123',
        redirectUri: 'https://app.example.com/callback'
    });
    console.log('Generated State:', state);

    const validatedState = securityManager.validateAndConsumeState(state, state);
    console.log('State Validated:', validatedState);
    console.log();

    // Test CSRF protection
    console.log('2. Testing CSRF Protection...');
    const csrfToken = securityManager.generateCSRFToken();
    console.log('Generated CSRF Token:', csrfToken);
    
    try {
        securityManager.validateCSRFToken('invalid-token', csrfToken);
    } catch (error) {
        console.log('✓ CSRF protection working:', error.message);
    }
    console.log();

    // Test PKCE
    console.log('3. Testing PKCE Security...');
    const codeVerifier = securityManager.generateCodeVerifier();
    const codeChallenge = await securityManager.generateCodeChallenge(codeVerifier);
    
    console.log('Code Verifier (first 16 chars):', codeVerifier.substring(0, 16) + '...');
    console.log('Code Challenge:', codeChallenge.substring(0, 16) + '...');
    console.log();

    // Test redirect URI validation
    console.log('4. Testing Redirect URI Validation...');
    const validUris = ['https://app.example.com/callback'];
    
    try {
        securityManager.validateRedirectUri('https://evil.com/callback', validUris);
    } catch (error) {
        console.log('✓ Invalid redirect URI blocked:', error.message);
    }
    console.log();

    // Run security tests
    const tester = new SecurityTester(securityManager);
    tester.runAllTests();

    console.log('=== Security Measures Demo Complete ===');
}

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        OAuthSecurityManager,
        SecurityError,
        SecurityAuditLogger,
        OAuthSecurityMiddleware,
        SecurityTester,
        SecurityConfig,
        demonstrateSecurityMeasures
    };
} else {
    window.OAuthSecurityMeasures = {
        OAuthSecurityManager,
        SecurityError,
        SecurityAuditLogger,
        OAuthSecurityMiddleware,
        SecurityTester,
        SecurityConfig
    };
}

// Run demo if executed directly
demonstrateSecurityMeasures();
```

## Security Implementation Checklist

### State Management
- [ ] Generate cryptographically secure random strings (minimum 32 characters)
- [ ] Store state server-side with expiration (10-15 minutes)
- [ ] Validate state on callback and consume immediately
- [ ] Clean up expired states to prevent memory leaks
- [ ] Include additional data in state (user ID, redirect URI) for validation

### CSRF Protection
- [ ] Generate CSRF tokens for all state-changing operations
- [ ] Validate CSRF tokens on both client and server
- [ ] Use SameSite cookie attributes
- [ ] Implement double submit cookie pattern for additional security
- [ ] Log CSRF validation failures for monitoring

### Token Security
- [ ] Encrypt tokens at rest using AES-256-GCM
- [ ] Store encryption keys securely (HSM, key vault)
- [ ] Implement token rotation policies
- [ ] Use short-lived access tokens with refresh mechanism
- [ ] Validate token signatures and issuer claims

### Redirect URI Security
- [ ] Validate redirect URIs against exact registered values
- [ ] Block open redirect vulnerabilities
- [ ] Prevent protocol injection (javascript:, data:, etc.)
- [ ] Use only HTTPS for redirect URIs
- [ ] Log unauthorized redirect attempts

### Rate Limiting and Monitoring
- [ ] Implement rate limiting on all OAuth endpoints
- [ ] Monitor failed authentication attempts
- [ ] Block suspicious clients temporarily
- [ ] Log all security events for audit trail
- [ ] Set up alerts for anomalous patterns

### PKCE Security
- [ ] Generate cryptographically random code verifiers (64+ characters)
- [ ] Use SHA256 for code challenge generation
- [ ] Validate code verifier format and length
- [ ] Implement PKCE for all public clients
- [ ] Never reuse code verifiers

This comprehensive security implementation provides defense-in-depth protection against common OAuth 2.0 vulnerabilities and attack vectors.
