# OAuth 2.0 Security Attack Vectors and Mitigations

## Overview

OAuth 2.0, while providing excellent security for delegated authorization, introduces several attack vectors that must be properly addressed. This document covers the three most critical attack vectors: Client Registration and Authentication, Token Storage and Transmission, and Token Validation.

---

## 1. Client Registration and Authentication Attacks

### **Attack Vector Description**
The client registration and authentication process is a primary target for attackers. Weak client registration processes or inadequate authentication mechanisms can lead to unauthorized access and token theft.

### **Common Attack Scenarios**

#### **A. Rogue Client Registration**
```javascript
// VULNERABLE: No proper validation during registration
function registerClientVulnerable(clientData) {
    const client = {
        clientId: clientData.clientId,
        clientSecret: clientData.clientSecret,
        redirectUris: clientData.redirectUris,
        clientType: clientData.clientType,
        // No validation of redirect URIs
        // No verification of ownership
        // No application review process
        createdAt: new Date()
    };
    
    return client; // Attacker can register malicious client
}

// SECURE: Proper client registration with validation
function registerClientSecure(clientData) {
    // Validate client data
    if (!validateClientData(clientData)) {
        throw new Error('Invalid client data');
    }
    
    // Verify redirect URIs are under client's control
    if (!verifyRedirectUris(clientData.redirectUris, clientData.website)) {
        throw new Error('Redirect URIs not owned by applicant');
    }
    
    // Generate client ID and secret server-side
    const clientId = generateClientId();
    const clientSecret = generateClientSecret();
    
    // Apply rate limiting
    if (isRateLimited(clientData.ownerEmail)) {
        throw new Error('Too many registration attempts');
    }
    
    const client = {
        clientId: clientId,
        clientSecret: hashClientSecret(clientSecret),
        redirectUris: clientData.redirectUris,
        clientType: determineClientType(clientData),
        ownerEmail: clientData.ownerEmail,
        applicationName: clientData.applicationName,
        status: 'pending_review',
        createdAt: new Date(),
        approvedAt: null
    };
    
    return client;
}
```

#### **B. Client Secret Brute Force**
```javascript
// VULNERABLE: Weak client secret generation
function generateWeakSecret() {
    return Math.random().toString(36).substring(7); // Easily guessable
}

// SECURE: Cryptographically secure secret generation
function generateSecureSecret() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => 
        ('0' + byte.toString(16)).slice(-2)
    ).join('');
}

// VULNERABLE: No rate limiting on client authentication
function authenticateClientVulnerable(clientId, clientSecret) {
    const client = getClientById(clientId);
    
    if (!client) {
        return { success: false, reason: 'Invalid client' };
    }
    
    if (client.clientSecret === clientSecret) { // Direct comparison
        return { success: true, client: client };
    }
    
    return { success: false, reason: 'Invalid credentials' };
}

// SECURE: Rate limiting and secure comparison
function authenticateClientSecure(clientId, clientSecret, clientIp) {
    // Apply rate limiting
    if (isRateLimited(clientIp, 'client_authentication')) {
        throw new Error('Rate limit exceeded');
    }
    
    const client = getClientById(clientId);
    
    if (!client) {
        incrementFailedAttempts(clientIp, 'client_authentication');
        return { success: false, reason: 'Invalid client' };
    }
    
    // Use constant-time comparison to prevent timing attacks
    if (timingSafeEqual(client.clientSecret, hashClientSecret(clientSecret))) {
        resetFailedAttempts(clientIp, 'client_authentication');
        return { success: true, client: client };
    }
    
    incrementFailedAttempts(clientIp, 'client_authentication');
    return { success: false, reason: 'Invalid credentials' };
}
```

#### **C. Redirect URI Manipulation**
```javascript
// VULNERABLE: Insufficient redirect URI validation
function validateRedirectUriVulnerable(redirectUri, client) {
    return client.redirectUris.includes(redirectUri); // Basic substring match
}

// SECURE: Strict redirect URI validation
function validateRedirectUriSecure(redirectUri, client) {
    try {
        const uri = new URL(redirectUri);
        
        // Must be HTTPS for production clients
        if (uri.protocol !== 'https:' && !isLocalhost(uri.hostname)) {
            return { valid: false, reason: 'Redirect URI must use HTTPS' };
        }
        
        // Must be in client's registered URIs
        const isRegistered = client.redirectUris.some(registeredUri => {
            const registered = new URL(registeredUri);
            
            // Exact match or subdomain of registered domain
            return registered.protocol === uri.protocol &&
                   registered.hostname === uri.hostname &&
                   registered.pathname === uri.pathname;
        });
        
        if (!isRegistered) {
            return { valid: false, reason: 'Redirect URI not registered' };
        }
        
        // No query parameters in registered URI (prevents open redirect)
        const hasUnregisteredParams = Array.from(uri.searchParams.keys())
            .some(param => !isRegisteredQueryParam(param, client));
        
        if (hasUnregisteredParams) {
            return { valid: false, reason: 'Unregistered query parameters' };
        }
        
        return { valid: true };
        
    } catch (error) {
        return { valid: false, reason: 'Invalid redirect URI format' };
    }
}
```

### **Attack Mitigation Strategies**

#### **1. Strong Client Registration Process**
```javascript
class SecureClientRegistration {
    constructor() {
        this.pendingApplications = new Map();
        this.approvedClients = new Map();
    }
    
    async registerClient(applicationData) {
        // Step 1: Validate application completeness
        if (!this.validateApplication(applicationData)) {
            throw new Error('Incomplete application');
        }
        
        // Step 2: Verify domain ownership
        const domainVerification = await this.verifyDomainOwnership(
            applicationData.domain, 
            applicationData.verificationMethod
        );
        
        if (!domainVerification.verified) {
            throw new Error('Domain ownership verification failed');
        }
        
        // Step 3: Application review process
        const reviewResult = await this.reviewApplication(applicationData);
        
        if (!reviewResult.approved) {
            throw new Error('Application rejected: ' + reviewResult.reason);
        }
        
        // Step 4: Generate secure client credentials
        const clientId = this.generateClientId();
        const clientSecret = this.generateSecureSecret();
        
        // Step 5: Store securely
        const client = {
            clientId: clientId,
            clientSecretHash: this.hashSecret(clientSecret),
            redirectUris: applicationData.redirectUris,
            clientType: applicationData.clientType,
            scopes: applicationData.scopes,
            ownerEmail: applicationData.ownerEmail,
            domain: applicationData.domain,
            status: 'active',
            createdAt: new Date(),
            lastUsed: null
        };
        
        this.approvedClients.set(clientId, client);
        
        // Return client secret only once
        return {
            clientId: clientId,
            clientSecret: clientSecret,
            // ... other non-sensitive data
        };
    }
    
    validateApplication(data) {
        const required = [
            'applicationName', 'description', 'ownerEmail', 
            'redirectUris', 'domain', 'clientType'
        ];
        
        return required.every(field => data[field] && data[field].trim());
    }
    
    async verifyDomainOwnership(domain, method) {
        // Implement DNS TXT record verification
        // Implement HTML file verification
        // Implement email verification
        switch (method) {
            case 'dns':
                return await this.verifyDnsTxt(domain);
            case 'html':
                return await this.verifyHtmlFile(domain);
            case 'email':
                return await this.verifyEmail(domain);
            default:
                throw new Error('Unsupported verification method');
        }
    }
}
```

#### **2. Client Authentication Security**
```javascript
class SecureClientAuthentication {
    authenticateClient(credentials, requestContext) {
        // Rate limiting per IP and client
        if (this.isRateLimited(requestContext.ip, credentials.clientId)) {
            this.logSuspiciousActivity({
                type: 'rate_limiting_triggered',
                ip: requestContext.ip,
                clientId: credentials.clientId,
                timestamp: new Date()
            });
            throw new Error('Rate limit exceeded');
        }
        
        const client = this.getClient(credentials.clientId);
        
        if (!client || client.status !== 'active') {
            this.incrementFailedAttempts(requestContext.ip);
            throw new Error('Invalid client');
        }
        
        // Verify client secret using constant-time comparison
        const isValid = this.timingSafeEqual(
            client.clientSecretHash,
            this.hashSecret(credentials.clientSecret)
        );
        
        if (!isValid) {
            this.incrementFailedAttempts(requestContext.ip);
            this.logFailedAttempt({
                type: 'invalid_client_secret',
                ip: requestContext.ip,
                clientId: credentials.clientId,
                timestamp: new Date()
            });
            throw new Error('Invalid client credentials');
        }
        
        // Reset failed attempts on success
        this.resetFailedAttempts(requestContext.ip);
        
        // Update last used timestamp
        client.lastUsed = new Date();
        
        return {
            success: true,
            client: client,
            metadata: {
                authenticationMethod: 'client_secret_basic',
                timestamp: new Date(),
                ip: requestContext.ip
            }
        };
    }
    
    timingSafeEqual(a, b) {
        if (a.length !== b.length) {
            return false;
        }
        
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a.charCodeAt(i) ^ b.charCodeAt(i);
        }
        
        return result === 0;
    }
    
    isRateLimited(ip, clientId = null) {
        const key = clientId ? `${ip}:${clientId}` : ip;
        const attempts = this.failedAttempts.get(key) || [];
        const recent = attempts.filter(time => 
            Date.now() - time < 60000 // Last minute
        );
        
        return recent.length >= 10; // Max 10 attempts per minute
    }
}
```

---

## 2. Token Storage and Transmission Attacks

### **Attack Vector Description**
Tokens are the most valuable assets in OAuth 2.0 systems. Poor storage and transmission practices can lead to token theft, replay attacks, and unauthorized access.

### **Common Attack Scenarios**

#### **A. Token Interception (Man-in-the-Middle)**
```javascript
// VULNERABLE: Transmitting tokens over HTTP
function sendTokenVulnerable(token, targetUrl) {
    const response = fetch(targetUrl, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        // No encryption - tokens sent in plain text
    });
    
    return response;
}

// SECURE: Always use HTTPS for token transmission
function sendTokenSecure(token, targetUrl) {
    // Ensure HTTPS
    if (!targetUrl.startsWith('https://')) {
        throw new Error('Token transmission must use HTTPS');
    }
    
    // Use secure headers
    const response = fetch(targetUrl, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'Cache-Control': 'no-cache'
        },
        credentials: 'include',
        mode: 'cors'
    });
    
    return response;
}

// VULNERABLE: Storing tokens in localStorage
function storeTokenVulnerable(accessToken, refreshToken) {
    localStorage.setItem('access_token', accessToken);
    localStorage.setItem('refresh_token', refreshToken);
    // Tokens can be stolen by XSS attacks
}

// SECURE: Secure token storage patterns
class SecureTokenStorage {
    constructor() {
        this.memoryStore = new Map();
        this.encryptedStore = new EncryptedLocalStorage();
    }
    
    storeTokens(tokens, userId) {
        // Option 1: Memory-only storage (most secure for web)
        this.memoryStore.set(userId, {
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresAt: Date.now() + (tokens.expiresIn * 1000)
        });
        
        // Option 2: Encrypted storage for mobile apps
        const encryptedTokens = this.encryptTokens(tokens);
        this.encryptedStore.setItem(`tokens_${userId}`, encryptedTokens);
    }
    
    getAccessToken(userId) {
        const stored = this.memoryStore.get(userId);
        
        if (!stored) {
            return null;
        }
        
        // Check expiration
        if (Date.now() > stored.expiresAt) {
            // Try to refresh using refresh token
            const newTokens = await this.refreshToken(userId, stored.refreshToken);
            if (newTokens) {
                this.storeTokens(newTokens, userId);
                return newTokens.accessToken;
            }
            return null;
        }
        
        return stored.accessToken;
    }
    
    encryptTokens(tokens) {
        const key = this.getEncryptionKey();
        const json = JSON.stringify(tokens);
        return this.aesEncrypt(json, key);
    }
    
    aesEncrypt(text, key) {
        // Use Web Crypto API for encryption
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        
        return crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: crypto.getRandomValues(new Uint8Array(12))
            },
            key,
            data
        );
    }
}
```

#### **B. Token Leakage through Logs**
```javascript
// VULNERABLE: Logging sensitive token data
function logAuthEventVulnerable(event) {
    console.log(`Auth Event: ${event.type} - Token: ${event.token}`);
    // Token is now in logs, accessible to anyone with log access
}

// SECURE: Redact sensitive information from logs
function logAuthEventSecure(event) {
    const sanitized = {
        type: event.type,
        userId: event.userId,
        clientId: event.clientId,
        timestamp: event.timestamp,
        tokenPreview: event.token ? `${event.token.substring(0, 8)}...` : null,
        success: event.success,
        ip: event.ip
    };
    
    console.log('Auth Event:', sanitized);
    
    // For security-critical events, log to secure audit trail
    if (this.isSecurityEvent(event.type)) {
        this.auditLogger.log({
            ...sanitized,
            userAgent: event.userAgent,
            sessionId: event.sessionId
        });
    }
}

// VULNERABLE: Error messages revealing tokens
function handleTokenErrorVulnerable(error) {
    return {
        error: 'Invalid token: ' + error.token,
        details: error.stack
    };
}

// SECURE: Generic error messages without sensitive data
function handleTokenErrorSecure(error, requestId) {
    // Log detailed error internally
    this.errorLogger.log({
        error: error.message,
        stack: error.stack,
        requestId: requestId,
        timestamp: new Date()
    });
    
    // Return generic error to client
    return {
        error: 'invalid_token',
        error_description: 'The access token is invalid or expired',
        request_id: requestId
    };
}
```

#### **C. Cross-Site Scripting (XSS) Token Theft**
```javascript
// VULNERABLE: Directly injecting token into DOM
function displayUserInfoVulnerable(userInfo) {
    document.getElementById('user-name').textContent = userInfo.name;
    document.getElementById('user-email').textContent = userInfo.email;
    
    // XSS vulnerability: if userInfo contains malicious script
    // <img src=x onerror="stealToken()">
}

// SECURE: Proper DOM manipulation with sanitization
function displayUserInfoSecure(userInfo) {
    // Always sanitize user input
    const safeName = sanitizeHtml(userInfo.name);
    const safeEmail = sanitizeHtml(userInfo.email);
    
    // Use textContent instead of innerHTML to prevent XSS
    document.getElementById('user-name').textContent = safeName;
    document.getElementById('user-email').textContent = safeEmail;
    
    // Validate and sanitize all data before display
    if (this.containsScript(userInfo.name) || this.containsScript(userInfo.email)) {
        throw new Error('Potential XSS attack detected');
    }
}

// CSP Implementation for additional protection
function implementContentSecurityPolicy() {
    const cspPolicy = `
        default-src 'self';
        script-src 'self' 'unsafe-inline'; 
        style-src 'self' 'unsafe-inline';
        img-src 'self' data: https:;
        connect-src 'self' https://api.example.com;
        frame-ancestors 'none';
        base-uri 'self';
        form-action 'self';
    `.replace(/\s+/g, ' ').trim();
    
    // Set CSP header
    response.setHeader('Content-Security-Policy', cspPolicy);
}

// Token protection against XSS
function protectTokensAgainstXSS() {
    // Use HttpOnly cookies for tokens (inaccessible to JavaScript)
    document.cookie = `access_token=${token}; HttpOnly; Secure; SameSite=Strict`;
    
    // Implement CSRF protection
    const csrfToken = generateCsrfToken();
    sessionStorage.setItem('csrf_token', csrfToken);
    
    // Include CSRF token in all requests
    function makeAuthenticatedRequest(url, options) {
        const csrfToken = sessionStorage.getItem('csrf_token');
        
        return fetch(url, {
            ...options,
            headers: {
                ...options.headers,
                'X-CSRF-Token': csrfToken,
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'include'
        });
    }
}
```

### **Attack Mitigation Strategies**

#### **1. Secure Token Transmission**
```javascript
class SecureTokenTransmission {
    constructor(config) {
        this.allowedDomains = config.allowedDomains || [];
        this.enforceHttps = config.enforceHttps !== false;
    }
    
    async sendSecureRequest(url, token, options = {}) {
        // Validate URL
        const urlObj = new URL(url);
        
        if (this.enforceHttps && urlObj.protocol !== 'https:') {
            throw new Error('HTTPS required for token transmission');
        }
        
        // Validate domain is allowed
        if (!this.isAllowedDomain(urlObj.hostname)) {
            throw new Error('Request to unauthorized domain');
        }
        
        // Prepare headers
        const headers = {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'Cache-Control': 'no-cache',
            ...options.headers
        };
        
        // Add CSRF protection
        const csrfToken = this.getCsrfToken();
        if (csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }
        
        // Make request with timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), options.timeout || 30000);
        
        try {
            const response = await fetch(url, {
                ...options,
                headers: headers,
                signal: controller.signal,
                credentials: 'include'
            });
            
            clearTimeout(timeoutId);
            
            // Validate response
            if (!response.ok) {
                await this.handleErrorResponse(response, token);
            }
            
            return response;
            
        } catch (error) {
            clearTimeout(timeoutId);
            
            if (error.name === 'AbortError') {
                throw new Error('Request timeout');
            }
            
            throw error;
        }
    }
    
    isAllowedDomain(domain) {
        return this.allowedDomains.some(allowed => {
            return domain === allowed || domain.endsWith(`.${allowed}`);
        });
    }
    
    async handleErrorResponse(response, token) {
        // Log security event
        this.logSecurityEvent({
            type: 'token_transmission_failed',
            status: response.status,
            url: response.url,
            tokenPreview: token.substring(0, 8),
            timestamp: new Date()
        });
        
        // Handle specific error codes
        switch (response.status) {
            case 401:
                // Token might be invalid, trigger refresh
                await this.handleTokenExpired();
                break;
            case 403:
                // Permission denied, might need re-authentication
                await this.handlePermissionDenied();
                break;
            default:
                // Generic error handling
                break;
        }
    }
}
```

#### **2. Token Storage Security**
```javascript
class SecureTokenStorage {
    constructor(options = {}) {
        this.storageType = options.storageType || 'memory'; // 'memory', 'encrypted', 'secure-cookie'
        this.encryptionKey = options.encryptionKey;
        this.secureCookieOptions = {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            domain: options.cookieDomain,
            path: '/'
        };
    }
    
    storeAccessToken(token, userId, metadata = {}) {
        switch (this.storageType) {
            case 'memory':
                this.storeInMemory(token, userId, metadata);
                break;
            case 'encrypted':
                this.storeEncrypted(token, userId, metadata);
                break;
            case 'secure-cookie':
                this.storeInSecureCookie(token, userId, metadata);
                break;
            default:
                throw new Error('Unknown storage type');
        }
        
        // Log storage event
        this.logStorageEvent({
            type: 'token_stored',
            storageType: this.storageType,
            userId: userId,
            timestamp: new Date(),
            metadata: metadata
        });
    }
    
    storeInMemory(token, userId, metadata) {
        const tokenData = {
            token: token,
            userId: userId,
            createdAt: Date.now(),
            expiresAt: Date.now() + (3600 * 1000), // 1 hour
            metadata: metadata
        };
        
        // Store in secure memory (not accessible from outside)
        if (!this.memoryStorage) {
            this.memoryStorage = new Map();
        }
        
        this.memoryStorage.set(userId, tokenData);
        
        // Set up automatic cleanup
        this.scheduleCleanup(tokenData.expiresAt);
    }
    
    storeEncrypted(token, userId, metadata) {
        if (!this.encryptionKey) {
            throw new Error('Encryption key required for encrypted storage');
        }
        
        const tokenData = {
            token: token,
            userId: userId,
            createdAt: Date.now(),
            expiresAt: Date.now() + (3600 * 1000),
            metadata: metadata
        };
        
        const encrypted = this.encrypt(JSON.stringify(tokenData));
        
        // Store encrypted data
        localStorage.setItem(`auth_token_${userId}`, encrypted);
        
        // Store separately for additional security
        sessionStorage.setItem(`token_meta_${userId}`, JSON.stringify({
            createdAt: tokenData.createdAt,
            expiresAt: tokenData.expiresAt
        }));
    }
    
    storeInSecureCookie(token, userId, metadata) {
        // Store in HTTP-only cookie
        const cookieValue = this.encrypt(`${userId}:${token}:${Date.now()}`);
        
        document.cookie = [
            `auth_token=${cookieValue}`,
            `Max-Age=3600`, // 1 hour
            `Path=/`,
            ...Object.entries(this.secureCookieOptions).map(([key, value]) => 
                `${key}=${value}`
            )
        ].join('; ');
        
        // Store metadata in session storage
        sessionStorage.setItem(`token_meta_${userId}`, JSON.stringify(metadata));
    }
    
    getAccessToken(userId) {
        let tokenData;
        
        switch (this.storageType) {
            case 'memory':
                tokenData = this.memoryStorage?.get(userId);
                break;
            case 'encrypted':
                const encrypted = localStorage.getItem(`auth_token_${userId}`);
                if (encrypted) {
                    const decrypted = this.decrypt(encrypted);
                    tokenData = JSON.parse(decrypted);
                }
                break;
            case 'secure-cookie':
                tokenData = this.getTokenFromCookie(userId);
                break;
        }
        
        if (!tokenData) {
            return null;
        }
        
        // Check expiration
        if (Date.now() > tokenData.expiresAt) {
            this.removeAccessToken(userId);
            return null;
        }
        
        return tokenData.token;
    }
    
    removeAccessToken(userId) {
        switch (this.storageType) {
            case 'memory':
                this.memoryStorage?.delete(userId);
                break;
            case 'encrypted':
                localStorage.removeItem(`auth_token_${userId}`);
                sessionStorage.removeItem(`token_meta_${userId}`);
                break;
            case 'secure-cookie':
                document.cookie = `auth_token=; Max-Age=0; Path=/`;
                sessionStorage.removeItem(`token_meta_${userId}`);
                break;
        }
        
        this.logStorageEvent({
            type: 'token_removed',
            userId: userId,
            timestamp: new Date()
        });
    }
    
    encrypt(text) {
        // Implementation would use proper encryption
        // This is a simplified example
        const key = this.encryptionKey || this.generateKey();
        return btoa(text + key).split('').reverse().join('');
    }
    
    decrypt(encrypted) {
        const key = this.encryptionKey || this.generateKey();
        const reversed = encrypted.split('').reverse().join('');
        return atob(reversed).replace(key, '');
    }
    
    generateKey() {
        // Generate encryption key from browser fingerprint
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('Browser fingerprint', 2, 2);
        
        return canvas.toDataURL().substring(0, 16);
    }
}
```

---

## 3. Token Validation Attacks

### **Attack Vector Description**
Token validation is critical for maintaining security. Weak validation can lead to token forgery, replay attacks, privilege escalation, and unauthorized access.

### **Common Attack Scenarios**

#### **A. Token Forgery and Tampering**
```javascript
// VULNERABLE: Basic token validation without signature verification
function validateTokenVulnerable(token) {
    try {
        const parts = token.split('.');
        const payload = JSON.parse(atob(parts[1]));
        
        // VULNERABLE: Only checking expiration, not signature
        if (payload.exp < Date.now() / 1000) {
            return { valid: false, reason: 'Token expired' };
        }
        
        // VULNERABLE: No signature verification - attacker can forge tokens
        return { valid: true, payload: payload };
        
    } catch (error) {
        return { valid: false, reason: 'Invalid token format' };
    }
}

// SECURE: Proper JWT validation with signature verification
class SecureTokenValidator {
    constructor(config) {
        this.publicKeys = config.publicKeys; // JWKS or embedded keys
        this.expectedIssuer = config.expectedIssuer;
        this.expectedAudience = config.expectedAudience;
        this.allowedAlgorithms = config.allowedAlgorithms || ['RS256', 'ES256'];
        this.clockSkew = config.clockSkew || 300; // 5 minutes
    }
    
    validateToken(token, options = {}) {
        try {
            // Step 1: Parse token
            const parsed = this.parseToken(token);
            
            // Step 2: Validate token structure
            const structureValidation = this.validateTokenStructure(parsed);
            if (!structureValidation.valid) {
                return structureValidation;
            }
            
            // Step 3: Validate signature
            const signatureValidation = this.validateSignature(token, parsed);
            if (!signatureValidation.valid) {
                return signatureValidation;
            }
            
            // Step 4: Validate claims
            const claimsValidation = this.validateClaims(parsed.payload, options);
            if (!claimsValidation.valid) {
                return claimsValidation;
            }
            
            // Step 5: Additional validations
            const additionalValidation = this.performAdditionalValidations(
                parsed.payload, options
            );
            if (!additionalValidation.valid) {
                return additionalValidation;
            }
            
            return {
                valid: true,
                payload: parsed.payload,
                header: parsed.header,
                token: token,
                metadata: {
                    validatedAt: new Date(),
                    issuer: parsed.payload.iss,
                    subject: parsed.payload.sub,
                    audience: parsed.payload.aud,
                    scopes: parsed.payload.scope || []
                }
            };
            
        } catch (error) {
            return {
                valid: false,
                reason: 'Token validation failed',
                error: error.message
            };
        }
    }
    
    parseToken(token) {
        const parts = token.split('.');
        
        if (parts.length !== 3) {
            throw new Error('Invalid token format');
        }
        
        try {
            const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
            const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
            const signature = parts[2];
            
            return { header, payload, signature };
            
        } catch (error) {
            throw new Error('Invalid base64 encoding');
        }
    }
    
    validateTokenStructure(parsed) {
        const { header, payload } = parsed;
        
        // Validate header
        if (!header.alg || !header.typ) {
            return { valid: false, reason: 'Invalid token header' };
        }
        
        // Only allow expected algorithms
        if (!this.allowedAlgorithms.includes(header.alg)) {
            return { 
                valid: false, 
                reason: `Algorithm not allowed: ${header.alg}` 
            };
        }
        
        // Validate required claims
        const requiredClaims = ['iss', 'sub', 'aud', 'exp', 'iat'];
        const missingClaims = requiredClaims.filter(claim => !(claim in payload));
        
        if (missingClaims.length > 0) {
            return { 
                valid: false, 
                reason: `Missing required claims: ${missingClaims.join(', ')}` 
            };
        }
        
        return { valid: true };
    }
    
    validateSignature(token, parsed) {
        const { header, signature } = parsed;
        
        try {
            // Get appropriate public key
            const publicKey = this.getPublicKey(header);
            
            if (!publicKey) {
                return { 
                    valid: false, 
                    reason: 'Public key not found for algorithm' 
                };
            }
            
            // Verify signature based on algorithm
            switch (header.alg) {
                case 'RS256':
                    return this.verifyRS256Signature(token, signature, publicKey);
                case 'ES256':
                    return this.verifyES256Signature(token, signature, publicKey);
                case 'HS256':
                    return this.verifyHS256Signature(token, signature, this.getSharedSecret());
                default:
                    return { 
                        valid: false, 
                        reason: `Unsupported algorithm: ${header.alg}` 
                    };
            }
            
        } catch (error) {
            return { 
                valid: false, 
                reason: 'Signature verification failed',
                error: error.message 
            };
        }
    }
    
    validateClaims(payload, options) {
        const now = Date.now() / 1000;
        const leeway = this.clockSkew;
        
        // Check expiration with clock skew tolerance
        if (payload.exp && (payload.exp + leeway) < now) {
            return { 
                valid: false, 
                reason: 'Token expired',
                expiredAt: new Date(payload.exp * 1000)
            };
        }
        
        // Check not before
        if (payload.nbf && (payload.nbf - leeway) > now) {
            return { 
                valid: false, 
                reason: 'Token not yet valid' 
            };
        }
        
        // Check issued at (prevent future-dated tokens)
        if (payload.iat && (payload.iat + leeway) > now) {
            return { 
                valid: false, 
                reason: 'Token issued in the future' 
            };
        }
        
        // Validate issuer
        if (this.expectedIssuer && payload.iss !== this.expectedIssuer) {
            return { 
                valid: false, 
                reason: 'Invalid issuer',
                expected: this.expectedIssuer,
                actual: payload.iss
            };
        }
        
        // Validate audience
        const expectedAudience = options.audience || this.expectedAudience;
        if (expectedAudience) {
            const tokenAudience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
            const audienceMatch = tokenAudience.some(aud => this.compareAudience(aud, expectedAudience));
            
            if (!audienceMatch) {
                return { 
                    valid: false, 
                    reason: 'Invalid audience',
                    expected: expectedAudience,
                    actual: payload.aud
                };
            }
        }
        
        return { valid: true };
    }
}
```

#### **B. Replay Attacks**
```javascript
// VULNERABLE: No replay attack protection
function validateTokenVulnerable(token) {
    const payload = JSON.parse(atob(token.split('.')[1]));
    
    if (payload.exp < Date.now() / 1000) {
        return { valid: false, reason: 'Token expired' };
    }
    
    // VULNERABLE: No jti checking - token can be replayed
    return { valid: true, payload: payload };
}

// SECURE: Token replay protection
class ReplayAttackProtection {
    constructor(config = {}) {
        this.jtiStore = new Map(); // Store used JWT IDs
        this.cleanupInterval = config.cleanupInterval || 3600000; // 1 hour
        this.maxJtiAge = config.maxJtiAge || 86400000; // 24 hours
        this.startCleanupTimer();
    }
    
    validateToken(token, options = {}) {
        const parsed = this.parseToken(token);
        const payload = parsed.payload;
        
        // Standard validations first
        const standardValidation = this.performStandardValidation(token);
        if (!standardValidation.valid) {
            return standardValidation;
        }
        
        // Check for JWT ID (jti claim)
        if (!payload.jti) {
            return { 
                valid: false, 
                reason: 'Token missing jti claim - replay attack protection requires jti' 
            };
        }
        
        // Check if this token has already been used
        if (this.isTokenAlreadyUsed(payload.jti)) {
            this.logReplayAttempt({
                jti: payload.jti,
                tokenPreview: token.substring(0, 20) + '...',
                timestamp: new Date()
            });
            
            return { 
                valid: false, 
                reason: 'Token has already been used - possible replay attack',
                jti: payload.jti
            };
        }
        
        // Mark token as used
        this.markTokenAsUsed(payload.jti, payload.exp);
        
        // For access tokens, implement one-time use
        if (options.requireOneTimeUse && this.isAccessToken(payload)) {
            // For access tokens, we typically don't want strict one-time use
            // but we can implement rate limiting or sliding window
            this.recordTokenUsage(payload.jti);
        }
        
        return {
            valid: true,
            payload: payload,
            jti: payload.jti,
            firstUsed: this.getTokenFirstUsed(payload.jti)
        };
    }
    
    isTokenAlreadyUsed(jti) {
        const usedRecord = this.jtiStore.get(jti);
        
        if (!usedRecord) {
            return false;
        }
        
        // Check if token has expired
        if (Date.now() > usedRecord.expiresAt) {
            this.jtiStore.delete(jti);
            return false;
        }
        
        return true;
    }
    
    markTokenAsUsed(jti, expiresAt) {
        const expiresAtMs = expiresAt * 1000;
        
        this.jtiStore.set(jti, {
            firstUsed: Date.now(),
            expiresAt: Math.min(expiresAtMs, Date.now() + this.maxJtiAge),
            usageCount: 1
        });
    }
    
    recordTokenUsage(jti) {
        const record = this.jtiStore.get(jti);
        if (record) {
            record.usageCount++;
            record.lastUsed = Date.now();
        }
    }
    
    startCleanupTimer() {
        setInterval(() => {
            this.cleanupExpiredRecords();
        }, this.cleanupInterval);
    }
    
    cleanupExpiredRecords() {
        const now = Date.now();
        const expiredJtids = [];
        
        for (const [jti, record] of this.jtiStore.entries()) {
            if (now > record.expiresAt) {
                expiredJtids.push(jti);
            }
        }
        
        // Remove expired records
        expiredJtids.forEach(jti => {
            this.jtiStore.delete(jti);
        });
        
        // Log cleanup
        if (expiredJtids.length > 0) {
            this.logCleanup({
                removedCount: expiredJtids.length,
                timestamp: new Date()
            });
        }
    }
}
```

#### **C. Privilege Escalation through Scope Manipulation**
```javascript
// VULNERABLE: Insufficient scope validation
function validateScopeVulnerable(token, requiredScopes) {
    const payload = JSON.parse(atob(token.split('.')[1]));
    const tokenScopes = payload.scope ? payload.scope.split(' ') : [];
    
    // VULNERABLE: Only checks if user has required scopes
    const hasScopes = requiredScopes.every(scope => tokenScopes.includes(scope));
    
    if (hasScopes) {
        return { valid: true, scopes: tokenScopes };
    }
    
    return { valid: false, reason: 'Insufficient permissions' };
}

// SECURE: Comprehensive scope validation
class SecureScopeValidator {
    constructor(config) {
        this.scopeDefinitions = config.scopeDefinitions || {};
        this.permissionMatrix = config.permissionMatrix || {};
        this.hierarchicalScopes = config.hierarchicalScopes || {};
    }
    
    validateScopes(token, requiredScopes, resourceContext = {}) {
        const payload = this.parseToken(token);
        const tokenScopes = this.extractScopes(payload);
        
        // Step 1: Basic scope validation
        const basicValidation = this.validateBasicScopes(requiredScopes, tokenScopes);
        if (!basicValidation.valid) {
            return basicValidation;
        }
        
        // Step 2: Hierarchical scope validation
        const hierarchicalValidation = this.validateHierarchicalScopes(
            requiredScopes, tokenScopes
        );
        if (!hierarchicalValidation.valid) {
            return hierarchicalValidation;
        }
        
        // Step 3: Context-aware validation
        const contextValidation = this.validateContextualScopes(
            requiredScopes, tokenScopes, resourceContext
        );
        if (!contextValidation.valid) {
            return contextValidation;
        }
        
        // Step 4: Resource-specific validation
        const resourceValidation = this.validateResourceScopes(
            requiredScopes, tokenScopes, resourceContext
        );
        if (!resourceValidation.valid) {
            return resourceValidation;
        }
        
        // Step 5: Time-based scope validation
        const timeValidation = this.validateTemporalScopes(token, requiredScopes);
        if (!timeValidation.valid) {
            return timeValidation;
        }
        
        return {
            valid: true,
            scopes: tokenScopes,
            grantedScopes: requiredScopes,
            metadata: {
                validatedAt: new Date(),
                scopeValidationType: 'comprehensive',
                resourceContext: resourceContext
            }
        };
    }
    
    extractScopes(payload) {
        // Extract scopes from multiple possible locations
        let scopes = [];
        
        // Standard scope claim
        if (payload.scope) {
            scopes = payload.scope.split(' ').filter(s => s.trim());
        }
        
        // Custom scope claims
        if (payload.permissions) {
            scopes = scopes.concat(payload.permissions);
        }
        
        // Role-based claims
        if (payload.roles) {
            scopes = scopes.concat(this.rolesToScopes(payload.roles));
        }
        
        // Custom claims
        if (payload.customClaims && payload.customClaims.scopes) {
            scopes = scopes.concat(payload.customClaims.scopes);
        }
        
        // Remove duplicates and validate
        return [...new Set(scopes)].filter(scope => this.isValidScope(scope));
    }
    
    validateBasicScopes(requiredScopes, tokenScopes) {
        const missingScopes = requiredScopes.filter(
            scope => !tokenScopes.includes(scope)
        );
        
        if (missingScopes.length > 0) {
            return {
                valid: false,
                reason: 'Missing required scopes',
                missingScopes: missingScopes,
                validationType: 'basic'
            };
        }
        
        return { valid: true };
    }
    
    validateHierarchicalScopes(requiredScopes, tokenScopes) {
        for (const requiredScope of requiredScopes) {
            // Check if token has the required scope or a higher-level scope
            const hasScope = tokenScopes.includes(requiredScope) ||
                           this.hasHigherLevelScope(requiredScope, tokenScopes);
            
            if (!hasScope) {
                return {
                    valid: false,
                    reason: `No hierarchical access to scope: ${requiredScope}`,
                    requiredScope: requiredScope,
                    validationType: 'hierarchical'
                };
            }
        }
        
        return { valid: true };
    }
    
    hasHigherLevelScope(requiredScope, tokenScopes) {
        // Check if any token scope grants higher access than required
        for (const tokenScope of tokenScopes) {
            if (this.isScopeParent(tokenScope, requiredScope)) {
                return true;
            }
        }
        return false;
    }
    
    validateContextualScopes(requiredScopes, tokenScopes, context) {
        // Apply context-specific rules
        const contextRules = this.getContextualRules(context);
        
        for (const rule of contextRules) {
            const validation = this.applyContextualRule(rule, requiredScopes, tokenScopes);
            if (!validation.valid) {
                return {
                    valid: false,
                    reason: validation.reason,
                    context: context,
                    validationType: 'contextual'
                };
            }
        }
        
        return { valid: true };
    }
    
    applyContextualRule(rule, requiredScopes, tokenScopes) {
        switch (rule.type) {
            case 'time_restriction':
                return this.validateTimeRestriction(rule, requiredScopes, tokenScopes);
            case 'ip_restriction':
                return this.validateIpRestriction(rule, requiredScopes, tokenScopes);
            case 'resource_restriction':
                return this.validateResourceRestriction(rule, requiredScopes, tokenScopes);
            default:
                return { valid: true };
        }
    }
}
```

### **Attack Mitigation Strategies**

#### **1. Comprehensive Token Validation Framework**
```javascript
class ComprehensiveTokenValidator {
    constructor(config) {
        this.validationStages = [
            'structure',
            'signature', 
            'claims',
            'security',
            'context',
            'business_rules'
        ];
        
        this.config = config;
        this.securityRules = this.initializeSecurityRules();
        this.businessRules = this.initializeBusinessRules();
    }
    
    async validateToken(token, context = {}) {
        const validation = {
            valid: false,
            token: token,
            stages: {},
            metadata: {
                validatedAt: new Date(),
                validator: 'ComprehensiveTokenValidator',
                version: '2.0'
            }
        };
        
        try {
            // Stage 1: Structure validation
            const structureResult = await this.validateStructure(token);
            validation.stages.structure = structureResult;
            
            if (!structureResult.valid) {
                validation.reason = structureResult.reason;
                return validation;
            }
            
            // Stage 2: Signature validation
            const signatureResult = await this.validateSignature(token, structureResult.data);
            validation.stages.signature = signatureResult;
            
            if (!signatureResult.valid) {
                validation.reason = signatureResult.reason;
                return validation;
            }
            
            // Stage 3: Claims validation
            const claimsResult = await this.validateClaims(
                structureResult.data.payload, 
                context
            );
            validation.stages.claims = claimsResult;
            
            if (!claimsResult.valid) {
                validation.reason = claimsResult.reason;
                return validation;
            }
            
            // Stage 4: Security validations
            const securityResult = await this.validateSecurity(
                token, 
                structureResult.data, 
                context
            );
            validation.stages.security = securityResult;
            
            if (!securityResult.valid) {
                validation.reason = securityResult.reason;
                return validation;
            }
            
            // Stage 5: Context validation
            const contextResult = await this.validateContext(
                structureResult.data.payload,
                context
            );
            validation.stages.context = contextResult;
            
            if (!contextResult.valid) {
                validation.reason = contextResult.reason;
                return validation;
            }
            
            // Stage 6: Business rules validation
            const businessResult = await this.validateBusinessRules(
                structureResult.data.payload,
                context
            );
            validation.stages.business_rules = businessResult;
            
            if (!businessResult.valid) {
                validation.reason = businessResult.reason;
                return validation;
            }
            
            // All validations passed
            validation.valid = true;
            validation.payload = structureResult.data.payload;
            validation.header = structureResult.data.header;
            validation.metadata.jti = structureResult.data.payload.jti;
            validation.metadata.scopes = this.extractScopes(structureResult.data.payload);
            validation.metadata.context = context;
            
            return validation;
            
        } catch (error) {
            validation.valid = false;
            validation.reason = 'Validation process failed';
            validation.error = error.message;
            validation.metadata.error = error;
            
            return validation;
        }
    }
    
    async validateSecurity(token, parsedToken, context) {
        const securityChecks = [
            this.checkReplayAttack,
            this.checkAlgorithm,
            this.checkKeyStrength,
            this.checkTokenAge,
            this.checkUsagePattern
        ];
        
        for (const check of securityChecks) {
            const result = await check.call(this, token, parsedToken, context);
            
            if (!result.valid) {
                return result;
            }
        }
        
        return { valid: true };
    }
    
    async checkReplayAttack(token, parsedToken, context) {
        // Implement replay attack detection
        const jti = parsedToken.payload.jti;
        
        if (!jti) {
            return { 
                valid: false, 
                reason: 'Token missing jti claim - replay attack prevention requires jti' 
            };
        }
        
        // Check if token has been used before
        const usageRecord = await this.getTokenUsageRecord(jti);
        
        if (usageRecord && usageRecord.isBlocked) {
            return {
                valid: false,
                reason: 'Token has been flagged for security reasons',
                jti: jti
            };
        }
        
        // Record token usage
        await this.recordTokenUsage({
            jti: jti,
            ip: context.clientIp,
            userAgent: context.userAgent,
            timestamp: new Date(),
            tokenPreview: token.substring(0, 20) + '...'
        });
        
        return { valid: true };
    }
    
    async checkAlgorithm(token, parsedToken, context) {
        const { header } = parsedToken;
        const allowedAlgorithms = this.config.allowedAlgorithms || ['RS256', 'ES256'];
        
        if (!allowedAlgorithms.includes(header.alg)) {
            // Log potential algorithm substitution attack
            await this.logSecurityEvent({
                type: 'algorithm_substitution_attempt',
                algorithm: header.alg,
                allowedAlgorithms: allowedAlgorithms,
                tokenPreview: token.substring(0, 20) + '...',
                timestamp: new Date()
            });
            
            return { 
                valid: false, 
                reason: `Algorithm not allowed: ${header.alg}` 
            };
        }
        
        // Check for algorithm confusion attacks
        if (header.alg === 'none' || header.alg === 'NULL') {
            return { 
                valid: false, 
                reason: 'Insecure algorithm detected' 
            };
        }
        
        return { valid: true };
    }
    
    async checkKeyStrength(token, parsedToken, context) {
        const { header } = parsedToken;
        
        // For RSA algorithms, check key size
        if (header.alg.startsWith('RS') || header.alg.startsWith('PS')) {
            const keySize = await this.getKeySize(header.kid);
            
            if (keySize && keySize < 2048) {
                await this.logSecurityEvent({
                    type: 'weak_key_detected',
                    keySize: keySize,
                    algorithm: header.alg,
                    timestamp: new Date()
                });
                
                return {
                    valid: false,
                    reason: `Insufficient key strength: ${keySize} bits (minimum 2048 required)`
                };
            }
        }
        
        // For ECDSA algorithms, check curve
        if (header.alg.startsWith('ES')) {
            const curve = this.getCurveFromHeader(header);
            const allowedCurves = this.config.allowedCurves || ['P-256', 'P-384', 'P-521'];
            
            if (!allowedCurves.includes(curve)) {
                return {
                    valid: false,
                    reason: `Curve not allowed: ${curve}`
                };
            }
        }
        
        return { valid: true };
    }
}
```

#### **2. Token Lifecycle Security**
```javascript
class TokenLifecycleSecurity {
    constructor(config) {
        this.rotationInterval = config.rotationInterval || 3600000; // 1 hour
        this.maxTokenAge = config.maxTokenAge || 86400000; // 24 hours
        this.invalidationReasons = new Map();
    }
    
    manageTokenLifecycle(tokenData) {
        return {
            create: () => this.createTokenSecurely(tokenData),
            rotate: () => this.rotateTokenSecurely(tokenData),
            invalidate: (reason) => this.invalidateToken(tokenData.jti, reason),
            validate: () => this.validateTokenSecurely(tokenData.token),
            cleanup: () => this.cleanupExpiredTokens()
        };
    }
    
    createTokenSecurely(tokenData) {
        // Generate secure token with all security measures
        const token = {
            jti: this.generateSecureJti(),
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (this.rotationInterval / 1000),
            nbf: Math.floor(Date.now() / 1000), // Not before
            iss: tokenData.issuer,
            aud: tokenData.audience,
            sub: tokenData.subject,
            scope: tokenData.scopes.join(' '),
            client_id: tokenData.clientId,
            token_type: 'Bearer',
            // Additional security claims
            auth_time: Math.floor(Date.now() / 1000),
            acr: tokenData.acrValue || 'urn:mace:incommon:iap:interactive',
            amr: tokenData.authenticationMethods || ['pwd'],
            azp: tokenData.authorizedParty,
            // Custom claims for business logic
            session_id: tokenData.sessionId,
            device_id: tokenData.deviceId,
            ip_hash: this.hashClientIp(tokenData.clientIp)
        };
        
        // Sign token with secure algorithm
        const signedToken = this.signToken(token);
        
        // Store token metadata for validation
        this.storeTokenMetadata(token.jti, {
            token: signedToken,
            payload: token,
            createdAt: new Date(),
            lastUsed: null,
            usageCount: 0,
            clientId: tokenData.clientId,
            subject: tokenData.subject,
            scopes: tokenData.scopes,
            metadata: tokenData.metadata
        });
        
        return signedToken;
    }
    
    async rotateTokenSecurely(tokenData) {
        const oldToken = await this.getTokenByJti(tokenData.jti);
        
        if (!oldToken) {
            throw new Error('Original token not found');
        }
        
        // Validate old token is still valid
        const validation = await this.validateTokenSecurely(oldToken.token);
        
        if (!validation.valid) {
            throw new Error('Cannot rotate invalid token');
        }
        
        // Check if rotation is due
        const tokenAge = Date.now() - (validation.payload.iat * 1000);
        
        if (tokenAge < this.rotationInterval * 0.8) { // 80% of rotation interval
            throw new Error('Token rotation not yet due');
        }
        
        // Create new token
        const newTokenData = {
            ...tokenData,
            jti: this.generateSecureJti(),
            sessionId: oldToken.sessionId, // Maintain session
            deviceId: oldToken.deviceId,
            metadata: {
                ...oldToken.metadata,
                rotated: true,
                previousJti: tokenData.jti
            }
        };
        
        const newToken = this.createTokenSecurely(newTokenData);
        
        // Invalidate old token
        this.invalidateToken(oldToken.jti, 'rotated');
        
        return {
            newToken: newToken,
            oldTokenInvalidated: true,
            rotationReason: 'scheduled'
        };
    }
    
    invalidateToken(jti, reason) {
        const invalidation = {
            jti: jti,
            reason: reason,
            timestamp: new Date(),
            invalidatedBy: 'system' // or user/session ID
        };
        
        this.invalidationReasons.set(jti, invalidation);
        
        // Remove from active tokens
        this.removeActiveToken(jti);
        
        // Log invalidation event
        this.logTokenInvalidation(invalidation);
        
        return true;
    }
    
    async validateTokenSecurely(token) {
        // Parse token
        const parsedToken = this.parseToken(token);
        
        // Check if token is invalidated
        if (this.invalidationReasons.has(parsedToken.payload.jti)) {
            const invalidation = this.invalidationReasons.get(parsedToken.payload.jti);
            
            return {
                valid: false,
                reason: 'Token has been invalidated',
                invalidation: invalidation,
                jti: parsedToken.payload.jti
            };
        }
        
        // Perform comprehensive validation
        const validation = await this.comprehensiveValidation(token);
        
        // Update usage statistics
        if (validation.valid) {
            this.updateTokenUsage(parsedToken.payload.jti, {
                lastUsed: new Date(),
                usageCount: 1
            });
        }
        
        return validation;
    }
}
```

---

## Security Monitoring and Alerting

### **Implementation of Security Monitoring**
```javascript
class OAuthSecurityMonitor {
    constructor(config) {
        this.alertThresholds = config.alertThresholds || {};
        this.monitoringRules = config.monitoringRules || [];
        this.notificationChannels = config.notificationChannels || [];
    }
    
    monitorSecurityEvents() {
        // Monitor for attack patterns
        const events = [
            'invalid_signature_attempts',
            'replay_attacks_detected',
            'scope_escalation_attempts',
            'token_forgery_attempts',
            'client_authentication_failures',
            'unusual_usage_patterns'
        ];
        
        events.forEach(eventType => {
            this.setupEventMonitoring(eventType);
        });
    }
    
    setupEventMonitoring(eventType) {
        // Set up real-time monitoring for each event type
        this.eventStream.on(eventType, async (eventData) => {
            await this.processSecurityEvent(eventType, eventData);
        });
    }
    
    async processSecurityEvent(eventType, eventData) {
        // Analyze event for attack patterns
        const analysis = await this.analyzeSecurityEvent(eventType, eventData);
        
        if (analysis.threatLevel >= this.getThreatThreshold(eventType)) {
            await this.triggerAlert(eventType, analysis);
        }
        
        // Update threat intelligence
        await this.updateThreatIntelligence(eventType, eventData);
        
        // Apply automated response if configured
        if (this.shouldApplyAutomatedResponse(eventType, analysis)) {
            await this.applyAutomatedResponse(eventType, analysis);
        }
    }
    
    async analyzeSecurityEvent(eventType, eventData) {
        const analysis = {
            eventType: eventType,
            threatLevel: 'low',
            indicators: [],
            recommendations: []
        };
        
        switch (eventType) {
            case 'invalid_signature_attempts':
                analysis.threatLevel = this.calculateSignatureAttackThreat(eventData);
                analysis.indicators = this.extractSignatureAttackIndicators(eventData);
                break;
                
            case 'replay_attacks_detected':
                analysis.threatLevel = this.calculateReplayAttackThreat(eventData);
                analysis.indicators = this.extractReplayAttackIndicators(eventData);
                break;
                
            case 'unusual_usage_patterns':
                analysis.threatLevel = this.calculateUsagePatternThreat(eventData);
                analysis.indicators = this.extractUsagePatternIndicators(eventData);
                break;
        }
        
        return analysis;
    }
}
```

---

## Conclusion

OAuth 2.0 security requires a comprehensive approach addressing all attack vectors. The three critical areas - Client Registration and Authentication, Token Storage and Transmission, and Token Validation - must be implemented with defense-in-depth strategies.

### **Key Security Principles:**
1. **Never Trust Client Input**: Validate all client-provided data
2. **Encrypt Everything**: Use HTTPS for all transmissions
3. **Validate Everything**: Verify tokens, signatures, claims, and scopes
4. **Monitor Continuously**: Track security events and anomalous behavior
5. **Plan for Compromise**: Implement token rotation and revocation mechanisms
6. **Defense in Depth**: Layer multiple security controls
7. **Regular Security Reviews**: Continuously assess and improve security posture

### **Implementation Checklist:**
- [ ] Secure client registration with verification
- [ ] Rate limiting on all authentication endpoints
- [ ] HTTPS-only token transmission
- [ ] Secure token storage with encryption
- [ ] Comprehensive token validation
- [ ] Replay attack prevention
- [ ] Scope validation and enforcement
- [ ] Security monitoring and alerting
- [ ] Incident response procedures
- [ ] Regular security audits

By implementing these comprehensive security measures, organizations can significantly reduce the risk of OAuth 2.0 attacks while maintaining a secure and user-friendly authentication experience.