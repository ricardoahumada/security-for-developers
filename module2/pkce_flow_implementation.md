# PKCE Flow Implementation

## Complete PKCE Implementation for Public Clients

This implementation provides a comprehensive example of OAuth 2.0 Authorization Code Flow with PKCE (Proof Key for Code Exchange) for public clients, including mobile applications and single-page applications.

```javascript
// PKCE Configuration
const PKCEConfig = {
    // Google OAuth with PKCE
    google: {
        authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenEndpoint: 'https://oauth2.googleapis.com/token',
        clientId: 'your-google-client-id.googleusercontent.com',
        // Note: No client secret for PKCE (public client)
        scopes: [
            'openid',
            'profile',
            'email',
            'https://www.googleapis.com/auth/drive.readonly'
        ],
        redirectUri: 'https://yourapp.com/auth/google/callback'
    },
    
    // Auth0 PKCE Configuration
    auth0: {
        authorizationEndpoint: 'https://your-tenant.auth0.com/authorize',
        tokenEndpoint: 'https://your-tenant.auth0.com/oauth/token',
        clientId: 'your-auth0-client-id',
        scopes: ['openid', 'profile', 'email'],
        redirectUri: 'https://yourapp.com/callback',
        additionalParams: {
            audience: 'https://api.yourapp.com',
            response_type: 'code'
        }
    },

    // Generic PKCE Configuration
    generic: {
        authorizationEndpoint: 'https://auth.provider.com/authorize',
        tokenEndpoint: 'https://auth.provider.com/token',
        clientId: 'your-client-id',
        scopes: ['read', 'write', 'profile'],
        redirectUri: 'https://yourapp.com/callback'
    }
};

// PKCE Flow Implementation
class PKCEFlow {
    constructor(config) {
        this.config = {
            clientId: config.clientId,
            authorizationEndpoint: config.authorizationEndpoint,
            tokenEndpoint: config.tokenEndpoint,
            redirectUri: config.redirectUri,
            scopes: config.scopes || [],
            codeVerifierStore: new Map(),
            stateStore: new Map(),
            ...config
        };
        
        // Validate PKCE requirements
        this.validatePKCERequirements();
    }

    validatePKCERequirements() {
        if (!this.config.clientId) {
            throw new Error('Client ID is required for PKCE flow');
        }

        if (this.config.clientSecret) {
            console.warn('PKCE flow does not require client secret for public clients');
        }

        if (!this.config.authorizationEndpoint) {
            throw new Error('Authorization endpoint is required');
        }

        if (!this.config.tokenEndpoint) {
            throw new Error('Token endpoint is required');
        }
    }

    // Step 1: Generate PKCE parameters
    generatePKCEParameters() {
        const codeVerifier = this.generateCodeVerifier();
        const codeChallenge = this.generateCodeChallenge(codeVerifier);
        const state = this.generateSecureRandomString();
        const nonce = this.generateSecureRandomString();

        // Store PKCE parameters securely
        const pkceData = {
            codeVerifier: codeVerifier,
            state: state,
            nonce: nonce,
            timestamp: Date.now(),
            expiration: Date.now() + (10 * 60 * 1000), // 10 minutes
            clientId: this.config.clientId,
            redirectUri: this.config.redirectUri,
            scopes: this.config.scopes
        };

        // Store with expiration
        this.codeVerifierStore.set(codeVerifier, pkceData);
        this.stateStore.set(state, { ...pkceData, codeVerifier });

        // Schedule cleanup
        setTimeout(() => {
            this.codeVerifierStore.delete(codeVerifier);
            this.stateStore.delete(state);
        }, 10 * 60 * 1000);

        return {
            codeVerifier: codeVerifier,
            codeChallenge: codeChallenge,
            state: state,
            nonce: nonce,
            method: 'S256'
        };
    }

    // Generate cryptographically secure code verifier
    generateCodeVerifier(length = 64) {
        if (length < 43 || length > 128) {
            throw new Error('Code verifier length must be between 43 and 128 characters');
        }

        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        
        // Convert to base64url string
        const base64String = btoa(String.fromCharCode(...array));
        return base64String
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '')
            .substring(0, length);
    }

    // Generate code challenge from code verifier
    async generateCodeChallenge(codeVerifier) {
        // Validate code verifier format
        if (!this.validateCodeVerifier(codeVerifier)) {
            throw new Error('Invalid code verifier format');
        }

        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        const digest = await crypto.subtle.digest('SHA-256', data);
        
        // Convert digest to base64url
        const base64Digest = btoa(String.fromCharCode(...new Uint8Array(digest)));
        return base64Digest
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    // Validate code verifier format
    validateCodeVerifier(codeVerifier) {
        // Must be 43-128 characters
        if (codeVerifier.length < 43 || codeVerifier.length > 128) {
            return false;
        }

        // Must contain only unreserved characters
        // unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
        return /^[A-Za-z0-9\-._~]+$/.test(codeVerifier);
    }

    // Generate secure random string for state and nonce
    generateSecureRandomString(length = 32) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return Array.from(array, byte => 
            ('0' + byte.toString(16)).slice(-2)
        ).join('');
    }

    // Step 2: Build authorization request URL
    buildAuthorizationUrl(pkceParams) {
        const params = {
            response_type: 'code',
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            scope: this.config.scopes.join(' '),
            state: pkceParams.state,
            nonce: pkceParams.nonce,
            code_challenge: pkceParams.codeChallenge,
            code_challenge_method: 'S256',
            // Additional parameters for better UX and security
            access_type: 'offline',
            prompt: 'consent',
            ...this.config.additionalParams
        };

        const url = new URL(this.config.authorizationEndpoint);
        Object.keys(params).forEach(key => {
            if (params[key] !== null && params[key] !== undefined) {
                url.searchParams.append(key, params[key]);
            }
        });

        return url.toString();
    }

    // Step 3: Initiate PKCE authorization flow
    initiateAuthorization() {
        console.log('Initiating PKCE Authorization Flow...');
        
        const pkceParams = this.generatePKCEParameters();
        const authorizationUrl = this.buildAuthorizationUrl(pkceParams);

        // Log PKCE initiation for security audit
        console.log('PKCE Flow Initiated:', {
            clientId: this.config.clientId,
            state: pkceParams.state.substring(0, 8) + '...',
            codeChallenge: pkceParams.codeChallenge.substring(0, 16) + '...'
        });

        return {
            authorizationUrl: authorizationUrl,
            pkceParams: pkceParams
        };
    }

    // Step 4: Handle authorization callback
    async handleCallback(callbackUrl) {
        const url = new URL(callbackUrl);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        const error = url.searchParams.get('error');

        // Handle OAuth errors
        if (error) {
            throw new PKCEError('OAUTH_ERROR', `${error}: ${url.searchParams.get('error_description')}`);
        }

        // Validate parameters
        if (!code) {
            throw new PKCEError('MISSING_CODE', 'Authorization code is missing');
        }

        if (!state) {
            throw new PKCEError('MISSING_STATE', 'State parameter is missing');
        }

        // Validate state and retrieve PKCE data
        const pkceData = this.validateStateAndRetrieveData(state);
        
        // Clean up used state
        this.stateStore.delete(state);

        return {
            authorizationCode: code,
            state: state,
            pkceData: pkceData
        };
    }

    // Validate state parameter and retrieve associated PKCE data
    validateStateAndRetrieveData(state) {
        const stateData = this.stateStore.get(state);
        
        if (!stateData) {
            console.error('Invalid state parameter:', state);
            throw new PKCEError('INVALID_STATE', 'State parameter is invalid or expired');
        }

        // Check expiration
        if (Date.now() > stateData.expiration) {
            console.error('Expired state parameter:', state);
            this.stateStore.delete(state);
            throw new PKCEError('STATE_EXPIRED', 'State parameter has expired');
        }

        // Additional validation
        if (stateData.clientId !== this.config.clientId) {
            console.error('State client ID mismatch:', {
                expected: this.config.clientId,
                actual: stateData.clientId
            });
            throw new PKCEError('CLIENT_MISMATCH', 'Client ID mismatch in state');
        }

        return stateData;
    }

    // Step 5: Exchange authorization code for tokens
    async exchangeCodeForTokens(authorizationCode, pkceData) {
        console.log('Exchanging authorization code for tokens...');

        // Validate authorization code
        const validation = await this.validateAuthorizationCode(authorizationCode, pkceData);
        if (!validation.valid) {
            throw new PKCEError('INVALID_CODE', validation.reason);
        }

        // Prepare token request with PKCE verification
        const tokenRequest = this.buildTokenRequest(authorizationCode, pkceData);
        
        try {
            // Make token request
            const tokenResponse = await this.makeTokenRequest(tokenRequest);
            
            // Validate and process token response
            const tokenData = this.validateTokenResponse(tokenResponse);
            
            // Store tokens securely
            const storedTokens = await this.storeTokens(tokenData, pkceData);
            
            console.log('Token exchange successful');
            
            return {
                accessToken: tokenData.access_token,
                refreshToken: tokenData.refresh_token,
                idToken: tokenData.id_token,
                expiresIn: tokenData.expires_in,
                tokenType: tokenData.token_type,
                scope: tokenData.scope,
                storedTokens: storedTokens
            };

        } catch (error) {
            if (error.name === 'TokenRequestError') {
                throw new PKCEError('TOKEN_EXCHANGE_FAILED', error.message);
            }
            throw new PKCEError('TOKEN_EXCHANGE_FAILED', `Token exchange failed: ${error.message}`);
        }
    }

    // Build token request with PKCE verification
    buildTokenRequest(authorizationCode, pkceData) {
        const tokenRequest = {
            grant_type: 'authorization_code',
            client_id: this.config.clientId,
            code: authorizationCode,
            redirect_uri: pkceData.redirectUri,
            code_verifier: pkceData.codeVerifier
        };

        // Validate code verifier
        if (!pkceData.codeVerifier) {
            throw new PKCEError('MISSING_CODE_VERIFIER', 'Code verifier is missing');
        }

        // Validate code verifier format
        if (!this.validateCodeVerifier(pkceData.codeVerifier)) {
            throw new PKCEError('INVALID_CODE_VERIFIER', 'Code verifier format is invalid');
        }

        return tokenRequest;
    }

    // Validate authorization code with authorization server
    async validateAuthorizationCode(code, pkceData) {
        // In a real implementation, you might validate with the authorization server
        // For this example, we'll simulate basic validation
        
        // Check code format
        if (!code || code.length < 10) {
            return { valid: false, reason: 'Authorization code is too short' };
        }

        // Additional validation logic would go here
        return { valid: true };
    }

    // Make token request to authorization server
    async makeTokenRequest(tokenRequest) {
        const headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        };

        // Note: No client secret authentication for PKCE flow
        // PKCE replaces the need for client secret in public clients

        const response = await fetch(this.config.tokenEndpoint, {
            method: 'POST',
            headers: headers,
            body: new URLSearchParams(tokenRequest)
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new TokenRequestError(
                errorData.error || 'token_request_failed',
                errorData.error_description || `Token request failed with status ${response.status}`,
                response.status,
                errorData
            );
        }

        return await response.json();
    }

    // Validate token response
    validateTokenResponse(response) {
        const requiredFields = ['access_token'];
        const missingFields = requiredFields.filter(field => !response[field]);

        if (missingFields.length > 0) {
            throw new PKCEError('INVALID_TOKEN_RESPONSE', 
                `Missing required fields: ${missingFields.join(', ')}`);
        }

        // Set expiration timestamp
        if (response.expires_in) {
            response.expires_at = Date.now() + (response.expires_in * 1000);
        }

        return response;
    }

    // Store tokens securely
    async storeTokens(tokenData, pkceData) {
        const tokenId = this.generateSecureRandomString(16);
        
        const tokenRecord = {
            tokenId: tokenId,
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token,
            idToken: tokenData.id_token,
            expiresAt: tokenData.expires_at,
            scope: tokenData.scope,
            tokenType: tokenData.token_type,
            userId: pkceData.userId || null,
            createdAt: new Date().toISOString(),
            clientId: this.config.clientId,
            // PKCE-specific data
            codeVerifier: pkceData.codeVerifier,
            authMethod: 'pkce'
        };

        // Store securely (implement based on your storage solution)
        await this.secureStorage.set(`pkce_token:${tokenId}`, tokenRecord);
        
        // Clean up PKCE parameters
        this.codeVerifierStore.delete(pkceData.codeVerifier);

        return {
            tokenId: tokenId,
            tokenRecord: tokenRecord
        };
    }

    // Refresh access token using refresh token
    async refreshAccessToken(refreshToken) {
        const tokenRequest = {
            grant_type: 'refresh_token',
            client_id: this.config.clientId,
            refresh_token: refreshToken
        };

        const tokenResponse = await this.makeTokenRequest(tokenRequest);
        const tokenData = this.validateTokenResponse(tokenResponse);

        // Update stored tokens
        const updatedTokens = await this.updateStoredTokens(refreshToken, tokenData);
        
        return {
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token || refreshToken,
            expiresIn: tokenData.expires_in,
            tokenType: tokenData.token_type,
            updatedTokens: updatedTokens
        };
    }

    async updateStoredTokens(oldRefreshToken, newTokenData) {
        // Find token record with the refresh token
        const tokenRecords = await this.secureStorage.findByRefreshToken(oldRefreshToken);
        
        if (tokenRecords.length === 0) {
            throw new PKCEError('INVALID_REFRESH_TOKEN', 'No valid token record found');
        }

        // Update token record
        const tokenRecord = tokenRecords[0];
        tokenRecord.accessToken = newTokenData.access_token;
        tokenRecord.refreshToken = newTokenData.refresh_token || oldRefreshToken;
        tokenRecord.expiresAt = newTokenData.expires_at;
        tokenRecord.updatedAt = new Date().toISOString();

        await this.secureStorage.update(tokenRecord.tokenId, tokenRecord);
        
        return tokenRecord;
    }

    // Check if access token is expired
    isTokenExpired(tokenData) {
        return tokenData.expires_at && Date.now() >= tokenData.expires_at;
    }

    // Ensure valid access token
    async ensureValidAccessToken(tokenId) {
        const tokenRecord = await this.secureStorage.get(`pkce_token:${tokenId}`);
        if (!tokenRecord) {
            throw new PKCEError('TOKEN_NOT_FOUND', 'Token record not found');
        }

        if (this.isTokenExpired(tokenRecord)) {
            if (tokenRecord.refreshToken) {
                const refreshedTokens = await this.refreshAccessToken(tokenRecord.refreshToken);
                return refreshedTokens.accessToken;
            }
            throw new PKCEError('TOKEN_EXPIRED', 'Token expired and no refresh token available');
        }

        return tokenRecord.accessToken;
    }
}

// Error Classes
class PKCEError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'PKCEError';
        this.code = code;
    }
}

class TokenRequestError extends Error {
    constructor(error, description, statusCode, details = {}) {
        super(description);
        this.name = 'TokenRequestError';
        this.error = error;
        this.statusCode = statusCode;
        this.details = details;
    }
}

// Secure Storage Interface (implement based on your storage solution)
class SecureStorage {
    constructor() {
        this.storage = new Map();
    }

    async set(key, value) {
        this.storage.set(key, JSON.stringify(value));
    }

    async get(key) {
        const stored = this.storage.get(key);
        return stored ? JSON.parse(stored) : null;
    }

    async update(key, value) {
        this.storage.set(key, JSON.stringify(value));
    }

    async findByRefreshToken(refreshToken) {
        const results = [];
        for (const [key, value] of this.storage.entries()) {
            if (key.startsWith('pkce_token:')) {
                const tokenRecord = JSON.parse(value);
                if (tokenRecord.refreshToken === refreshToken) {
                    results.push(tokenRecord);
                }
            }
        }
        return results;
    }
}

// Complete Example Usage
class ExamplePKCEApp {
    constructor(provider = 'google') {
        this.config = PKCEConfig[provider];
        this.storage = new SecureStorage();
        this.pkceFlow = new PKCEFlow(this.config);
        this.pkceFlow.secureStorage = this.storage;
    }

    // Simulate frontend initiation
    initiateLogin() {
        const { authorizationUrl, pkceParams } = this.pkceFlow.initiateAuthorization();
        
        console.log('Redirecting to authorization server...');
        console.log('PKCE Parameters:', {
            codeChallenge: pkceParams.codeChallenge.substring(0, 16) + '...',
            state: pkceParams.state.substring(0, 8) + '...',
            method: pkceParams.method
        });

        return authorizationUrl;
    }

    // Simulate callback handling
    async handleCallback(callbackUrl) {
        try {
            const { authorizationCode, pkceData } = await this.pkceFlow.handleCallback(callbackUrl);
            
            console.log('Authorization code received:', authorizationCode.substring(0, 16) + '...');
            
            const tokenData = await this.pkceFlow.exchangeCodeForTokens(authorizationCode, pkceData);
            
            console.log('Token exchange successful');
            console.log('Access token:', tokenData.accessToken.substring(0, 20) + '...');
            
            return {
                success: true,
                tokens: tokenData,
                userInfo: this.decodeUserInfo(tokenData.idToken)
            };

        } catch (error) {
            console.error('PKCE callback failed:', error.message);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Decode ID token (simplified - in production use proper JWT library)
    decodeUserInfo(idToken) {
        if (!idToken) return null;
        
        try {
            const parts = idToken.split('.');
            if (parts.length !== 3) return null;
            
            const payload = JSON.parse(atob(parts[1]));
            return {
                userId: payload.sub,
                email: payload.email,
                name: payload.name,
                expiresAt: payload.exp * 1000
            };
        } catch (error) {
            return null;
        }
    }

    // Example API call with token
    async makeAuthenticatedRequest(endpoint, tokenId) {
        try {
            const accessToken = await this.pkceFlow.ensureValidAccessToken(tokenId);
            
            const response = await fetch(endpoint, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`API request failed: ${response.status}`);
            }

            return await response.json();

        } catch (error) {
            console.error('Authenticated request failed:', error);
            throw error;
        }
    }
}

// Demo Function
async function demonstratePKCEFlow() {
    console.log('=== PKCE Flow Demo ===\n');

    const app = new ExamplePKCEApp('google');

    try {
        // Step 1: Initiate PKCE flow
        console.log('1. Initiating PKCE Flow...');
        const authorizationUrl = app.initiateLogin();
        console.log('Authorization URL generated\n');

        // Step 2: Simulate callback
        console.log('2. Simulating OAuth Callback...');
        const mockCallbackUrl = 'https://yourapp.com/auth/google/callback?code=mock_auth_code&state=mock_state';
        
        // In a real scenario, this would be called after user completes OAuth
        const authResult = await app.handleCallback(mockCallbackUrl);
        
        if (authResult.success) {
            console.log('✓ PKCE flow completed successfully');
            console.log('Access Token:', authResult.tokens.accessToken.substring(0, 20) + '...');
            
            if (authResult.userInfo) {
                console.log('User Info:', {
                    userId: authResult.userInfo.userId,
                    email: authResult.userInfo.email
                });
            }
        } else {
            console.log('✗ PKCE flow failed:', authResult.error);
        }

    } catch (error) {
        console.error('PKCE demo failed:', error.message);
    }

    console.log('\n=== PKCE Flow Demo Complete ===');
}

// PKCE vs Authorization Code Comparison
function comparePKCEFlows() {
    console.log('\n=== PKCE vs Authorization Code Flow Comparison ===');
    
    const comparison = {
        clientTypes: {
            authorizationCode: 'Confidential clients (server-side)',
            pkce: 'Public clients (mobile, SPA, desktop)'
        },
        authentication: {
            authorizationCode: 'Client secret required',
            pkce: 'Code verifier/challenge only'
        },
        security: {
            authorizationCode: 'High (with client secret)',
            pkce: 'High (with PKCE mechanism)'
        },
        complexity: {
            authorizationCode: 'Medium',
            pkce: 'Medium-High (PKCE implementation)'
        },
        browserSupport: {
            authorizationCode: 'Requires server-side implementation',
            pkce: 'Requires Web Crypto API support'
        }
    };

    Object.keys(comparison).forEach(aspect => {
        console.log(`\n${aspect.toUpperCase()}:`);
        console.log(`  Authorization Code: ${comparison[aspect].authorizationCode}`);
        console.log(`  PKCE: ${comparison[aspect].pkce}`);
    });
}

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        PKCEFlow,
        PKCEError,
        TokenRequestError,
        SecureStorage,
        ExamplePKCEApp,
        PKCEConfig,
        demonstratePKCEFlow,
        comparePKCEFlows
    };
} else {
    window.PKCEFlow = {
        PKCEFlow,
        PKCEError,
        TokenRequestError,
        SecureStorage,
        ExamplePKCEApp,
        PKCEConfig
    };
}

// Run demo if executed directly
if (typeof window === 'undefined') {
    demonstratePKCEFlow();
    comparePKCEFlows();
}
```

## PKCE Security Benefits

### What PKCE Protects Against

1. **Authorization Code Interception**
   - Without PKCE: Attacker intercepts code and exchanges for token
   - With PKCE: Attacker needs both code AND code verifier

2. **Code Injection Attacks**
   - PKCE parameters must match exactly
   - State parameter provides additional CSRF protection

3. **Public Client Limitations**
   - No client secret required
   - Prevents client impersonation
   - Maintains security without infrastructure dependencies

### Implementation Checklist

- [ ] Generate cryptographically random code verifiers (43-128 characters)
- [ ] Use SHA256 for code challenge generation
- [ ] Validate code verifier format and length
- [ ] Store PKCE parameters securely with expiration
- [ ] Include state parameter for CSRF protection
- [ ] Validate all parameters on callback
- [ ] Clean up used PKCE parameters
- [ ] Implement proper error handling
- [ ] Test with multiple browsers and mobile platforms
- [ ] Monitor PKCE failures for security analysis

PKCE provides enterprise-grade security for public clients without requiring complex infrastructure, making it the recommended choice for mobile applications and modern web applications.
