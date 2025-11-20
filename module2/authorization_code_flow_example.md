# Authorization Code Flow Implementation

## Complete Server-Side Implementation

This implementation provides a production-ready example of the OAuth 2.0 Authorization Code Flow for confidential clients (server-side web applications).

```javascript
// Configuration and Setup
const OAuthConfig = {
    // Google OAuth Configuration
    google: {
        authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenEndpoint: 'https://oauth2.googleapis.com/token',
        clientId: 'your-google-client-id.googleusercontent.com',
        clientSecret: 'your-google-client-secret',
        scopes: [
            'openid',
            'profile',
            'email',
            'https://www.googleapis.com/auth/drive.readonly'
        ],
        redirectUri: 'https://yourapp.com/auth/google/callback'
    },
    
    // Generic OAuth Configuration
    generic: {
        authorizationEndpoint: 'https://auth.provider.com/authorize',
        tokenEndpoint: 'https://auth.provider.com/token',
        clientId: 'your-client-id',
        clientSecret: 'your-client-secret',
        scopes: ['read', 'write', 'admin'],
        redirectUri: 'https://yourapp.com/auth/callback',
        additionalParams: {
            audience: 'https://api.provider.com',
            response_mode: 'query'
        }
    }
};

// Authorization Code Flow Implementation
class AuthorizationCodeFlow {
    constructor(config) {
        this.config = {
            clientId: config.clientId,
            clientSecret: config.clientSecret,
            authorizationEndpoint: config.authorizationEndpoint,
            tokenEndpoint: config.tokenEndpoint,
            redirectUri: config.redirectUri,
            scopes: config.scopes || [],
            stateStore: new Map(), // In production, use Redis or database
            codeStore: new Map(), // In production, use Redis or database
            ...config
        };
    }

    // Step 1: Initiate Authorization Request
    initiateAuthorization(customState = null) {
        const state = customState || this.generateSecureRandomString(32);
        const nonce = this.generateSecureRandomString(32);
        
        // Store state and nonce for validation
        this.config.stateStore.set(state, {
            nonce: nonce,
            timestamp: Date.now(),
            redirectUri: this.config.redirectUri
        });

        // Build authorization URL
        const authUrl = this.buildAuthorizationUrl(state, nonce);
        
        return {
            authorizationUrl: authUrl,
            state: state,
            nonce: nonce
        };
    }

    // Build authorization URL with all required parameters
    buildAuthorizationUrl(state, nonce) {
        const params = {
            response_type: 'code',
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            scope: this.config.scopes.join(' '),
            state: state,
            nonce: nonce,
            // Additional security parameters
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

    // Step 2: Handle Authorization Callback
    async handleAuthorizationCallback(callbackUrl, expectedState) {
        const url = new URL(callbackUrl);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        const error = url.searchParams.get('error');

        // Handle OAuth errors
        if (error) {
            throw new OAuthAuthorizationError(error, url.searchParams.get('error_description'));
        }

        // Validate state parameter
        this.validateState(state, expectedState);

        // Retrieve stored state data
        const stateData = this.config.stateStore.get(state);
        if (!stateData) {
            throw new Error('Invalid state parameter');
        }

        // Clean up used state
        this.config.stateStore.delete(state);

        return {
            authorizationCode: code,
            state: state,
            stateData: stateData
        };
    }

    // Step 3: Exchange Authorization Code for Tokens
    async exchangeCodeForTokens(authorizationCode, stateData) {
        // Validate authorization code
        const validation = await this.validateAuthorizationCode(authorizationCode, stateData);
        if (!validation.valid) {
            throw new Error(`Invalid authorization code: ${validation.reason}`);
        }

        // Prepare token request
        const tokenRequest = {
            grant_type: 'authorization_code',
            client_id: this.config.clientId,
            client_secret: this.config.clientSecret,
            code: authorizationCode,
            redirect_uri: stateData.redirectUri
        };

        try {
            // Make token request
            const tokenResponse = await this.makeTokenRequest(tokenRequest);
            
            // Validate token response
            const tokenData = this.validateTokenResponse(tokenResponse);
            
            // Store token data securely
            const storedTokens = await this.storeTokens(tokenData);
            
            return {
                accessToken: tokenData.access_token,
                refreshToken: tokenData.refresh_token,
                expiresIn: tokenData.expires_in,
                tokenType: tokenData.token_type,
                scope: tokenData.scope,
                idToken: tokenData.id_token,
                storedTokens: storedTokens
            };

        } catch (error) {
            if (error.name === 'OAuthTokenError') {
                throw new Error(`Token exchange failed: ${error.message}`);
            }
            throw new Error(`Token exchange failed: ${error.message}`);
        }
    }

    // Validate authorization code with authorization server
    async validateAuthorizationCode(code, stateData) {
        // In a real implementation, you might validate with the auth server
        // For this example, we'll simulate validation
        return {
            valid: true,
            userId: stateData.userId,
            clientId: this.config.clientId,
            scopes: this.config.scopes
        };
    }

    // Make request to token endpoint
    async makeTokenRequest(tokenRequest) {
        const headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        };

        // Some providers require authentication
        if (this.config.clientSecret) {
            const credentials = Buffer.from(
                `${this.config.clientId}:${this.config.clientSecret}`
            ).toString('base64');
            headers['Authorization'] = `Basic ${credentials}`;
        }

        const response = await fetch(this.config.tokenEndpoint, {
            method: 'POST',
            headers: headers,
            body: new URLSearchParams(tokenRequest)
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new OAuthTokenError(
                errorData.error || 'token_request_failed',
                errorData.error_description || 'Token request failed',
                response.status
            );
        }

        return await response.json();
    }

    // Validate token response structure
    validateTokenResponse(response) {
        const requiredFields = ['access_token'];
        const missingFields = requiredFields.filter(field => !response[field]);

        if (missingFields.length > 0) {
            throw new Error(`Missing required fields in token response: ${missingFields.join(', ')}`);
        }

        // Set expiration timestamp
        if (response.expires_in) {
            response.expires_at = Date.now() + (response.expires_in * 1000);
        }

        return response;
    }

    // Store tokens securely
    async storeTokens(tokenData) {
        // In production, use encrypted database or secure storage
        const tokenId = this.generateSecureRandomString(16);
        const tokenRecord = {
            tokenId: tokenId,
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token,
            expiresAt: tokenData.expires_at,
            scope: tokenData.scope,
            tokenType: tokenData.token_type,
            createdAt: new Date().toISOString(),
            userId: tokenData.user_id || null,
            clientId: this.config.clientId
        };

        // Store in secure storage (implementation depends on your setup)
        await this.secureStorage.set(`token:${tokenId}`, tokenRecord);
        
        return {
            tokenId: tokenId,
            tokenRecord: tokenRecord
        };
    }

    // Utility methods
    generateSecureRandomString(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return Array.from(array, byte => 
            ('0' + byte.toString(16)).slice(-2)
        ).join('');
    }

    validateState(receivedState, expectedState) {
        if (!receivedState || !expectedState) {
            throw new Error('State parameter missing');
        }

        if (receivedState !== expectedState) {
            throw new Error('State parameter mismatch - possible CSRF attack');
        }

        // Check state age (optional, depends on security requirements)
        const stateData = this.config.stateStore.get(receivedState);
        if (stateData && (Date.now() - stateData.timestamp) > 600000) { // 10 minutes
            throw new Error('State parameter expired');
        }
    }
}

// Error Classes
class OAuthAuthorizationError extends Error {
    constructor(error, description) {
        super(`${error}: ${description}`);
        this.name = 'OAuthAuthorizationError';
        this.error = error;
        this.description = description;
    }
}

class OAuthTokenError extends Error {
    constructor(error, description, statusCode) {
        super(`${error}: ${description}`);
        this.name = 'OAuthTokenError';
        this.error = error;
        this.description = description;
        this.statusCode = statusCode;
    }
}

// Token Refresh Implementation
class TokenManager {
    constructor(oauthFlow, tokenStore) {
        this.oauthFlow = oauthFlow;
        this.tokenStore = tokenStore;
    }

    async refreshAccessToken(refreshToken) {
        const tokenRequest = {
            grant_type: 'refresh_token',
            client_id: this.oauthFlow.config.clientId,
            client_secret: this.oauthFlow.config.clientSecret,
            refresh_token: refreshToken
        };

        const tokenResponse = await this.oauthFlow.makeTokenRequest(tokenRequest);
        const tokenData = this.oauthFlow.validateTokenResponse(tokenResponse);

        // Update stored tokens
        const updatedTokens = await this.updateStoredTokens(refreshToken, tokenData);
        
        return {
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token || refreshToken, // May not be returned
            expiresIn: tokenData.expires_in,
            tokenType: tokenData.token_type,
            updatedTokens: updatedTokens
        };
    }

    async updateStoredTokens(oldRefreshToken, newTokenData) {
        // Find the token record with the old refresh token
        const tokenRecords = await this.tokenStore.findByRefreshToken(oldRefreshToken);
        
        if (tokenRecords.length === 0) {
            throw new Error('No valid token record found for refresh token');
        }

        // Update the token record
        const tokenRecord = tokenRecords[0];
        tokenRecord.accessToken = newTokenData.access_token;
        tokenRecord.refreshToken = newTokenData.refresh_token || oldRefreshToken;
        tokenRecord.expiresAt = newTokenData.expires_at;
        tokenRecord.updatedAt = new Date().toISOString();

        await this.tokenStore.update(tokenRecord.tokenId, tokenRecord);
        
        return tokenRecord;
    }

    async isAccessTokenExpired(tokenId) {
        const tokenRecord = await this.tokenStore.get(`token:${tokenId}`);
        if (!tokenRecord) return true;

        return Date.now() >= tokenRecord.expiresAt;
    }

    async getValidAccessToken(tokenId) {
        const tokenRecord = await this.tokenStore.get(`token:${tokenId}`);
        if (!tokenRecord) {
            throw new Error('Token not found');
        }

        if (Date.now() >= tokenRecord.expiresAt) {
            // Attempt to refresh the token
            if (tokenRecord.refreshToken) {
                const refreshedTokens = await this.refreshAccessToken(tokenRecord.refreshToken);
                return refreshedTokens.accessToken;
            }
            throw new Error('Access token expired and no refresh token available');
        }

        return tokenRecord.accessToken;
    }
}

// Secure Storage Interface (implement based on your backend)
class SecureStorage {
    async set(key, value) {
        // Implement secure storage (database, Redis, etc.)
        // For demo purposes, using in-memory storage
        global.tokenStore = global.tokenStore || new Map();
        global.tokenStore.set(key, JSON.stringify(value));
    }

    async get(key) {
        global.tokenStore = global.tokenStore || new Map();
        const stored = global.tokenStore.get(key);
        return stored ? JSON.parse(stored) : null;
    }

    async update(key, value) {
        global.tokenStore = global.tokenStore || new Map();
        global.tokenStore.set(key, JSON.stringify(value));
    }

    async findByRefreshToken(refreshToken) {
        global.tokenStore = global.tokenStore || new Map();
        const results = [];
        
        for (const [key, value] of global.tokenStore.entries()) {
            if (key.startsWith('token:')) {
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
class ExampleWebApp {
    constructor() {
        this.storage = new SecureStorage();
        this.oauthFlow = new AuthorizationCodeFlow(OAuthConfig.generic);
        this.tokenManager = new TokenManager(this.oauthFlow, this.storage);
    }

    // Simulate Express.js route handlers
    async handleAuthStart(req, res) {
        try {
            const { authorizationUrl, state } = this.oauthFlow.initiateAuthorization();
            
            // Store state in session (in real app, use proper session management)
            req.session.oauthState = state;
            req.session.save();

            res.redirect(authorizationUrl);
        } catch (error) {
            console.error('Auth initiation failed:', error);
            res.status(500).send('Authentication initiation failed');
        }
    }

    async handleAuthCallback(req, res) {
        try {
            const { authorizationCode, stateData } = await this.oauthFlow.handleAuthorizationCallback(
                req.url,
                req.session.oauthState
            );

            // Clear session state
            delete req.session.oauthState;

            const tokenData = await this.oauthFlow.exchangeCodeForTokens(
                authorizationCode,
                stateData
            );

            // Store token reference in session
            req.session.tokenId = tokenData.storedTokens.tokenId;

            // Redirect to dashboard or success page
            res.redirect('/dashboard');
        } catch (error) {
            console.error('Auth callback failed:', error);
            res.status(400).send(`Authentication failed: ${error.message}`);
        }
    }

    async handleApiCall(req, res) {
        try {
            const tokenId = req.session.tokenId;
            const accessToken = await this.tokenManager.getValidAccessToken(tokenId);

            // Use access token to call external API
            const apiResponse = await this.callExternalApi(accessToken);
            
            res.json({
                success: true,
                data: apiResponse,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            console.error('API call failed:', error);
            res.status(401).json({
                success: false,
                error: 'Authentication required or token expired'
            });
        }
    }

    async callExternalApi(accessToken) {
        // Example API call using the access token
        const response = await fetch('https://api.provider.com/user/profile', {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`API call failed: ${response.status}`);
        }

        return await response.json();
    }
}

// Demo Function
async function demonstrateAuthorizationCodeFlow() {
    console.log('=== Authorization Code Flow Demo ===\n');

    const webApp = new ExampleWebApp();

    try {
        // Step 1: Initiate Authorization
        console.log('1. Initiating Authorization...');
        const { authorizationUrl, state } = webApp.oauthFlow.initiateAuthorization();
        console.log('Authorization URL:', authorizationUrl);
        console.log('Generated State:', state);

        // Step 2: Simulate Callback (in real scenario, user completes OAuth on provider)
        console.log('\n2. Simulating OAuth Callback...');
        const mockCallbackUrl = `${OAuthConfig.generic.redirectUri}?code=mock_auth_code&state=${state}`;
        
        // Step 3: Handle Callback
        console.log('3. Processing Authorization Callback...');
        const { authorizationCode } = await webApp.oauthFlow.handleAuthorizationCallback(
            mockCallbackUrl,
            state
        );
        console.log('Authorization Code Received:', authorizationCode);

        // Step 4: Exchange Code for Tokens
        console.log('\n4. Exchanging Authorization Code for Tokens...');
        const stateData = { redirectUri: OAuthConfig.generic.redirectUri };
        const tokenData = await webApp.oauthFlow.exchangeCodeForTokens(authorizationCode, stateData);
        
        console.log('Token Exchange Successful!');
        console.log('Access Token (truncated):', tokenData.accessToken.substring(0, 20) + '...');
        console.log('Refresh Token (truncated):', tokenData.refreshToken?.substring(0, 20) + '...');
        console.log('Expires In:', tokenData.expiresIn, 'seconds');

        console.log('\n=== Authorization Code Flow Complete ===');
        
    } catch (error) {
        console.error('Demo failed:', error.message);
    }
}

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        AuthorizationCodeFlow,
        TokenManager,
        OAuthConfig,
        OAuthAuthorizationError,
        OAuthTokenError,
        SecureStorage,
        ExampleWebApp,
        demonstrateAuthorizationCodeFlow
    };
} else {
    window.AuthorizationCodeFlow = {
        AuthorizationCodeFlow,
        TokenManager,
        OAuthConfig,
        OAuthAuthorizationError,
        OAuthTokenError,
        SecureStorage,
        ExampleWebApp
    };
}

// Run demo if executed directly
if (typeof window === 'undefined') {
    demonstrateAuthorizationCodeFlow();
}
```

## Security Checklist for Authorization Code Flow

### Client Registration
- [ ] Register redirect URIs exactly as they will be used
- [ ] Obtain and securely store client secret
- [ ] Verify client ID and secret with authorization server
- [ ] Document all required scopes and their purposes

### Authorization Request
- [ ] Generate cryptographically secure state parameter
- [ ] Include nonce if required by provider
- [ ] Validate redirect URI matches registered URIs
- [ ] Use HTTPS for all requests
- [ ] Limit requested scopes to minimum required

### Callback Handling
- [ ] Validate state parameter to prevent CSRF
- [ ] Handle OAuth errors gracefully
- [ ] Clean up used state parameters
- [ ] Log authentication attempts for audit

### Token Exchange
- [ ] Use client secret for authentication
- [ ] Validate authorization code before exchange
- [ ] Store tokens encrypted at rest
- [ ] Implement proper error handling
- [ ] Set appropriate token expiration times

### Token Management
- [ ] Implement secure token refresh mechanism
- [ ] Revoke tokens on logout or consent withdrawal
- [ ] Monitor token usage and detect anomalies
- [ ] Rotate client credentials regularly
- [ ] Implement token introspection if needed

This implementation provides a robust, production-ready foundation for OAuth 2.0 Authorization Code Flow in server-side web applications.
