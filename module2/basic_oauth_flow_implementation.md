# Basic OAuth 2.0 Flow Implementation

## Flow Types Overview

This implementation demonstrates all major OAuth 2.0 flows with practical examples and comparisons.

```javascript
// Base OAuth Client Class
class OAuthClient {
    constructor(config) {
        this.config = config;
        this.config = {
            clientId: config.clientId,
            clientSecret: config.clientSecret,
            authorizationEndpoint: config.authorizationEndpoint,
            tokenEndpoint: config.tokenEndpoint,
            redirectUri: config.redirectUri,
            scopes: config.scopes || [],
            ...config
        };
    }

    // Utility methods
    generateRandomString(length = 32) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return Array.from(array, byte => 
            ('0' + byte.toString(16)).slice(-2)
        ).join('');
    }

    buildUrl(baseUrl, params) {
        const url = new URL(baseUrl);
        Object.keys(params).forEach(key => 
            url.searchParams.append(key, params[key])
        );
        return url.toString();
    }

    async makeRequest(url, options = {}) {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                ...options.headers
            },
            ...options
        });
        return response.json();
    }
}

// 1. Authorization Code Flow (Confidential Clients)
class AuthorizationCodeClient extends OAuthClient {
    constructor(config) {
        super(config);
    }

    initiateAuthorization() {
        const state = this.generateRandomString();
        
        // Store state for verification
        sessionStorage.setItem('oauth_state', state);
        sessionStorage.setItem('oauth_flow_type', 'authorization_code');

        const params = {
            response_type: 'code',
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            scope: this.config.scopes.join(' '),
            state: state
        };

        const authUrl = this.buildUrl(this.config.authorizationEndpoint, params);
        window.location.href = authUrl;
    }

    async handleCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const storedState = sessionStorage.getItem('oauth_state');

        if (!code || state !== storedState) {
            throw new Error('Invalid authorization code or state mismatch');
        }

        // Clear stored state
        sessionStorage.removeItem('oauth_state');

        return await this.exchangeCodeForToken(code);
    }

    async exchangeCodeForToken(code) {
        const tokenRequest = {
            grant_type: 'authorization_code',
            client_id: this.config.clientId,
            code: code,
            redirect_uri: this.config.redirectUri
        };

        // Add client secret for confidential clients
        if (this.config.clientSecret) {
            tokenRequest.client_secret = this.config.clientSecret;
        }

        const response = await this.makeRequest(this.config.tokenEndpoint, {
            method: 'POST',
            body: new URLSearchParams(tokenRequest)
        });

        // Store tokens securely
        this.storeTokens(response);
        return response;
    }

    storeTokens(tokens) {
        if (tokens.access_token) {
            localStorage.setItem('access_token', tokens.access_token);
        }
        if (tokens.refresh_token) {
            localStorage.setItem('refresh_token', tokens.refresh_token);
        }
    }
}

// 2. Authorization Code Flow with PKCE (Public Clients)
class PKCEClient extends OAuthClient {
    constructor(config) {
        super(config);
        this.codeVerifier = null;
    }

    async initiateAuthorization() {
        // Generate code verifier and challenge
        this.codeVerifier = this.generateCodeVerifier();
        const codeChallenge = await this.generateCodeChallenge(this.codeVerifier);
        
        const state = this.generateRandomString();
        
        // Store PKCE parameters
        sessionStorage.setItem('pkce_code_verifier', this.codeVerifier);
        sessionStorage.setItem('oauth_state', state);
        sessionStorage.setItem('oauth_flow_type', 'pkce');

        const params = {
            response_type: 'code',
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            scope: this.config.scopes.join(' '),
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        };

        const authUrl = this.buildUrl(this.config.authorizationEndpoint, params);
        window.location.href = authUrl;
    }

    generateCodeVerifier() {
        return this.generateRandomString(64);
    }

    async generateCodeChallenge(verifier) {
        const encoder = new TextEncoder();
        const data = encoder.encode(verifier);
        const digest = await crypto.subtle.digest('SHA-256', data);
        
        // Convert to base64url
        const base64Digest = btoa(String.fromCharCode(...new Uint8Array(digest)));
        return base64Digest.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    async handleCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const storedState = sessionStorage.getItem('oauth_state');
        const codeVerifier = sessionStorage.getItem('pkce_code_verifier');

        if (!code || !state || !codeVerifier || state !== storedState) {
            throw new Error('Invalid authorization code, state mismatch, or missing PKCE verifier');
        }

        // Clear stored parameters
        sessionStorage.removeItem('oauth_state');
        sessionStorage.removeItem('pkce_code_verifier');

        return await this.exchangeCodeForToken(code, codeVerifier);
    }

    async exchangeCodeForToken(code, codeVerifier) {
        const tokenRequest = {
            grant_type: 'authorization_code',
            client_id: this.config.clientId,
            code: code,
            redirect_uri: this.config.redirectUri,
            code_verifier: codeVerifier
        };

        const response = await this.makeRequest(this.config.tokenEndpoint, {
            method: 'POST',
            body: new URLSearchParams(tokenRequest)
        });

        this.storeTokens(response);
        return response;
    }
}

// 3. Client Credentials Flow (Server-to-Server)
class ClientCredentialsClient extends OAuthClient {
    constructor(config) {
        super(config);
    }

    async requestAccessToken() {
        if (!this.config.clientSecret) {
            throw new Error('Client credentials flow requires client secret');
        }

        const tokenRequest = {
            grant_type: 'client_credentials',
            client_id: this.config.clientId,
            client_secret: this.config.clientSecret,
            scope: this.config.scopes.join(' ')
        };

        const response = await this.makeRequest(this.config.tokenEndpoint, {
            method: 'POST',
            body: new URLSearchParams(tokenRequest)
        });

        this.storeTokens(response);
        return response;
    }

    storeTokens(tokens) {
        if (tokens.access_token) {
            localStorage.setItem('cc_access_token', tokens.access_token);
        }
        // Client credentials typically don't issue refresh tokens
    }
}

// 4. Resource Owner Password Credentials Flow (Legacy)
class PasswordCredentialsClient extends OAuthClient {
    constructor(config) {
        super(config);
    }

    async authenticateUser(username, password) {
        const tokenRequest = {
            grant_type: 'password',
            client_id: this.config.clientId,
            client_secret: this.config.clientSecret,
            username: username,
            password: password,
            scope: this.config.scopes.join(' ')
        };

        const response = await this.makeRequest(this.config.tokenEndpoint, {
            method: 'POST',
            body: new URLSearchParams(tokenRequest)
        });

        this.storeTokens(response);
        return response;
    }
}

// 5. Implicit Flow (Deprecated - for educational purposes only)
class ImplicitClient extends OAuthClient {
    constructor(config) {
        super(config);
    }

    initiateAuthorization() {
        const state = this.generateRandomString();
        
        sessionStorage.setItem('oauth_state', state);
        sessionStorage.setItem('oauth_flow_type', 'implicit');

        const params = {
            response_type: 'token',
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            scope: this.config.scopes.join(' '),
            state: state
        };

        const authUrl = this.buildUrl(this.config.authorizationEndpoint, params);
        window.location.href = authUrl;
    }

    handleCallback() {
        const urlParams = new URLSearchParams(window.location.hash.substring(1));
        const accessToken = urlParams.get('access_token');
        const state = urlParams.get('state');
        const storedState = sessionStorage.getItem('oauth_state');

        if (!accessToken || state !== storedState) {
            throw new Error('Invalid access token or state mismatch');
        }

        sessionStorage.removeItem('oauth_state');
        localStorage.setItem('implicit_access_token', accessToken);

        return { access_token: accessToken };
    }
}

// Flow Comparison Implementation
class OAuthFlowAnalyzer {
    static analyzeFlowRequirements(clientType, environment) {
        const flows = {
            'authorization_code': {
                suitable: ['confidential'],
                environments: ['web_server'],
                security: 'high',
                complexity: 'medium',
                recommended: clientType === 'confidential' && environment === 'web_server'
            },
            'pkce': {
                suitable: ['public'],
                environments: ['spa', 'mobile'],
                security: 'high',
                complexity: 'medium-high',
                recommended: clientType === 'public'
            },
            'client_credentials': {
                suitable: ['confidential'],
                environments: ['server_to_server'],
                security: 'high',
                complexity: 'low',
                recommended: environment === 'server_to_server'
            },
            'password_credentials': {
                suitable: ['confidential', 'public'],
                environments: ['legacy'],
                security: 'low',
                complexity: 'low',
                recommended: false
            },
            'implicit': {
                suitable: ['public'],
                environments: ['spa'],
                security: 'low',
                complexity: 'low',
                recommended: false
            }
        };

        return flows;
    }

    static recommendFlow(clientConfig) {
        const { clientType, environment, hasClientSecret, needsUserConsent } = clientConfig;

        // Decision tree
        if (environment === 'server_to_server') {
            return { flow: 'client_credentials', reason: 'Server-to-server communication' };
        }

        if (needsUserConsent) {
            if (clientType === 'confidential' && hasClientSecret) {
                return { flow: 'authorization_code', reason: 'Confidential client with user consent' };
            } else {
                return { flow: 'pkce', reason: 'Public client requiring user consent and security' };
            }
        }

        // Legacy systems only
        return { flow: 'client_credentials', reason: 'Default secure option for service communication' };
    }
}

// Usage Examples
async function demonstrateAllFlows() {
    console.log('=== OAuth 2.0 Flows Demo ===\n');

    // 1. Authorization Code Flow
    console.log('1. Authorization Code Flow (Confidential Client)');
    const webAppClient = new AuthorizationCodeClient({
        clientId: 'web-app-123',
        clientSecret: 'secret-key',
        authorizationEndpoint: 'https://auth.example.com/authorize',
        tokenEndpoint: 'https://auth.example.com/token',
        redirectUri: 'https://app.example.com/callback',
        scopes: ['read', 'write']
    });

    // webAppClient.initiateAuthorization();
    console.log('✓ Configured for confidential web applications\n');

    // 2. PKCE Flow
    console.log('2. Authorization Code Flow with PKCE (Public Client)');
    const mobileAppClient = new PKCEClient({
        clientId: 'mobile-app-456',
        authorizationEndpoint: 'https://auth.example.com/authorize',
        tokenEndpoint: 'https://auth.example.com/token',
        redirectUri: 'mobile-app://callback',
        scopes: ['profile', 'photos']
    });

    // mobileAppClient.initiateAuthorization();
    console.log('✓ Configured for public clients (mobile, SPA)\n');

    // 3. Client Credentials Flow
    console.log('3. Client Credentials Flow (Server-to-Server)');
    const serviceClient = new ClientCredentialsClient({
        clientId: 'service-account-789',
        clientSecret: 'service-secret',
        authorizationEndpoint: 'https://auth.example.com/authorize',
        tokenEndpoint: 'https://auth.example.com/token',
        scopes: ['api:read']
    });

    // await serviceClient.requestAccessToken();
    console.log('✓ Configured for service-to-service communication\n');

    // Flow Analysis
    console.log('4. Flow Analysis for Different Scenarios');
    const scenarios = [
        { clientType: 'confidential', hasClientSecret: true, environment: 'web_server', needsUserConsent: true },
        { clientType: 'public', hasClientSecret: false, environment: 'mobile', needsUserConsent: true },
        { clientType: 'confidential', hasClientSecret: true, environment: 'server_to_server', needsUserConsent: false }
    ];

    scenarios.forEach((scenario, index) => {
        const recommendation = OAuthFlowAnalyzer.recommendFlow(scenario);
        console.log(`Scenario ${index + 1}:`, recommendation);
    });
}

// Error Handling Examples
class OAuthErrorHandler {
    static handleTokenResponse(response) {
        if (response.error) {
            const errorMessages = {
                'invalid_request': 'The request is missing a required parameter',
                'unauthorized_client': 'The client is not authorized to request an authorization code',
                'unsupported_response_type': 'The authorization server does not support obtaining an authorization code',
                'invalid_scope': 'The requested scope is invalid or unknown',
                'server_error': 'The authorization server encountered an unexpected condition',
                'temporarily_unavailable': 'The authorization server is currently unable to handle the request'
            };

            const message = errorMessages[response.error] || 'Unknown OAuth error';
            const error = new Error(`${response.error}: ${message}`);
            error.code = response.error;
            error.state = response.state;
            throw error;
        }
        return response;
    }

    static validateTokenResponse(response) {
        const requiredFields = ['access_token'];
        const missingFields = requiredFields.filter(field => !response[field]);

        if (missingFields.length > 0) {
            throw new Error(`Missing required fields: ${missingFields.join(', ')}`);
        }

        // Check for expiration if token_type is bearer
        if (response.expires_in) {
            response.expires_at = Date.now() + (response.expires_in * 1000);
        }

        return response;
    }
}

// Token Refresh Implementation
class TokenManager {
    constructor(client) {
        this.client = client;
    }

    async refreshAccessToken(refreshToken) {
        const tokenRequest = {
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            client_id: this.client.config.clientId
        };

        if (this.client.config.clientSecret) {
            tokenRequest.client_secret = this.client.config.clientSecret;
        }

        const response = await this.client.makeRequest(this.client.config.tokenEndpoint, {
            method: 'POST',
            body: new URLSearchParams(tokenRequest)
        });

        OAuthErrorHandler.handleTokenResponse(response);
        OAuthErrorHandler.validateTokenResponse(response);

        this.client.storeTokens(response);
        return response;
    }

    isTokenExpired(token) {
        return token && token.expires_at && Date.now() >= token.expires_at;
    }

    async ensureValidAccessToken() {
        const accessToken = localStorage.getItem('access_token');
        const refreshToken = localStorage.getItem('refresh_token');

        if (!accessToken) {
            throw new Error('No access token available');
        }

        // In a real implementation, you would decode and check the JWT
        // For this example, we'll use stored expiration
        const tokenData = JSON.parse(localStorage.getItem('token_data') || '{}');
        
        if (this.isTokenExpired(tokenData) && refreshToken) {
            return await this.refreshAccessToken(refreshToken);
        }

        return { access_token: accessToken };
    }
}

// Export for Node.js or browser usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        OAuthClient,
        AuthorizationCodeClient,
        PKCEClient,
        ClientCredentialsClient,
        PasswordCredentialsClient,
        ImplicitClient,
        OAuthFlowAnalyzer,
        OAuthErrorHandler,
        TokenManager,
        demonstrateAllFlows
    };
} else {
    window.OAuthFlows = {
        OAuthClient,
        AuthorizationCodeClient,
        PKCEClient,
        ClientCredentialsClient,
        PasswordCredentialsClient,
        ImplicitClient,
        OAuthFlowAnalyzer,
        OAuthErrorHandler,
        TokenManager
    };
}

// Execute demo
demonstrateAllFlows();

```

## Flow Comparison Summary

| Flow | Client Type | Security | Complexity | Use Case | Status |
|------|-------------|----------|------------|----------|--------|
| **Authorization Code** | Confidential | ★★★★★ | ★★★☆☆ | Web servers | Recommended |
| **PKCE** | Public | ★★★★★ | ★★★★☆ | Mobile/SPA | Recommended |
| **Client Credentials** | Confidential | ★★★★☆ | ★☆☆☆☆ | Server-to-server | Recommended |
| **Implicit** | Public | ★★☆☆☆ | ★☆☆☆☆ | Legacy SPA | **Deprecated** |
| **Password Credentials** | Both | ★☆☆☆☆ | ★☆☆☆☆ | Legacy systems | **Discouraged** |

## Security Best Practices

1. **Always use HTTPS** for all OAuth endpoints
2. **Validate state parameter** to prevent CSRF attacks
3. **Use PKCE for public clients** (no client secret)
4. **Store tokens securely** and encrypt at rest
5. **Implement proper token refresh** mechanisms
6. **Use short-lived access tokens** with refresh tokens
7. **Never expose client secrets** in client-side code
8. **Implement proper error handling** and user feedback

This implementation provides a comprehensive foundation for understanding and implementing OAuth 2.0 flows in various scenarios.
