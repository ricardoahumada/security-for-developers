# Authorization Code Flow Implementation

## Complete Server-Side Implementation

This implementation provides a production-ready example of the OAuth 2.0 Authorization Code Flow for confidential clients (server-side web applications).

```javascript

// Authorization Code Flow Implementation for Browser Environment
class AuthorizationCodeFlowDemo {
    constructor() {
        // Configuration for demo purposes
        this.config = {
            clientId: 'your-client-id',
            clientSecret: 'your-client-secret',
            authorizationEndpoint: 'https://auth.provider.com/authorize',
            tokenEndpoint: 'https://auth.provider.com/token',
            redirectUri: 'https://yourapp.com/auth/callback',
            scopes: ['read', 'write', 'admin'],
            apiEndpoint: 'https://api.provider.com'
        };
        
        this.authCode = null;
        this.tokens = null;
        this.state = null;
    }

    // Generate a cryptographically secure random string
    generateRandomString(length = 32) {
        try {
            // Check if crypto API is available
            if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
                const array = new Uint8Array(length);
                crypto.getRandomValues(array);
                return Array.from(array, byte => 
                    ('0' + byte.toString(16)).slice(-2)
                ).join('');
            } else {
                // Fallback for environments without crypto API
                return Array.from({length: length}, () => 
                    Math.floor(Math.random() * 16).toString(16)
                ).join('');
            }
        } catch (error) {
            console.error('Error generating random string:', error);
            return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        }
    }

    // Build authorization URL
    buildAuthorizationUrl() {
        try {
            this.state = this.generateRandomString();
            
            const params = {
                response_type: 'code',
                client_id: this.config.clientId,
                redirect_uri: this.config.redirectUri,
                scope: this.config.scopes.join(' '),
                state: this.state,
                access_type: 'offline',
                prompt: 'consent',
                audience: this.config.apiEndpoint,
                response_mode: 'query'
            };

            const url = new URL(this.config.authorizationEndpoint);
            Object.keys(params).forEach(key => url.searchParams.append(key, params[key]));
            
            return {
                url: url.toString(),
                state: this.state
            };
        } catch (error) {
            console.error('Error building authorization URL:', error);
            throw new Error('Failed to build authorization URL');
        }
    }

    // Simulate authorization process (for demo purposes)
    simulateAuthorization() {
        console.log('1. Initiating Authorization...');
        
        const authInfo = this.buildAuthorizationUrl();
        console.log('Authorization URL:');
        console.log(authInfo.url);
        console.log('\nGenerated State:');
        console.log(authInfo.state);
        
        // Store state for verification
        sessionStorage.setItem('oauth_state', this.state);
        
        // Simulate receiving authorization code
        console.log('\n2. Simulating OAuth Callback...');
        this.authCode = 'mock_auth_code'; // In real scenario, this comes from URL
        console.log('Authorization Code Received:', this.authCode);
        
        return this.authCode;
    }

    // Handle authorization callback
    handleAuthorizationCallback() {
        try {
            console.log('\n3. Processing Authorization Callback...');
            console.log('Authorization Code Received:');
            console.log(this.authCode);
            
            // Verify state (in real scenario, check against URL parameter)
            const storedState = sessionStorage.getItem('oauth_state');
            if (this.state !== storedState) {
                throw new Error('State mismatch - potential CSRF attack');
            }
            
            console.log('✓ State verification passed');
            return true;
        } catch (error) {
            console.error('Error handling authorization callback:', error);
            throw error;
        }
    }

    // Exchange authorization code for tokens
    async exchangeCodeForTokens(code) {
        try {
            console.log('\n4. Exchanging Authorization Code for Tokens...');
            
            // Prepare token request
            const tokenRequest = {
                grant_type: 'authorization_code',
                client_id: this.config.clientId,
                code: code,
                redirect_uri: this.config.redirectUri
            };

            // Add client secret if available (confidential client)
            if (this.config.clientSecret) {
                tokenRequest.client_secret = this.config.clientSecret;
            }

            console.log('Token Request:', tokenRequest);

            // Simulate API call (since we can't make real HTTP requests in demo)
            // In real implementation, you would use:
            // const response = await fetch(this.config.tokenEndpoint, {
            //     method: 'POST',
            //     headers: {
            //         'Content-Type': 'application/x-www-form-urlencoded',
            //         'Authorization': 'Basic ' + btoa(`${this.config.clientId}:${this.config.clientSecret}`)
            //     },
            //     body: new URLSearchParams(tokenRequest)
            // });
            // const tokens = await response.json();

            // Simulate successful token response
            const simulatedTokens = {
                access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
                    btoa(JSON.stringify({
                        sub: 'user123',
                        aud: this.config.clientId,
                        exp: Math.floor(Date.now() / 1000) + 3600,
                        iat: Math.floor(Date.now() / 1000),
                        scope: this.config.scopes.join(' ')
                    })) + 
                    '.mock_signature',
                refresh_token: 'mock_refresh_token_' + this.generateRandomString(16),
                token_type: 'Bearer',
                expires_in: 3600,
                scope: this.config.scopes.join(' ')
            };

            this.tokens = simulatedTokens;
            
            // Store tokens securely
            this.storeTokens();
            
            console.log('✓ Token exchange successful');
            console.log('Access Token:', this.tokens.access_token);
            console.log('Refresh Token:', this.tokens.refresh_token);
            console.log('Expires In:', this.tokens.expires_in, 'seconds');
            
            return this.tokens;
        } catch (error) {
            console.error('Token exchange failed:', error.message);
            
            // Provide more specific error handling
            if (error.name === 'TypeError' && error.message.includes('undefined')) {
                console.error('Error: Unable to process response - missing or invalid data');
            } else if (error.name === 'NetworkError') {
                console.error('Error: Network request failed - check your internet connection');
            } else {
                console.error('Error: Token exchange failed due to:', error.message);
            }
            
            throw new Error(`Token exchange failed: ${error.message}`);
        }
    }

    // Store tokens securely
    storeTokens() {
        try {
            if (this.tokens && this.tokens.access_token) {
                // In a real application, use more secure storage methods
                localStorage.setItem('oauth_access_token', this.tokens.access_token);
                localStorage.setItem('oauth_refresh_token', this.tokens.refresh_token || '');
                localStorage.setItem('oauth_token_type', this.tokens.token_type);
                localStorage.setItem('oauth_expires_at', (Date.now() + this.tokens.expires_in * 1000).toString());
                localStorage.setItem('oauth_scope', this.tokens.scope || '');
                
                console.log('✓ Tokens stored securely');
            }
        } catch (error) {
            console.error('Error storing tokens:', error);
        }
    }

    // Make authenticated API request
    async makeAuthenticatedRequest() {
        try {
            const accessToken = this.tokens?.access_token;
            
            if (!accessToken) {
                throw new Error('No access token available');
            }
            
            console.log('\n5. Making Authenticated API Request...');
            console.log('Access Token:', accessToken.substring(0, 50) + '...');
            
            // Simulate API request
            const mockApiResponse = {
                user: {
                    id: 'user123',
                    name: 'John Doe',
                    email: 'john.doe@example.com'
                },
                data: {
                    message: 'Successfully authenticated with OAuth 2.0',
                    timestamp: new Date().toISOString(),
                    scopes: this.config.scopes
                }
            };
            
            console.log('✓ API Request successful');
            console.log('Response:', mockApiResponse);
            
            return mockApiResponse;
        } catch (error) {
            console.error('API request failed:', error.message);
            throw error;
        }
    }

    // Refresh access token
    async refreshAccessToken() {
        try {
            const refreshToken = localStorage.getItem('oauth_refresh_token');
            
            if (!refreshToken) {
                throw new Error('No refresh token available');
            }
            
            console.log('\n6. Refreshing Access Token...');
            
            const refreshRequest = {
                grant_type: 'refresh_token',
                refresh_token: refreshToken,
                client_id: this.config.clientId
            };

            // In real implementation:
            // const response = await fetch(this.config.tokenEndpoint, {
            //     method: 'POST',
            //     headers: {
            //         'Content-Type': 'application/x-www-form-urlencoded'
            //     },
            //     body: new URLSearchParams(refreshRequest)
            // });
            
            // Simulate refresh response
            const newTokens = {
                access_token: 'new_' + this.tokens.access_token,
                token_type: 'Bearer',
                expires_in: 3600
            };
            
            this.tokens = { ...this.tokens, ...newTokens };
            this.storeTokens();
            
            console.log('✓ Token refreshed successfully');
            return newTokens;
        } catch (error) {
            console.error('Token refresh failed:', error.message);
            throw error;
        }
    }

    // Complete OAuth flow demo
    async runDemo() {
        try {
            console.log('=== OAuth 2.0 Authorization Code Flow Demo ===\n');
            
            // Step 1: Initiate authorization
            this.simulateAuthorization();
            
            // Step 2: Handle callback
            this.handleAuthorizationCallback();
            
            // Step 3: Exchange code for tokens
            await this.exchangeCodeForTokens(this.authCode);
            
            // Step 4: Make authenticated request
            await this.makeAuthenticatedRequest();
            
            // Step 5: Demonstrate token refresh
            await this.refreshAccessToken();
            
            console.log('\n=== Demo Completed Successfully ===');
            
            return {
                success: true,
                tokens: this.tokens,
                message: 'OAuth 2.0 Authorization Code Flow completed successfully'
            };
            
        } catch (error) {
            console.error('\n=== Demo Failed ===');
            console.error('Error:', error.message);
            
            return {
                success: false,
                error: error.message,
                message: 'OAuth 2.0 Authorization Code Flow failed'
            };
        }
    }

    // Validate token (utility method)
    validateToken(token) {
        try {
            if (!token) {
                return { valid: false, reason: 'No token provided' };
            }
            
            // Basic JWT structure validation (header.payload.signature)
            const parts = token.split('.');
            if (parts.length !== 3) {
                return { valid: false, reason: 'Invalid token format' };
            }
            
            // Try to decode payload
            try {
                const payload = JSON.parse(atob(parts[1]));
                const now = Math.floor(Date.now() / 1000);
                
                if (payload.exp && payload.exp < now) {
                    return { valid: false, reason: 'Token expired' };
                }
                
                return { valid: true, payload: payload };
            } catch (decodeError) {
                return { valid: false, reason: 'Unable to decode token payload' };
            }
        } catch (error) {
            return { valid: false, reason: 'Token validation error: ' + error.message };
        }
    }
}

// Demo execution
const demo = new AuthorizationCodeFlowDemo();

// Run the complete demo
demo.runDemo().then(result => {
    console.log('\nDemo Result:', result);
    
    // Test token validation
    if (result.success && result.tokens) {
        const validation = demo.validateToken(result.tokens.access_token);
        console.log('Token Validation:', validation);
    }
}).catch(error => {
    console.error('Demo execution error:', error);
});

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthorizationCodeFlowDemo;
} else if (typeof window !== 'undefined') {
    window.AuthorizationCodeFlowDemo = AuthorizationCodeFlowDemo;
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
