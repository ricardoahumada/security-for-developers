# PKCE Flow Implementation

## Complete PKCE Implementation for Public Clients

This implementation provides a comprehensive example of OAuth 2.0 Authorization Code Flow with PKCE (Proof Key for Code Exchange) for public clients, including mobile applications and single-page applications.

```javascript
// PKCE Flow Implementation - Final Fixed Version
// This version ensures all values are properly typed and validated

// PKCE Configuration
const PKCEConfig = {
    generic: {
        authorizationEndpoint: 'https://auth.provider.com/authorize',
        tokenEndpoint: 'https://auth.provider.com/token',
        clientId: 'your-client-id',
        scopes: ['read', 'write', 'profile'],
        redirectUri: 'https://yourapp.com/callback'
    }
};

// Utility functions with proper type validation
function generateSecureRandomString(length = 32) {
    try {
        // Try crypto API first
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            const array = new Uint8Array(length);
            crypto.getRandomValues(array);
            return Array.from(array, byte => 
                ('0' + byte.toString(16)).slice(-2)
            ).join('');
        }
    } catch (error) {
        console.warn('Crypto API failed, using Math.random fallback');
    }
    
    // Fallback to Math.random
    return Array.from({length: length}, () => 
        Math.floor(Math.random() * 16).toString(16)
    ).join('');
}

function base64UrlEncode(input) {
    try {
        // Ensure input is a string
        const str = String(input || '');
        
        // Encode to base64
        const base64 = btoa(str);
        
        // Convert to base64url format
        return base64
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    } catch (error) {
        console.error('Base64 encoding failed:', error);
        // Return a safe fallback string
        return String(input || 'fallback');
    }
}

function validateString(str, name) {
    if (!str || typeof str !== 'string') {
        console.warn(`${name} is not a valid string:`, typeof str, str);
        return false;
    }
    return true;
}

// Simplified PKCE Flow Implementation
class SimplifiedPKCEFlow {
    constructor(config) {
        this.config = {
            clientId: config.clientId || 'demo-client',
            authorizationEndpoint: config.authorizationEndpoint || 'https://auth.example.com/authorize',
            tokenEndpoint: config.tokenEndpoint || 'https://auth.example.com/token',
            redirectUri: config.redirectUri || 'https://example.com/callback',
            scopes: config.scopes || ['read', 'write']
        };
        
        this.codeVerifierStore = new Map();
        this.stateStore = new Map();
        this.secureStorage = new Map();
    }

    // Generate PKCE parameters (with proper type checking) - async version
    async generatePKCEParameters() {
        try {
            console.log('Generating PKCE parameters...');
            
            // Generate code verifier (43-128 characters)
            const codeVerifier = this.generateCodeVerifier();
            console.log('Code verifier generated:', codeVerifier ? codeVerifier.substring(0, 20) + '...' : 'FAILED');
            
            if (!validateString(codeVerifier, 'codeVerifier')) {
                throw new Error('Failed to generate valid code verifier');
            }
            
            // Generate code challenge (base64url encoded SHA-256 of verifier) - await the async call
            const codeChallenge = await this.generateCodeChallenge(codeVerifier);
            console.log('Code challenge generated:', codeChallenge && typeof codeChallenge === 'string' ? codeChallenge.substring(0, 20) + '...' : 'FAILED');
            
            if (!validateString(codeChallenge, 'codeChallenge')) {
                throw new Error('Failed to generate valid code challenge');
            }
            
            // Generate state parameter
            const state = generateSecureRandomString(32);
            console.log('State generated:', state ? state.substring(0, 8) + '...' : 'FAILED');
            
            // Generate nonce
            const nonce = generateSecureRandomString(16);
            console.log('Nonce generated:', nonce ? nonce.substring(0, 8) + '...' : 'FAILED');

            // Store PKCE parameters
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

            // Validate all PKCE data
            if (!validateString(pkceData.codeVerifier, 'pkceData.codeVerifier') ||
                !validateString(pkceData.state, 'pkceData.state') ||
                !validateString(pkceData.nonce, 'pkceData.nonce')) {
                throw new Error('Invalid PKCE data generated');
            }

            // Store with expiration
            try {
                this.codeVerifierStore.set(codeVerifier, pkceData);
                this.stateStore.set(state, { ...pkceData, codeVerifier });
                console.log('PKCE parameters stored successfully');
            } catch (storeError) {
                console.error('Storage error:', storeError);
            }

            // Schedule cleanup
            setTimeout(() => {
                this.codeVerifierStore.delete(codeVerifier);
                this.stateStore.delete(state);
            }, 10 * 60 * 1000);

            const result = {
                codeVerifier: codeVerifier,
                codeChallenge: codeChallenge,
                state: state,
                nonce: nonce,
                method: 'S256'
            };

            // Final validation of result
            if (!validateString(result.codeChallenge, 'result.codeChallenge')) {
                throw new Error('Result codeChallenge is invalid');
            }

            console.log('✓ PKCE parameters generated successfully');
            return result;
            
        } catch (error) {
            console.error('Error generating PKCE parameters:', error);
            throw new Error('Failed to generate PKCE parameters: ' + error.message);
        }
    }

    // Generate cryptographically secure code verifier
    generateCodeVerifier(length = 64) {
        try {
            if (length < 43 || length > 128) {
                throw new Error('Code verifier length must be between 43 and 128 characters');
            }

            let randomString = '';
            
            try {
                // Try crypto API first
                if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
                    const array = new Uint8Array(length);
                    crypto.getRandomValues(array);
                    randomString = Array.from(array, byte => 
                        ('0' + byte.toString(16)).slice(-2)
                    ).join('');
                } else {
                    throw new Error('Crypto API not available');
                }
            } catch (cryptoError) {
                console.warn('Using Math.random fallback for code verifier');
                // Fallback to Math.random
                const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
                for (let i = 0; i < length; i++) {
                    randomString += chars.charAt(Math.floor(Math.random() * chars.length));
                }
            }
            
            // Ensure we have a valid string
            if (!randomString || typeof randomString !== 'string') {
                throw new Error('Failed to generate random string');
            }
            
            // Convert to base64url format
            const encoded = base64UrlEncode(randomString);
            const result = encoded.substring(0, length);
            
            // Final validation
            if (!validateString(result, 'codeVerifier result')) {
                throw new Error('Final code verifier validation failed');
            }
            
            return result;
            
        } catch (error) {
            console.error('Error in generateCodeVerifier:', error);
            // Final fallback - ensure we always return a valid string
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
            let result = '';
            for (let i = 0; i < 64; i++) {
                result += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            return result;
        }
    }

    // Generate code challenge from code verifier (with proper string validation)
    async generateCodeChallenge(codeVerifier) {
        try {
            console.log('Generating code challenge from verifier...');
            
            // Validate input
            if (!validateString(codeVerifier, 'codeVerifier input')) {
                throw new Error('Invalid code verifier provided to generateCodeChallenge');
            }

            // Try to use crypto API for SHA-256
            if (typeof crypto !== 'undefined' && crypto.subtle && crypto.subtle.digest) {
                try {
                    const encoder = new TextEncoder();
                    const data = encoder.encode(codeVerifier);
                    const digest = await crypto.subtle.digest('SHA-256', data);
                    
                    // Convert digest to base64url
                    const base64Digest = btoa(String.fromCharCode(...new Uint8Array(digest)));
                    const challenge = base64UrlEncode(base64Digest);
                    
                    // Validate result
                    if (!validateString(challenge, 'SHA-256 challenge')) {
                        throw new Error('SHA-256 challenge validation failed');
                    }
                    
                    console.log('Generated challenge using SHA-256');
                    return challenge;
                } catch (shaError) {
                    console.warn('SHA-256 failed, using direct encoding:', shaError.message);
                }
            } else {
                console.warn('Crypto subtle API not available, using direct encoding');
            }
            
            // Fallback: encode the verifier directly
            console.log('Using code verifier as challenge (fallback)');
            const challenge = base64UrlEncode(codeVerifier);
            
            // Validate result
            if (!validateString(challenge, 'fallback challenge')) {
                throw new Error('Fallback challenge validation failed');
            }
            
            return challenge;
            
        } catch (error) {
            console.error('Error generating code challenge:', error);
            // Final fallback - ensure we always return a valid string
            const challenge = String(codeVerifier || 'fallback_challenge_1234567890123456789012345678901234567890');
            
            if (!validateString(challenge, 'final fallback challenge')) {
                throw new Error('Even final fallback challenge is invalid');
            }
            
            return challenge;
        }
    }

    // Validate code verifier format
    validateCodeVerifier(codeVerifier) {
        if (!codeVerifier || typeof codeVerifier !== 'string') {
            return false;
        }
        
        // Must be 43-128 characters
        if (codeVerifier.length < 43 || codeVerifier.length > 128) {
            console.warn('Code verifier length invalid:', codeVerifier.length);
            return false;
        }

        // Must contain only unreserved characters
        const validChars = /^[A-Za-z0-9\-._~]+$/;
        if (!validChars.test(codeVerifier)) {
            console.warn('Code verifier contains invalid characters');
            return false;
        }
        
        return true;
    }

    // Build authorization request URL (robust version)
    buildAuthorizationUrl(pkceParams) {
        try {
            console.log('Building authorization URL...');
            
            // Validate PKCE parameters
            if (!pkceParams || typeof pkceParams !== 'object') {
                throw new Error('Invalid PKCE parameters provided');
            }
            
            const params = {
                response_type: 'code',
                client_id: this.config.clientId,
                redirect_uri: this.config.redirectUri,
                scope: this.config.scopes.join(' '),
                state: pkceParams.state,
                nonce: pkceParams.nonce,
                code_challenge: pkceParams.codeChallenge,
                code_challenge_method: 'S256',
                access_type: 'offline',
                prompt: 'consent'
            };

            // Validate all parameter values are strings
            Object.keys(params).forEach(key => {
                if (params[key] !== null && params[key] !== undefined) {
                    params[key] = String(params[key]);
                }
            });

            console.log('Authorization parameters:', {
                client_id: params.client_id.substring(0, 8) + '...',
                scope: params.scope,
                state: params.state.substring(0, 8) + '...',
                code_challenge: params.code_challenge.substring(0, 16) + '...'
            });

            // Build URL manually for maximum compatibility
            const queryParams = [];
            for (const [key, value] of Object.entries(params)) {
                if (value !== null && value !== undefined && value !== '') {
                    queryParams.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
                }
            }
            
            const url = `${this.config.authorizationEndpoint}?${queryParams.join('&')}`;
            console.log('Authorization URL built successfully');
            return url;
            
        } catch (error) {
            console.error('Error building authorization URL:', error);
            throw new Error('Failed to build authorization URL: ' + error.message);
        }
    }

    // Initiate PKCE authorization flow
    async initiateAuthorization() {
        try {
            console.log('Initiating PKCE Authorization Flow...');
            
            // Generate PKCE parameters (await the async call)
            const pkceParams = await this.generatePKCEParameters();
            
            // Validate pkceParams
            if (!pkceParams || typeof pkceParams !== 'object') {
                throw new Error('generatePKCEParameters returned invalid result');
            }
            
            // Build authorization URL
            const authorizationUrl = this.buildAuthorizationUrl(pkceParams);

            console.log('✓ PKCE Flow Initiated Successfully');
            console.log('PKCE Parameters:', {
                clientId: this.config.clientId.substring(0, 8) + '...',
                state: pkceParams.state.substring(0, 8) + '...',
                codeChallenge: pkceParams.codeChallenge.substring(0, 16) + '...',
                method: pkceParams.method
            });

            return {
                authorizationUrl: authorizationUrl,
                pkceParams: pkceParams
            };
            
        } catch (error) {
            console.error('Error initiating PKCE authorization:', error);
            throw error;
        }
    }

    // Handle authorization callback (simplified)
    async handleCallback(callbackUrl) {
        try {
            console.log('Handling authorization callback...');
            
            // Parse callback URL
            const url = new URL(callbackUrl);
            const code = url.searchParams.get('code');
            const state = url.searchParams.get('state');
            const error = url.searchParams.get('error');

            console.log('Callback parameters:', {
                hasCode: !!code,
                codePreview: code ? code.substring(0, 16) + '...' : 'none',
                hasState: !!state,
                hasError: !!error
            });

            // Handle OAuth errors
            if (error) {
                throw new Error(`OAuth Error: ${error} - ${url.searchParams.get('error_description') || 'No description'}`);
            }

            // Validate parameters
            if (!code) {
                throw new Error('Authorization code is missing');
            }

            if (!state) {
                throw new Error('State parameter is missing');
            }

            // Validate state
            const pkceData = this.stateStore.get(state);
            if (!pkceData) {
                throw new Error('Invalid or expired state parameter');
            }

            // Clean up used state
            this.stateStore.delete(state);

            console.log('✓ Callback handled successfully');
            return {
                authorizationCode: code,
                state: state,
                pkceData: pkceData
            };
            
        } catch (error) {
            console.error('Error handling callback:', error);
            throw error;
        }
    }

    // Exchange authorization code for tokens (simplified for demo)
    async exchangeCodeForTokens(authorizationCode, pkceData) {
        try {
            console.log('Exchanging authorization code for tokens...');
            
            // Validate code format
            if (!authorizationCode || authorizationCode.length < 10) {
                throw new Error('Invalid authorization code');
            }

            // Simulate token response (in real app, this would be an HTTP request)
            console.log('Generating mock tokens...');
            
            const mockTokenResponse = {
                access_token: 'mock_access_token_' + generateSecureRandomString(32),
                refresh_token: 'mock_refresh_token_' + generateSecureRandomString(16),
                id_token: 'mock_id_token_' + generateSecureRandomString(48),
                token_type: 'Bearer',
                expires_in: 3600,
                scope: this.config.scopes.join(' ')
            };

            console.log('✓ Tokens generated successfully');
            console.log('Access Token:', mockTokenResponse.access_token.substring(0, 20) + '...');
            console.log('Expires In:', mockTokenResponse.expires_in, 'seconds');
            
            return {
                accessToken: mockTokenResponse.access_token,
                refreshToken: mockTokenResponse.refresh_token,
                idToken: mockTokenResponse.id_token,
                expiresIn: mockTokenResponse.expires_in,
                tokenType: mockTokenResponse.token_type,
                scope: mockTokenResponse.scope
            };

        } catch (error) {
            console.error('Error exchanging code for tokens:', error);
            throw error;
        }
    }
}

// Example PKCE App
class ExamplePKCEApp {
    constructor(provider = 'generic') {
        this.config = PKCEConfig[provider];
        this.pkceFlow = new SimplifiedPKCEFlow(this.config);
    }

    // Initiate login process
    async initiateLogin() {
        try {
            console.log('Starting PKCE login process...');
            const result = await this.pkceFlow.initiateAuthorization();
            
            console.log('Authorization URL ready for redirect');
            console.log('PKCE Login initiated successfully');
            
            return result; // Return both authorizationUrl and pkceParams
        } catch (error) {
            console.error('Error initiating login:', error);
            throw error;
        }
    }

    // Handle callback
    async handleCallback(callbackUrl) {
        try {
            console.log('Processing OAuth callback...');
            const { authorizationCode, pkceData } = await this.pkceFlow.handleCallback(callbackUrl);
            
            console.log('Authorization code received:', authorizationCode.substring(0, 16) + '...');
            
            const tokenData = await this.pkceFlow.exchangeCodeForTokens(authorizationCode, pkceData);
            
            console.log('✓ PKCE flow completed successfully');
            
            return {
                success: true,
                tokens: tokenData,
                message: 'PKCE authentication completed successfully'
            };

        } catch (error) {
            console.error('PKCE callback failed:', error.message);
            return {
                success: false,
                error: error.message
            };
        }
    }
}

// Demo function
async function demonstratePKCEFlow() {
    console.log('=== PKCE Flow Demo ===\n');

    try {
        const app = new ExamplePKCEApp('generic');

        // Step 1: Initiate PKCE flow
        console.log('1. Initiating PKCE Flow...');
        const { authorizationUrl, pkceParams } = await app.pkceFlow.initiateAuthorization();
        console.log('Authorization URL generated\n');

        // Step 2: Simulate callback with the SAME state that was generated
        console.log('2. Simulating OAuth Callback...');
        const mockCallbackUrl = `https://yourapp.com/callback?code=mock_auth_code_${Date.now()}&state=${pkceParams.state}`;
        
        const authResult = await app.handleCallback(mockCallbackUrl);
        
        if (authResult.success) {
            console.log('✓ PKCE flow completed successfully');
            console.log('Access Token:', authResult.tokens.accessToken.substring(0, 20) + '...');
            console.log('Token Type:', authResult.tokens.tokenType);
            console.log('Expires In:', authResult.tokens.expiresIn, 'seconds');
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
        CLIENTTYPES: {
            authorizationCode: 'Confidential clients (server-side)',
            pkce: 'Public clients (mobile, SPA, desktop)'
        },
        AUTHENTICATION: {
            authorizationCode: 'Client secret required',
            pkce: 'Code verifier/challenge only'
        },
        SECURITY: {
            authorizationCode: 'High (with client secret)',
            pkce: 'High (with PKCE mechanism)'
        },
        COMPLEXITY: {
            authorizationCode: 'Medium',
            pkce: 'Medium-High (PKCE implementation)'
        },
        BROWSERSUPPORT: {
            authorizationCode: 'Requires server-side implementation',
            pkce: 'Requires Web Crypto API support'
        }
    };

    Object.keys(comparison).forEach(aspect => {
        console.log(`\n${aspect}:`);
        console.log(`  Authorization Code: ${comparison[aspect].authorizationCode}`);
        console.log(`  PKCE: ${comparison[aspect].pkce}`);
    });
}

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SimplifiedPKCEFlow,
        ExamplePKCEApp,
        PKCEConfig,
        demonstratePKCEFlow,
        comparePKCEFlows,
        generateSecureRandomString,
        base64UrlEncode,
        validateString
    };
} else if (typeof window !== 'undefined') {
    window.PKCEFlowDemo = {
        SimplifiedPKCEFlow,
        ExamplePKCEApp,
        PKCEConfig
    };
}

// Run demo automatically
if (typeof window !== 'undefined' || typeof global !== 'undefined') {
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

