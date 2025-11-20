# SPA PKCE Implementation

## Single Page Application OAuth 2.0 with PKCE

This implementation provides a comprehensive PKCE flow for modern Single Page Applications (React, Vue, Angular) using modern browser APIs and security best practices.

```javascript
// SPA PKCE Configuration
const SPAPKCEConfig = {
    // Application configuration
    app: {
        name: 'My SPA App',
        version: '1.0.0',
        storageKeyPrefix: 'spa_auth_',
        tokenRefreshThreshold: 5 * 60 * 1000, // 5 minutes before expiry
    },
    
    // OAuth provider configurations
    providers: {
        auth0: {
            authorizationEndpoint: 'https://your-tenant.auth0.com/authorize',
            tokenEndpoint: 'https://your-tenant.auth0.com/oauth/token',
            clientId: 'your-auth0-spa-client-id',
            scopes: ['openid', 'profile', 'email'],
            redirectUri: window.location.origin + '/callback',
            audience: 'https://api.yourapp.com'
        },
        google: {
            authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
            tokenEndpoint: 'https://oauth2.googleapis.com/token',
            clientId: 'your-google-client-id.googleusercontent.com',
            scopes: ['openid', 'profile', 'email', 'https://www.googleapis.com/auth/drive.readonly'],
            redirectUri: window.location.origin + '/callback'
        },
        generic: {
            authorizationEndpoint: 'https://auth.provider.com/authorize',
            tokenEndpoint: 'https://auth.provider.com/token',
            clientId: 'your-spa-client-id',
            scopes: ['read', 'write', 'profile'],
            redirectUri: window.location.origin + '/callback'
        }
    }
};

// Main SPA PKCE Flow Manager
class SPAPKCEFlow {
    constructor(provider = 'auth0') {
        this.config = SPAPKCEConfig.providers[provider];
        this.appConfig = SPAPKCEConfig.app;
        this.currentAuthRequest = null;
        this.isAuthenticating = false;
        this.tokenCheckInterval = null;
        
        // Initialize token storage
        this.initializeTokenStorage();
        
        // Setup message listener for cross-tab communication
        this.setupCrossTabCommunication();
    }

    // Initialize token storage with encryption
    initializeTokenStorage() {
        this.storage = {
            // Use sessionStorage for sensitive data (cleared on tab close)
            session: window.sessionStorage,
            // Use localStorage for persistent data (with encryption)
            local: window.localStorage
        };
    }

    // Generate PKCE parameters
    generatePKCEParameters() {
        const codeVerifier = this.generateCodeVerifier();
        const codeChallenge = this.generateCodeChallenge(codeVerifier);
        const state = this.generateSecureRandomString();
        const nonce = this.generateSecureRandomString();

        const pkceData = {
            codeVerifier: codeVerifier,
            codeChallenge: codeChallenge,
            state: state,
            nonce: nonce,
            timestamp: Date.now(),
            expiration: Date.now() + (10 * 60 * 1000), // 10 minutes
            clientId: this.config.clientId,
            redirectUri: this.config.redirectUri,
            scopes: this.config.scopes
        };

        // Store PKCE data securely
        this.storePKCEData(pkceData);
        
        return pkceData;
    }

    // Generate cryptographically secure code verifier
    generateCodeVerifier(length = 64) {
        if (length < 43 || length > 128) {
            throw new Error('Code verifier length must be between 43 and 128 characters');
        }

        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        
        // Convert to base64url
        const base64String = btoa(String.fromCharCode(...array));
        return base64String
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '')
            .substring(0, length);
    }

    // Generate SHA256 code challenge
    async generateCodeChallenge(codeVerifier) {
        if (!this.validateCodeVerifier(codeVerifier)) {
            throw new Error('Invalid code verifier format');
        }

        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        const digest = await crypto.subtle.digest('SHA-256', data);
        
        // Convert to base64url
        const base64Digest = btoa(String.fromCharCode(...new Uint8Array(digest)));
        return base64Digest
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    // Validate code verifier
    validateCodeVerifier(codeVerifier) {
        return codeVerifier.length >= 43 && 
               codeVerifier.length <= 128 && 
               /^[A-Za-z0-9\-._~]+$/.test(codeVerifier);
    }

    // Generate secure random string
    generateSecureRandomString(length = 32) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return Array.from(array, byte => 
            ('0' + byte.toString(16)).slice(-2)
        ).join('');
    }

    // Build authorization URL
    buildAuthorizationUrl(pkceData) {
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: this.config.clientId,
            redirect_uri: pkceData.redirectUri,
            scope: pkceData.scopes.join(' '),
            state: pkceData.state,
            nonce: pkceData.nonce,
            code_challenge: pkceData.codeChallenge,
            code_challenge_method: 'S256',
            // Additional SPA-specific parameters
            prompt: 'consent',
            ...this.config.additionalParams
        });

        // Include audience if specified
        if (this.config.audience) {
            params.append('audience', this.config.audience);
        }

        return `${this.config.authorizationEndpoint}?${params.toString()}`;
    }

    // Initiate authentication flow
    async initiateAuthentication() {
        if (this.isAuthenticating) {
            throw new Error('Authentication already in progress');
        }

        if (!this.isCryptoSupported()) {
            throw new Error('Web Crypto API not supported');
        }

        try {
            this.isAuthenticating = true;
            
            // Generate and store PKCE parameters
            const pkceData = this.generatePKCEParameters();
            
            // Build authorization URL
            const authUrl = this.buildAuthorizationUrl(pkceData);
            
            // Store current auth request state
            this.currentAuthRequest = {
                startTime: Date.now(),
                pkceData: pkceData
            };
            
            // Broadcast auth start to other tabs
            this.broadcastAuthStart();
            
            // Redirect to authorization server
            window.location.href = authUrl;

        } catch (error) {
            this.isAuthenticating = false;
            throw new SPAPKCEError('AUTH_INITIATION_FAILED', error.message);
        }
    }

    // Handle authentication callback
    async handleCallback() {
        const urlParams = new URLSearchParams(window.location.search);
        const hashParams = new URLSearchParams(window.location.hash.substring(1));
        
        // Check both query params and hash params
        const code = urlParams.get('code') || hashParams.get('code');
        const state = urlParams.get('state') || hashParams.get('state');
        const error = urlParams.get('error') || hashParams.get('error');

        // Handle OAuth errors
        if (error) {
            const errorDescription = urlParams.get('error_description') || hashParams.get('error_description');
            throw new SPAPKCEError('OAUTH_ERROR', `${error}: ${errorDescription}`);
        }

        // Validate required parameters
        if (!code || !state) {
            throw new SPAPKCEError('INVALID_CALLBACK', 'Missing required callback parameters');
        }

        // Retrieve stored PKCE data
        const storedPKCEData = this.retrievePKCEData();
        if (!storedPKCEData) {
            throw new SPAPKCEError('NO_PKCE_DATA', 'No PKCE data found in storage');
        }

        // Validate state parameter
        if (state !== storedPKCEData.state) {
            throw new SPAPKCEError('STATE_MISMATCH', 'State parameter does not match');
        }

        // Check state expiration
        if (Date.now() > storedPKCEData.expiration) {
            throw new SPAPKCEError('STATE_EXPIRED', 'PKCE data has expired');
        }

        try {
            // Exchange code for tokens
            const tokenData = await this.exchangeCodeForTokens(code, storedPKCEData);
            
            // Clear PKCE data
            this.clearPKCEData();
            
            // Store tokens
            await this.storeTokens(tokenData);
            
            // Broadcast successful auth to other tabs
            this.broadcastAuthSuccess(tokenData);
            
            // Clear current auth request
            this.currentAuthRequest = null;
            this.isAuthenticating = false;
            
            return tokenData;

        } catch (error) {
            this.broadcastAuthError(error);
            this.isAuthenticating = false;
            throw error;
        }
    }

    // Exchange authorization code for tokens
    async exchangeCodeForTokens(authorizationCode, pkceData) {
        const tokenRequest = {
            grant_type: 'authorization_code',
            client_id: this.config.clientId,
            code: authorizationCode,
            redirect_uri: pkceData.redirectUri,
            code_verifier: pkceData.codeVerifier
        };

        try {
            const response = await fetch(this.config.tokenEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                },
                body: new URLSearchParams(tokenRequest),
                credentials: 'omit' // Don't send cookies for PKCE
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new SPAPKCEError('TOKEN_EXCHANGE_FAILED', 
                    `Token request failed: ${errorData.error || response.status}`);
            }

            const tokenResponse = await response.json();
            
            // Validate token response
            if (!tokenResponse.access_token) {
                throw new SPAPKCEError('INVALID_TOKEN_RESPONSE', 'No access token in response');
            }

            // Add expiration timestamp
            if (tokenResponse.expires_in) {
                tokenResponse.expires_at = Date.now() + (tokenResponse.expires_in * 1000);
            }

            return tokenResponse;

        } catch (error) {
            if (error.name === 'SPAPKCEError') {
                throw error;
            }
            throw new SPAPKCEError('TOKEN_REQUEST_FAILED', `Token request failed: ${error.message}`);
        }
    }

    // Store PKCE data securely
    storePKCEData(pkceData) {
        try {
            const storageKey = `${this.appConfig.storageKeyPrefix}pkce_data`;
            sessionStorage.setItem(storageKey, JSON.stringify(pkceData));
        } catch (error) {
            throw new SPAPKCEError('STORAGE_FAILED', `Failed to store PKCE data: ${error.message}`);
        }
    }

    // Retrieve stored PKCE data
    retrievePKCEData() {
        try {
            const storageKey = `${this.appConfig.storageKeyPrefix}pkce_data`;
            const stored = sessionStorage.getItem(storageKey);
            return stored ? JSON.parse(stored) : null;
        } catch (error) {
            return null;
        }
    }

    // Clear PKCE data
    clearPKCEData() {
        try {
            const storageKey = `${this.appConfig.storageKeyPrefix}pkce_data`;
            sessionStorage.removeItem(storageKey);
        } catch (error) {
            console.warn('Failed to clear PKCE data:', error.message);
        }
    }

    // Store tokens with encryption
    async storeTokens(tokenData) {
        try {
            const tokenRecord = {
                accessToken: tokenData.access_token,
                refreshToken: tokenData.refresh_token,
                idToken: tokenData.id_token,
                expiresAt: tokenData.expires_at,
                tokenType: tokenData.token_type,
                scope: tokenData.scope,
                provider: this.config.clientId,
                createdAt: new Date().toISOString(),
                userAgent: navigator.userAgent
            };

            // Encrypt sensitive data
            const encryptedRecord = await this.encryptSensitiveData(tokenRecord);
            const storageKey = `${this.appConfig.storageKeyPrefix}tokens`;
            
            // Store in localStorage (more persistent)
            localStorage.setItem(storageKey, JSON.stringify(encryptedRecord));
            
            // Store minimal data in sessionStorage for current session
            const sessionData = {
                hasValidTokens: true,
                provider: this.config.clientId,
                timestamp: Date.now()
            };
            sessionStorage.setItem(`${storageKey}_session`, JSON.stringify(sessionData));

            // Start token expiration monitoring
            this.startTokenMonitoring(tokenData.expires_at);

        } catch (error) {
            throw new SPAPKCEError('TOKEN_STORAGE_FAILED', `Failed to store tokens: ${error.message}`);
        }
    }

    // Encrypt sensitive data using Web Crypto API
    async encryptSensitiveData(data) {
        const key = await this.generateStorageKey();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encodedData = new TextEncoder().encode(JSON.stringify(data));
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encodedData
        );

        return {
            data: Array.from(new Uint8Array(encrypted)),
            iv: Array.from(iv),
            timestamp: Date.now()
        };
    }

    // Decrypt sensitive data
    async decryptSensitiveData(encryptedRecord) {
        const key = await this.generateStorageKey();
        
        const data = new Uint8Array(encryptedRecord.data);
        const iv = new Uint8Array(encryptedRecord.iv);
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            data
        );

        const decoded = new TextDecoder().decode(decrypted);
        return JSON.parse(decoded);
    }

    // Generate encryption key (in production, use a proper key management system)
    async generateStorageKey() {
        const material = `${this.appConfig.name}_${navigator.userAgent}_${screen.width}x${screen.height}`;
        const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(material));
        return crypto.subtle.importKey(
            'raw',
            hash,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );
    }

    // Get stored tokens
    async getStoredTokens() {
        try {
            const storageKey = `${this.appConfig.storageKeyPrefix}tokens`;
            const stored = localStorage.getItem(storageKey);
            
            if (!stored) return null;

            const encryptedRecord = JSON.parse(stored);
            return await this.decryptSensitiveData(encryptedRecord);

        } catch (error) {
            console.error('Failed to retrieve tokens:', error);
            return null;
        }
    }

    // Check if access token is expired
    async isTokenExpired() {
        const tokens = await this.getStoredTokens();
        if (!tokens || !tokens.expiresAt) return true;
        
        return Date.now() >= tokens.expiresAt;
    }

    // Get valid access token (refresh if needed)
    async getValidAccessToken() {
        const tokens = await this.getStoredTokens();
        if (!tokens) {
            throw new SPAPKCEError('NO_TOKENS', 'No authentication tokens found');
        }

        // Check if token is expired or about to expire
        const timeUntilExpiry = tokens.expiresAt - Date.now();
        if (timeUntilExpiry <= this.appConfig.tokenRefreshThreshold) {
            if (tokens.refreshToken) {
                return await this.refreshAccessToken();
            } else {
                throw new SPAPKCEError('TOKEN_EXPIRED', 'Access token expired and no refresh token available');
            }
        }

        return tokens.accessToken;
    }

    // Refresh access token
    async refreshAccessToken() {
        const tokens = await this.getStoredTokens();
        if (!tokens || !tokens.refreshToken) {
            throw new SPAPKCEError('NO_REFRESH_TOKEN', 'No refresh token available');
        }

        const tokenRequest = {
            grant_type: 'refresh_token',
            client_id: this.config.clientId,
            refresh_token: tokens.refreshToken
        };

        try {
            const response = await fetch(this.config.tokenEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                },
                body: new URLSearchParams(tokenRequest),
                credentials: 'omit'
            });

            if (!response.ok) {
                throw new Error('Token refresh failed');
            }

            const tokenResponse = await response.json();
            
            // Update stored tokens
            const updatedTokens = {
                ...tokens,
                accessToken: tokenResponse.access_token,
                expiresAt: Date.now() + (tokenResponse.expires_in * 1000),
                refreshToken: tokenResponse.refresh_token || tokens.refreshToken
            };

            await this.storeTokens(updatedTokens);
            return updatedTokens.accessToken;

        } catch (error) {
            // Clear invalid tokens
            await this.clearTokens();
            throw new SPAPKCEError('REFRESH_FAILED', `Token refresh failed: ${error.message}`);
        }
    }

    // Start token monitoring
    startTokenMonitoring(expirationTime) {
        // Clear existing interval
        if (this.tokenCheckInterval) {
            clearInterval(this.tokenCheckInterval);
        }

        // Check token validity every minute
        this.tokenCheckInterval = setInterval(async () => {
            if (await this.isTokenExpired()) {
                this.clearTokens();
                this.broadcastAuthError(new SPAPKCEError('TOKEN_EXPIRED', 'Token expired'));
            }
        }, 60000);
    }

    // Clear stored tokens
    async clearTokens() {
        try {
            const storageKey = `${this.appConfig.storageKeyPrefix}tokens`;
            localStorage.removeItem(storageKey);
            sessionStorage.removeItem(`${storageKey}_session`);
            
            // Stop token monitoring
            if (this.tokenCheckInterval) {
                clearInterval(this.tokenCheckInterval);
                this.tokenCheckInterval = null;
            }
        } catch (error) {
            console.warn('Failed to clear tokens:', error.message);
        }
    }

    // Logout
    async logout() {
        await this.clearTokens();
        this.isAuthenticating = false;
        this.currentAuthRequest = null;
        this.broadcastAuthLogout();
    }

    // Setup cross-tab communication
    setupCrossTabCommunication() {
        window.addEventListener('storage', (event) => {
            if (event.key === `${this.appConfig.storageKeyPrefix}auth_broadcast`) {
                const data = JSON.parse(event.newValue);
                this.handleCrossTabMessage(data);
            }
        });
    }

    // Broadcast auth events to other tabs
    broadcastAuthStart() {
        this.broadcastMessage({ type: 'auth_start', timestamp: Date.now() });
    }

    broadcastAuthSuccess(tokenData) {
        this.broadcastMessage({ 
            type: 'auth_success', 
            tokenData: { 
                hasTokens: true,
                provider: this.config.clientId 
            },
            timestamp: Date.now() 
        });
    }

    broadcastAuthError(error) {
        this.broadcastMessage({ 
            type: 'auth_error', 
            error: error.message,
            timestamp: Date.now() 
        });
    }

    broadcastAuthLogout() {
        this.broadcastMessage({ 
            type: 'auth_logout', 
            timestamp: Date.now() 
        });
    }

    broadcastMessage(data) {
        try {
            localStorage.setItem(
                `${this.appConfig.storageKeyPrefix}auth_broadcast`, 
                JSON.stringify(data)
            );
        } catch (error) {
            console.warn('Failed to broadcast message:', error.message);
        }
    }

    // Handle cross-tab messages
    handleCrossTabMessage(data) {
        // Implement cross-tab synchronization logic
        switch (data.type) {
            case 'auth_success':
                // Update UI to reflect authentication
                this.onCrossTabAuthSuccess && this.onCrossTabAuthSuccess(data);
                break;
            case 'auth_logout':
                // Update UI to reflect logout
                this.onCrossTabAuthLogout && this.onCrossTabAuthLogout(data);
                break;
        }
    }

    // Check if Web Crypto API is supported
    isCryptoSupported() {
        return !!(window.crypto && window.crypto.subtle);
    }

    // Callback methods (to be overridden)
    onAuthSuccess(tokenData) {
        console.log('Authentication successful:', tokenData);
    }

    onAuthError(error) {
        console.error('Authentication failed:', error);
    }

    onCrossTabAuthSuccess(data) {
        // Handle successful authentication in another tab
    }

    onCrossTabAuthLogout(data) {
        // Handle logout in another tab
    }
}

// React Hook for SPA PKCE
import { useState, useEffect, useCallback } from 'react';

export function useSPAPKCE(provider = 'auth0') {
    const [authState, setAuthState] = useState({
        isAuthenticated: false,
        isAuthenticating: false,
        user: null,
        tokens: null,
        error: null
    });

    const [pkceFlow] = useState(() => new SPAPKCEFlow(provider));

    useEffect(() => {
        // Set up callback handlers
        pkceFlow.onAuthSuccess = (tokenData) => {
            setAuthState(prev => ({
                ...prev,
                isAuthenticated: true,
                isAuthenticating: false,
                tokens: tokenData,
                error: null
            }));
            
            // Parse user info from ID token
            if (tokenData.id_token) {
                const userInfo = parseUserInfo(tokenData.id_token);
                setAuthState(prev => ({ ...prev, user: userInfo }));
            }
        };

        pkceFlow.onAuthError = (error) => {
            setAuthState(prev => ({
                ...prev,
                isAuthenticated: false,
                isAuthenticating: false,
                error: error.message
            }));
        };

        pkceFlow.onCrossTabAuthSuccess = () => {
            // Reload tokens from storage
            checkExistingTokens();
        };

        pkceFlow.onCrossTabAuthLogout = () => {
            setAuthState({
                isAuthenticated: false,
                isAuthenticating: false,
                user: null,
                tokens: null,
                error: null
            });
        };

        // Check for existing tokens on mount
        checkExistingTokens();

        // Check if this is a callback URL
        if (isCallbackUrl()) {
            handleCallback();
        }
    }, []);

    const parseUserInfo = (idToken) => {
        try {
            const parts = idToken.split('.');
            if (parts.length !== 3) return null;
            
            const payload = JSON.parse(atob(parts[1]));
            return {
                userId: payload.sub,
                email: payload.email,
                name: payload.name,
                picture: payload.picture
            };
        } catch (error) {
            return null;
        }
    };

    const checkExistingTokens = async () => {
        try {
            const tokens = await pkceFlow.getStoredTokens();
            if (tokens && !(await pkceFlow.isTokenExpired())) {
                setAuthState(prev => ({
                    ...prev,
                    isAuthenticated: true,
                    tokens: tokens
                }));

                if (tokens.idToken) {
                    const userInfo = parseUserInfo(tokens.idToken);
                    setAuthState(prev => ({ ...prev, user: userInfo }));
                }
            }
        } catch (error) {
            console.error('Failed to check existing tokens:', error);
        }
    };

    const isCallbackUrl = () => {
        const urlParams = new URLSearchParams(window.location.search);
        const hashParams = new URLSearchParams(window.location.hash.substring(1));
        return !!(urlParams.get('code') || hashParams.get('code'));
    };

    const handleCallback = async () => {
        try {
            setAuthState(prev => ({ ...prev, isAuthenticating: true, error: null }));
            await pkceFlow.handleCallback();
            
            // Clear URL parameters after successful callback
            window.history.replaceState({}, document.title, window.location.pathname);
            
        } catch (error) {
            setAuthState(prev => ({
                ...prev,
                isAuthenticating: false,
                error: error.message
            }));
        }
    };

    const signIn = useCallback(async () => {
        try {
            setAuthState(prev => ({ ...prev, isAuthenticating: true, error: null }));
            await pkceFlow.initiateAuthentication();
        } catch (error) {
            setAuthState(prev => ({
                ...prev,
                isAuthenticating: false,
                error: error.message
            }));
        }
    }, []);

    const signOut = useCallback(async () => {
        await pkceFlow.logout();
        setAuthState({
            isAuthenticated: false,
            isAuthenticating: false,
            user: null,
            tokens: null,
            error: null
        });
    }, []);

    const makeAuthenticatedRequest = useCallback(async (url, options = {}) => {
        try {
            const accessToken = await pkceFlow.getValidAccessToken();
            return await fetch(url, {
                ...options,
                headers: {
                    ...options.headers,
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/json'
                },
                credentials: 'omit' // Don't send cookies for PKCE
            });
        } catch (error) {
            throw new Error(`Authentication failed: ${error.message}`);
        }
    }, []);

    return {
        ...authState,
        signIn,
        signOut,
        makeAuthenticatedRequest
    };
}

// React Component Example
import React from 'react';

const SPALoginComponent = () => {
    const {
        isAuthenticated,
        isAuthenticating,
        user,
        error,
        signIn,
        signOut
    } = useSPAPKCE('auth0');

    if (isAuthenticating) {
        return <div>Authenticating...</div>;
    }

    if (isAuthenticated) {
        return (
            <div>
                <h2>Welcome, {user?.name}!</h2>
                <img src={user?.picture} alt="Profile" />
                <button onClick={signOut}>Sign Out</button>
            </div>
        );
    }

    return (
        <div>
            <h2>Please sign in</h2>
            {error && <div className="error">{error}</div>}
            <button onClick={signIn}>Sign In</button>
        </div>
    );
};

// Error Classes
class SPAPKCEError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'SPAPKCEError';
        this.code = code;
    }
}

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SPAPKCEFlow,
        SPAPKCEError,
        useSPAPKCE,
        SPALoginComponent,
        SPAPKCEConfig
    };
} else {
    window.SPAPKCEFlow = {
        SPAPKCEFlow,
        SPAPKCEError,
        SPAPKCEConfig
    };
}

// Browser compatibility and security considerations
console.log(`
=== SPA PKCE Security Considerations ===

Browser Compatibility:
- Requires Web Crypto API support (modern browsers)
- Fallback for older browsers may be needed

Security Features:
- Tokens encrypted using Web Crypto API
- Cross-tab communication for session sync
- Automatic token refresh before expiration
- Secure token storage (localStorage + sessionStorage)
- CSRF protection with state parameter
- PKCE code verifier/challenge mechanism

Best Practices:
- Always use HTTPS
- Implement proper error handling
- Monitor token expiration
- Clear tokens on logout
- Validate redirect URIs
- Use Content Security Policy headers
`);
```

## SPA Security Best Practices

### Browser Security
- **Content Security Policy**: Implement CSP headers to prevent XSS
- **HTTPS Only**: Ensure all OAuth endpoints use HTTPS
- **XSS Protection**: Sanitize all user input and external data
- **Clickjacking Protection**: Use X-Frame-Options header

### Token Security
- **Encryption**: Encrypt tokens at rest using Web Crypto API
- **Short Lifespan**: Use short-lived access tokens with refresh tokens
- **Secure Storage**: Store tokens in appropriate browser storage
- **Cleanup**: Clear tokens on logout and on callback processing

### Cross-Tab Synchronization
- **BroadcastChannel**: Use BroadcastChannel API for tab communication
- **Storage Events**: Listen to storage events for token sync
- **Session Management**: Maintain consistent session state across tabs

### Performance Considerations
- **Token Refresh**: Refresh tokens before expiration
- **Caching**: Cache user information to reduce API calls
- **Lazy Loading**: Load authentication logic when needed
- **Monitoring**: Implement token usage monitoring

This SPA PKCE implementation provides a robust, secure authentication solution for modern web applications with proper browser security considerations and cross-tab synchronization.
