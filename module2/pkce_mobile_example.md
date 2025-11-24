# Mobile PKCE Implementation Example

## React Native Mobile App with OAuth 2.0 PKCE

This implementation demonstrates PKCE flow specifically designed for React Native mobile applications, including proper platform-specific considerations for iOS and Android.

```javascript
// React Native PKCE Implementation
import { Platform, Linking, Alert } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import CryptoJS from 'crypto-js'; // You'll need to install this package

// Mobile-specific PKCE Configuration
const MobilePKCEConfig = {
    // App-specific configuration
    app: {
        scheme: 'myapp', // Custom URL scheme for deep linking
        bundleId: 'com.mycompany.myapp', // iOS bundle ID / Android package name
        name: 'My Mobile App'
    },
    
    // OAuth provider configurations
    providers: {
        google: {
            authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
            tokenEndpoint: 'https://oauth2.googleapis.com/token',
            clientId: 'your-google-client-id.googleusercontent.com',
            scopes: ['openid', 'profile', 'email', 'https://www.googleapis.com/auth/drive.readonly'],
            redirectUri: 'myapp://auth/callback'
        },
        auth0: {
            authorizationEndpoint: 'https://your-tenant.auth0.com/authorize',
            tokenEndpoint: 'https://your-tenant.auth0.com/oauth/token',
            clientId: 'your-auth0-client-id',
            scopes: ['openid', 'profile', 'email'],
            redirectUri: 'myapp://auth/callback'
        },
        generic: {
            authorizationEndpoint: 'https://auth.provider.com/authorize',
            tokenEndpoint: 'https://auth.provider.com/token',
            clientId: 'your-mobile-client-id',
            scopes: ['read', 'write', 'profile'],
            redirectUri: 'myapp://auth/callback'
        }
    }
};

// Mobile PKCE Flow Manager
class MobilePKCEFlow {
    constructor(provider = 'google') {
        this.config = MobilePKCEConfig.providers[provider];
        this.appConfig = MobilePKCEConfig.app;
        this.currentAuthRequest = null;
        this.isAuthenticating = false;
    }

    // Generate PKCE parameters for mobile
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
            expiration: Date.now() + (15 * 60 * 1000), // 15 minutes for mobile
            provider: this.config.clientId
        };

        return pkceData;
    }

    // Generate cryptographically secure random string for mobile
    generateCodeVerifier(length = 64) {
        // For React Native, we'll use CryptoJS for consistent random generation
        const randomBytes = CryptoJS.lib.WordArray.random(length);
        const base64String = CryptoJS.enc.Base64.stringify(randomBytes);
        
        // Ensure URL-safe encoding
        return base64String
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '')
            .substring(0, length);
    }

    // Generate SHA256 code challenge
    generateCodeChallenge(codeVerifier) {
        const hash = CryptoJS.SHA256(codeVerifier);
        return CryptoJS.enc.Base64.stringify(hash)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    // Generate secure random string
    generateSecureRandomString(length = 32) {
        const randomBytes = CryptoJS.lib.WordArray.random(length);
        const base64String = CryptoJS.enc.Base64.stringify(randomBytes);
        return base64String
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '')
            .substring(0, length);
    }

    // Initiate authentication flow
    async initiateAuthentication() {
        if (this.isAuthenticating) {
            throw new Error('Authentication already in progress');
        }

        try {
            this.isAuthenticating = true;
            
            // Generate PKCE parameters
            const pkceData = this.generatePKCEParameters();
            
            // Store PKCE data securely
            await this.storePKCEData(pkceData);
            
            // Build authorization URL
            const authUrl = this.buildAuthorizationUrl(pkceData);
            
            // Open authorization URL in browser
            await this.openAuthorizationUrl(authUrl);
            
            // Listen for callback
            this.setupAuthCallbackListener();
            
            return {
                success: true,
                message: 'Authentication initiated. Complete login in browser.',
                state: pkceData.state
            };

        } catch (error) {
            this.isAuthenticating = false;
            throw new MobilePKCEError('AUTH_INITIATION_FAILED', error.message);
        }
    }

    // Build authorization URL with mobile-specific parameters
    buildAuthorizationUrl(pkceData) {
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            scope: this.config.scopes.join(' '),
            state: pkceData.state,
            nonce: pkceData.nonce,
            code_challenge: pkceData.codeChallenge,
            code_challenge_method: 'S256',
            // Mobile-specific parameters
            access_type: 'offline',
            prompt: 'consent',
            // iOS-specific
            ...(Platform.OS === 'ios' && {
                response_type: 'code'
            })
        });

        return `${this.config.authorizationEndpoint}?${params.toString()}`;
    }

    // Open authorization URL in browser
    async openAuthorizationUrl(url) {
        try {
            const supported = await Linking.canOpenURL(url);
            
            if (supported) {
                await Linking.openURL(url);
            } else {
                throw new Error('Cannot open authorization URL');
            }
        } catch (error) {
            throw new MobilePKCEError('BROWSER_OPEN_FAILED', `Cannot open browser: ${error.message}`);
        }
    }

    // Setup callback listener for deep linking
    setupAuthCallbackListener() {
        const subscription = Linking.addEventListener('url', async (event) => {
            await this.handleAuthCallback(event.url);
            subscription.remove();
        });
    }

    // Handle authentication callback
    async handleAuthCallback(url) {
        try {
            // Parse callback URL
            const { code, state, error } = this.parseCallbackUrl(url);
            
            // Handle OAuth errors
            if (error) {
                throw new MobilePKCEError('OAUTH_ERROR', `${error}: ${url.split('error=')[1]}`);
            }

            // Validate parameters
            if (!code || !state) {
                throw new MobilePKCEError('INVALID_CALLBACK', 'Missing required parameters in callback');
            }

            // Retrieve stored PKCE data
            const storedPKCEData = await this.retrievePKCEData();
            if (!storedPKCEData) {
                throw new MobilePKCEError('NO_PKCE_DATA', 'No PKCE data found in storage');
            }

            // Validate state parameter
            if (state !== storedPKCEData.state) {
                throw new MobilePKCEError('STATE_MISMATCH', 'State parameter does not match');
            }

            // Exchange code for tokens
            const tokenData = await this.exchangeCodeForTokens(code, storedPKCEData);
            
            // Clean up PKCE data
            await this.clearPKCEData();
            
            // Store tokens securely
            await this.storeTokens(tokenData);
            
            // Notify success
            this.onAuthSuccess(tokenData);
            
        } catch (error) {
            this.onAuthError(error);
        } finally {
            this.isAuthenticating = false;
        }
    }

    // Parse callback URL
    parseCallbackUrl(url) {
        const urlObj = new URL(url);
        const params = new URLSearchParams(urlObj.hash ? urlObj.hash.substring(1) : urlObj.search);
        
        return {
            code: params.get('code'),
            state: params.get('state'),
            error: params.get('error'),
            errorDescription: params.get('error_description')
        };
    }

    // Exchange authorization code for tokens
    async exchangeCodeForTokens(authorizationCode, pkceData) {
        const tokenRequest = {
            grant_type: 'authorization_code',
            client_id: this.config.clientId,
            code: authorizationCode,
            redirect_uri: this.config.redirectUri,
            code_verifier: pkceData.codeVerifier
        };

        try {
            const response = await fetch(this.config.tokenEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                },
                body: new URLSearchParams(tokenRequest)
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new MobilePKCEError('TOKEN_EXCHANGE_FAILED', 
                    `Token request failed: ${errorData.error || response.status}`);
            }

            const tokenResponse = await response.json();
            
            // Validate token response
            if (!tokenResponse.access_token) {
                throw new MobilePKCEError('INVALID_TOKEN_RESPONSE', 'No access token in response');
            }

            // Add expiration timestamp
            if (tokenResponse.expires_in) {
                tokenResponse.expires_at = Date.now() + (tokenResponse.expires_in * 1000);
            }

            return tokenResponse;

        } catch (error) {
            if (error.name === 'MobilePKCEError') {
                throw error;
            }
            throw new MobilePKCEError('TOKEN_REQUEST_FAILED', `Token request failed: ${error.message}`);
        }
    }

    // Store PKCE data securely
    async storePKCEData(pkceData) {
        try {
            await AsyncStorage.setItem('@pkce_data', JSON.stringify(pkceData));
        } catch (error) {
            throw new MobilePKCEError('STORAGE_FAILED', `Failed to store PKCE data: ${error.message}`);
        }
    }

    // Retrieve stored PKCE data
    async retrievePKCEData() {
        try {
            const stored = await AsyncStorage.getItem('@pkce_data');
            return stored ? JSON.parse(stored) : null;
        } catch (error) {
            return null;
        }
    }

    // Clear stored PKCE data
    async clearPKCEData() {
        try {
            await AsyncStorage.removeItem('@pkce_data');
        } catch (error) {
            console.warn('Failed to clear PKCE data:', error.message);
        }
    }

    // Store tokens securely
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
                createdAt: new Date().toISOString()
            };

            // Encrypt sensitive data before storing
            const encryptedRecord = await this.encryptSensitiveData(tokenRecord);
            await AsyncStorage.setItem('@auth_tokens', JSON.stringify(encryptedRecord));

        } catch (error) {
            throw new MobilePKCEError('TOKEN_STORAGE_FAILED', `Failed to store tokens: ${error.message}`);
        }
    }

    // Get stored tokens
    async getStoredTokens() {
        try {
            const stored = await AsyncStorage.getItem('@auth_tokens');
            if (!stored) return null;

            const encryptedRecord = JSON.parse(stored);
            return await this.decryptSensitiveData(encryptedRecord);

        } catch (error) {
            console.error('Failed to retrieve tokens:', error);
            return null;
        }
    }

    // Encrypt sensitive data
    async encryptSensitiveData(data) {
        // In production, use platform-specific secure storage (Keychain/Keystore)
        const secretKey = 'your-encryption-key'; // Use device-specific key in production
        const encrypted = CryptoJS.AES.encrypt(JSON.stringify(data), secretKey).toString();
        
        return {
            data: encrypted,
            timestamp: Date.now()
        };
    }

    // Decrypt sensitive data
    async decryptSensitiveData(encryptedRecord) {
        const secretKey = 'your-encryption-key'; // Use device-specific key in production
        try {
            const bytes = CryptoJS.AES.decrypt(encryptedRecord.data, secretKey);
            const decrypted = bytes.toString(CryptoJS.enc.Utf8);
            return JSON.parse(decrypted);
        } catch (error) {
            throw new MobilePKCEError('DECRYPTION_FAILED', 'Failed to decrypt stored data');
        }
    }

    // Refresh access token
    async refreshAccessToken() {
        const tokens = await this.getStoredTokens();
        if (!tokens || !tokens.refreshToken) {
            throw new MobilePKCEError('NO_REFRESH_TOKEN', 'No refresh token available');
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
                body: new URLSearchParams(tokenRequest)
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
            return updatedTokens;

        } catch (error) {
            // Clear invalid tokens
            await this.clearTokens();
            throw new MobilePKCEError('REFRESH_FAILED', `Token refresh failed: ${error.message}`);
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
            throw new MobilePKCEError('NO_TOKENS', 'No authentication tokens found');
        }

        if (await this.isTokenExpired()) {
            return await this.refreshAccessToken();
        }

        return tokens.accessToken;
    }

    // Clear stored tokens
    async clearTokens() {
        try {
            await AsyncStorage.removeItem('@auth_tokens');
            await this.clearPKCEData();
        } catch (error) {
            console.warn('Failed to clear tokens:', error.message);
        }
    }

    // Logout
    async logout() {
        await this.clearTokens();
        this.isAuthenticating = false;
    }

    // Callback methods to be overridden
    onAuthSuccess(tokenData) {
        // Override this method to handle successful authentication
        console.log('Authentication successful:', tokenData);
    }

    onAuthError(error) {
        // Override this method to handle authentication errors
        console.error('Authentication failed:', error);
        Alert.alert('Authentication Error', error.message);
    }
}

// React Hook for Mobile PKCE
import { useState, useEffect } from 'react';

export function useMobilePKCE(provider = 'google') {
    const [authState, setAuthState] = useState({
        isAuthenticated: false,
        isAuthenticating: false,
        user: null,
        tokens: null,
        error: null
    });

    const [pkceFlow] = useState(() => new MobilePKCEFlow(provider));

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
            
            // Parse user info from ID token if available
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

        // Check for existing tokens on mount
        checkExistingTokens();
    }, []);

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

    const signIn = async () => {
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
    };

    const signOut = async () => {
        await pkceFlow.logout();
        setAuthState({
            isAuthenticated: false,
            isAuthenticating: false,
            user: null,
            tokens: null,
            error: null
        });
    };

    const makeAuthenticatedRequest = async (url, options = {}) => {
        try {
            const accessToken = await pkceFlow.getValidAccessToken();
            return await fetch(url, {
                ...options,
                headers: {
                    ...options.headers,
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/json'
                }
            });
        } catch (error) {
            throw new Error(`Authentication failed: ${error.message}`);
        }
    };

    return {
        ...authState,
        signIn,
        signOut,
        makeAuthenticatedRequest
    };
}

// React Native Component Example
import React from 'react';
import { View, Button, Text, Alert, ActivityIndicator, Image } from 'react-native';

const MobileLoginScreen = () => {
    const {
        isAuthenticated,
        isAuthenticating,
        user,
        error,
        signIn,
        signOut
    } = useMobilePKCE('google');

    if (isAuthenticating) {
        return (
            <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
                <ActivityIndicator size="large" />
                <Text>Authenticating...</Text>
            </View>
        );
    }

    if (isAuthenticated) {
        return (
            <View style={{ flex: 1, padding: 20, justifyContent: 'center' }}>
                <Text style={{ fontSize: 24, fontWeight: 'bold', marginBottom: 20 }}>
                    Welcome back!
                </Text>
                
                {user && (
                    <View style={{ marginBottom: 20 }}>
                        {user.picture && (
                            <Image 
                                source={{ uri: user.picture }} 
                                style={{ width: 80, height: 80, borderRadius: 40, marginBottom: 10 }}
                            />
                        )}
                        <Text>Name: {user.name}</Text>
                        <Text>Email: {user.email}</Text>
                        <Text>User ID: {user.userId}</Text>
                    </View>
                )}
                
                <Button title="Sign Out" onPress={signOut} />
            </View>
        );
    }

    return (
        <View style={{ flex: 1, padding: 20, justifyContent: 'center' }}>
            <Text style={{ fontSize: 24, fontWeight: 'bold', marginBottom: 20 }}>
                Sign in to continue
            </Text>
            
            {error && (
                <View style={{ backgroundColor: '#ffebee', padding: 10, marginBottom: 20 }}>
                    <Text style={{ color: '#c62828' }}>{error}</Text>
                </View>
            )}
            
            <Button 
                title="Sign in with Google" 
                onPress={signIn}
                disabled={isAuthenticating}
            />
        </View>
    );
};

// Platform-specific URL Configuration
const PlatformConfig = {
    ios: {
        // iOS URL Scheme configuration
        urlSchemes: ['myapp'],
        // Universal Links configuration
        universalLinks: {
            domains: ['yourapp.com'],
            paths: ['/auth/callback']
        }
    },
    android: {
        // Android Intent filters
        intentFilters: [
            {
                action: 'VIEW',
                categories: ['DEFAULT', 'BROWSABLE'],
                data: [
                    {
                        scheme: 'myapp',
                        host: 'auth'
                    }
                ]
            }
        ]
    }
};

// Error Classes
class MobilePKCEError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'MobilePKCEError';
        this.code = code;
    }
}

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        MobilePKCEFlow,
        MobilePKCEError,
        useMobilePKCE,
        MobileLoginScreen,
        MobilePKCEConfig,
        PlatformConfig
    };
} else {
    window.MobilePKCEFlow = {
        MobilePKCEFlow,
        MobilePKCEError,
        MobilePKCEConfig,
        PlatformConfig
    };
}

// Usage Instructions
console.log(`
=== Mobile PKCE Implementation Guide ===

1. Install required packages:
   npm install @react-native-async-storage/async-storage crypto-js

2. Configure app.json for deep linking:
   {
     "expo": {
       "scheme": "myapp",
       "ios": {
         "bundleId": "com.mycompany.myapp"
       },
       "android": {
         "package": "com.mycompany.myapp"
       }
     }
   }

3. Set up OAuth redirect URI:
   myapp://auth/callback

4. Use the useMobilePKCE hook in your components:
   const { isAuthenticated, signIn, signOut } = useMobilePKCE('google');

5. Handle authentication in your app flow
`);
```

## Mobile-Specific Security Considerations

### iOS Security
- **App Transport Security**: Ensure HTTPS for all OAuth endpoints
- **Universal Links**: Use universal links instead of custom schemes when possible
- **Keychain Storage**: Store tokens in iOS Keychain for maximum security
- **Background App Refresh**: Consider token refresh during app backgrounding

### Android Security
- **Network Security Config**: Configure network security for HTTPS enforcement
- **Android Keystore**: Use Android Keystore for token encryption
- **App Links**: Prefer Android App Links over custom URL schemes
- **Fingerprint Protection**: Consider biometric authentication for sensitive operations

### Cross-Platform Best Practices
- **Biometric Authentication**: Add biometric protection for high-security apps
- **Certificate Pinning**: Implement certificate pinning for API communications
- **Root Detection**: Detect and handle rooted/jailbroken devices
- **Secure Storage**: Use platform-specific secure storage APIs

### Token Management
- **Automatic Refresh**: Implement automatic token refresh before expiration
- **Secure Deletion**: Securely delete tokens on logout
- **Token Scope**: Minimize requested scopes to reduce attack surface
- **Session Management**: Implement proper session lifecycle management

This mobile-specific PKCE implementation provides a robust, secure authentication solution for React Native applications with proper platform-specific considerations for both iOS and Android.
