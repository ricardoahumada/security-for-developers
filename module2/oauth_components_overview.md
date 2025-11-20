# OAuth 2.0 Components Overview

## Component Architecture

### Core Components Implementation

```javascript
// OAuth 2.0 Components Visualization
class OAuthComponent {
    constructor(name, type, securityLevel) {
        this.name = name;
        this.type = type;
        this.securityLevel = securityLevel;
    }

    describe() {
        return `${this.name}: ${this.type} component with ${this.securityLevel} security requirements`;
    }
}

// Resource Owner Implementation
class ResourceOwner {
    constructor(userId, permissions) {
        this.userId = userId;
        this.permissions = permissions;
        this.consentHistory = [];
    }

    grantConsent(clientId, requestedScopes) {
        const consent = {
            clientId: clientId,
            scopes: requestedScopes,
            timestamp: new Date().toISOString(),
            granted: true
        };
        this.consentHistory.push(consent);
        return consent;
    }

    revokeConsent(clientId) {
        this.consentHistory = this.consentHistory.filter(
            consent => consent.clientId !== clientId
        );
    }
}

// Client Implementation with Types
class OAuthClient {
    constructor(config) {
        this.clientId = config.clientId;
        this.clientType = config.clientType; // 'confidential' or 'public'
        this.redirectUris = config.redirectUris || [];
        this.grantedScopes = config.scopes || [];
        this.clientSecret = config.clientSecret;
    }

    canUseClientCredentials() {
        return this.clientType === 'confidential' && this.clientSecret;
    }

    validateRedirectUri(uri) {
        return this.redirectUris.includes(uri);
    }
}

// Authorization Server Implementation
class AuthorizationServer {
    constructor(config) {
        this.config = config;
        this.authorizationCodes = new Map();
        this.accessTokens = new Map();
        this.refreshTokens = new Map();
        this.clients = new Map();
        this.users = new Map();
    }

    // Register a new client
    registerClient(clientConfig) {
        const client = new OAuthClient(clientConfig);
        this.clients.set(client.clientId, client);
        return client;
    }

    // Generate and store authorization code
    generateAuthorizationCode(clientId, userId, redirectUri, scopes, state) {
        const code = this.generateRandomString(32);
        const expiration = Date.now() + (10 * 60 * 1000); // 10 minutes

        const codeData = {
            clientId: clientId,
            userId: userId,
            redirectUri: redirectUri,
            scopes: scopes,
            state: state,
            expiration: expiration
        };

        this.authorizationCodes.set(code, codeData);
        return code;
    }

    // Validate and consume authorization code
    validateAuthorizationCode(code, clientId, clientSecret) {
        const codeData = this.authorizationCodes.get(code);
        
        if (!codeData) return null;
        if (codeData.expiration < Date.now()) return null;
        if (codeData.clientId !== clientId) return null;

        // For confidential clients, verify client secret
        const client = this.clients.get(clientId);
        if (client.clientType === 'confidential' && client.clientSecret !== clientSecret) {
            return null;
        }

        // Remove used code
        this.authorizationCodes.delete(code);
        return codeData;
    }

    // Generate access token
    generateAccessToken(clientId, userId, scopes) {
        const tokenData = {
            accessToken: this.generateJWT(),
            refreshToken: this.generateRandomString(64),
            clientId: clientId,
            userId: userId,
            scopes: scopes,
            expiration: Date.now() + (3600 * 1000), // 1 hour
            issuedAt: Date.now()
        };

        this.accessTokens.set(tokenData.accessToken, tokenData);
        this.refreshTokens.set(tokenData.refreshToken, tokenData);
        return tokenData;
    }

    // Generate random string
    generateRandomString(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return Array.from(array, byte => 
            ('0' + byte.toString(16)).slice(-2)
        ).join('');
    }

    // Generate JWT (simplified)
    generateJWT() {
        const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
        const payload = btoa(JSON.stringify({ 
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3600
        }));
        const signature = this.generateRandomString(64);
        return `${header}.${payload}.${signature}`;
    }
}

// Resource Server Implementation
class ResourceServer {
    constructor(config) {
        this.config = config;
        this.protectedResources = new Map();
        this.authorizationServer = config.authorizationServer;
    }

    // Register a protected resource
    registerResource(resourceId, accessRequirements) {
        const resource = {
            resourceId: resourceId,
            accessRequirements: accessRequirements,
            metadata: {
                created: new Date().toISOString(),
                type: 'api_endpoint'
            }
        };
        this.protectedResources.set(resourceId, resource);
        return resource;
    }

    // Validate access token and check permissions
    validateAccessToken(accessToken, requiredScopes) {
        const tokenData = this.authorizationServer.accessTokens.get(accessToken);
        
        if (!tokenData) return { valid: false, reason: 'Invalid token' };
        if (tokenData.expiration < Date.now()) return { valid: false, reason: 'Token expired' };

        // Check if token has required scopes
        const hasRequiredScopes = requiredScopes.every(scope => 
            tokenData.scopes.includes(scope)
        );

        if (!hasRequiredScopes) {
            return { valid: false, reason: 'Insufficient permissions' };
        }

        return { 
            valid: true, 
            userId: tokenData.userId, 
            scopes: tokenData.scopes 
        };
    }

    // Handle protected resource request
    handleProtectedRequest(req, res) {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Missing or invalid authorization header' });
        }

        const accessToken = authHeader.substring(7);
        const resourceId = req.params.resourceId;
        const requiredScopes = this.getRequiredScopes(req.method, resourceId);

        const validation = this.validateAccessToken(accessToken, requiredScopes);
        
        if (!validation.valid) {
            return res.status(403).json({ 
                error: 'Access denied', 
                reason: validation.reason 
            });
        }

        // Grant access to resource
        return this.accessResource(req, res, validation);
    }

    getRequiredScopes(httpMethod, resourceId) {
        // Define scope requirements for different operations
        const scopeMap = {
            'GET': ['read'],
            'POST': ['write'],
            'PUT': ['write'],
            'PATCH': ['write'],
            'DELETE': ['admin']
        };
        return scopeMap[httpMethod] || ['read'];
    }

    accessResource(req, res, validation) {
        // Implementation would handle the actual resource access
        res.json({
            message: 'Access granted',
            userId: validation.userId,
            scopes: validation.scopes,
            timestamp: new Date().toISOString()
        });
    }
}

// Usage Example
function demonstrateOAuthComponents() {
    // Setup
    const authServer = new AuthorizationServer({
        issuer: 'https://auth.example.com'
    });

    const resourceServer = new ResourceServer({
        authorizationServer: authServer
    });

    // Register a client
    const client = authServer.registerClient({
        clientId: 'web-app-123',
        clientType: 'confidential',
        clientSecret: 'super-secret-key',
        redirectUris: ['https://web-app.example.com/callback'],
        scopes: ['read', 'write']
    });

    // Register a protected resource
    resourceServer.registerResource('user-profile', {
        scopes: ['read'],
        description: 'User profile information'
    });

    // Simulate OAuth flow
    const authCode = authServer.generateAuthorizationCode(
        'web-app-123',
        'user-456',
        'https://web-app.example.com/callback',
        ['read', 'write'],
        'random-state-123'
    );

    console.log('Generated authorization code:', authCode);

    // Exchange code for tokens
    const tokenData = authServer.validateAuthorizationCode(
        authCode,
        'web-app-123',
        'super-secret-key'
    );

    if (tokenData) {
        const tokens = authServer.generateAccessToken(
            'web-app-123',
            'user-456',
            ['read', 'write']
        );

        console.log('Access tokens generated:', tokens);
    }

    // Validate access
    const resourceValidation = resourceServer.validateAccessToken(
        'access-token-example',
        ['read']
    );

    console.log('Resource access validation:', resourceValidation);
}

// Component Relationship Diagram
console.log(`
OAuth 2.0 Component Relationships:

Resource Owner (User)
       ↓
       ↓ [Authorization Request]
       ↓
    Client (Application)
       ↓ [Authorization Code]
       ↓
Authorization Server
       ↓ [Access Token]
       ↓
    Resource Server (API)
       ↓
    Protected Resources
`);

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        OAuthComponent,
        ResourceOwner,
        OAuthClient,
        AuthorizationServer,
        ResourceServer,
        demonstrateOAuthComponents
    };
} else {
    // Browser environment
    window.OAuthComponents = {
        OAuthComponent,
        ResourceOwner,
        OAuthClient,
        AuthorizationServer,
        ResourceServer,
        demonstrateOAuthComponents
    };
}
```

## Component Types Comparison

| Component | Type | Responsibilities | Security Level | Examples |
|-----------|------|-----------------|----------------|----------|
| **Resource Owner** | Human/User | Grants consent, owns data | N/A | End users, customers |
| **Client** | Application | Requests access, uses tokens | Depends on type | Web apps, mobile apps, APIs |
| **Authorization Server** | Service | Issues tokens, validates | High | Auth0, Google OAuth, Okta |
| **Resource Server** | API Service | Protects resources | High | Gmail API, Drive API, internal APIs |

## Security Considerations by Component

### Resource Owner
- **Authentication**: Must authenticate securely
- **Consent**: Granular control over permissions
- **Revocation**: Easy access revocation mechanism

### Client
- **Client Registration**: Secure client registration process
- **Confidential Clients**: Secure secret storage
- **Public Clients**: No secret storage, use PKCE

### Authorization Server
- **Token Generation**: Cryptographically secure
- **State Management**: CSRF protection
- **Code Management**: Single-use, short-lived codes

### Resource Server
- **Token Validation**: Validate all tokens
- **Scope Checking**: Enforce granular permissions
- **Audit Logging**: Track all access attempts

This overview provides the foundation for understanding how OAuth 2.0 components work together to provide secure, delegated authorization.
