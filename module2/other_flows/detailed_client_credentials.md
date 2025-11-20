# Detailed Client Credentials Implementation

## Step 1: Client Authentication Request

```javascript
class ClientCredentialsClient {
  constructor(config) {
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret; // Keep secure!
    this.tokenUrl = config.tokenUrl;
    this.apiBaseUrl = config.apiBaseUrl;
  }

  // Step 1: Request access token with client credentials
  async requestAccessToken(scopes = []) {
    const credentials = `${this.clientId}:${this.clientSecret}`;
    const encodedCredentials = Buffer.from(credentials).toString('base64');

    const tokenRequest = new URLSearchParams({
      grant_type: 'client_credentials'
    });

    // Add scopes if provided
    if (scopes.length > 0) {
      tokenRequest.append('scope', scopes.join(' '));
    }

    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${encodedCredentials}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: tokenRequest.toString()
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(`Token request failed: ${error.error}`);
    }

    const tokens = await response.json();
    
    // Store tokens securely
    await this.storeTokens(tokens);
    
    return tokens;
  }

  storeTokens(tokens) {
    // Store in secure database or configuration management
    return {
      access_token: this.encryptToken(tokens.access_token),
      refresh_token: tokens.refresh_token ? this.encryptToken(tokens.refresh_token) : null,
      expires_at: Date.now() + (tokens.expires_in * 1000),
      token_type: tokens.token_type,
      scope: tokens.scope
    };
  }
}
```

## Step 2: Using Access Tokens for API Calls

```javascript
class ProtectedAPI {
  constructor(client) {
    this.client = client;
  }

  // Make authenticated API calls
  async makeAuthenticatedRequest(endpoint, options = {}) {
    try {
      // Get valid access token
      const accessToken = await this.getValidAccessToken();
      
      const response = await fetch(`${this.client.apiBaseUrl}${endpoint}`, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 401) {
        // Token might be expired, try to refresh
        await this.refreshAccessToken();
        return this.makeAuthenticatedRequest(endpoint, options);
      }

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`);
      }

      return await response.json();
      
    } catch (error) {
      throw new Error(`Authenticated request failed: ${error.message}`);
    }
  }

  async getValidAccessToken() {
    const storedTokens = await this.client.getStoredTokens();
    
    if (!storedTokens) {
      throw new Error('No stored tokens found');
    }

    // Check if token is expired
    if (Date.now() >= storedTokens.expires_at) {
      if (storedTokens.refresh_token) {
        return await this.refreshAccessToken();
      } else {
        throw new Error('Token expired and no refresh token available');
      }
    }

    return this.client.decryptToken(storedTokens.access_token);
  }

  async refreshAccessToken() {
    const storedTokens = await this.client.getStoredTokens();
    
    if (!storedTokens.refresh_token) {
      throw new Error('No refresh token available');
    }

    const refreshResponse = await fetch(this.client.tokenUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${Buffer.from(`${this.client.clientId}:${this.client.clientSecret}`).toString('base64')}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: this.client.decryptToken(storedTokens.refresh_token)
      })
    });

    if (!refreshResponse.ok) {
      throw new Error('Token refresh failed');
    }

    const newTokens = await refreshResponse.json();
    
    // Update stored tokens
    await this.client.storeTokens(newTokens);
    
    return newTokens.access_token;
  }
}
```
