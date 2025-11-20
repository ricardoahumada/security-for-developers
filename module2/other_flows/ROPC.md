# ROPC Implementation (Legacy Support Only)

```javascript
// ⚠️ LEGACY: ROPC implementation (discouraged)
class ROPCClient {
  constructor(config) {
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.tokenUrl = config.tokenUrl;
  }

  // ⚠️ LEGACY: Only use for backward compatibility
  async authenticateUser(username, password) {
    const credentials = `${this.clientId}:${this.clientSecret}`;
    const encodedCredentials = Buffer.from(credentials).toString('base64');

    const tokenRequest = new URLSearchParams({
      grant_type: 'password',
      username: username,
      password: password,
      scope: 'openid profile email'
    });

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
      throw new Error(`ROPC authentication failed: ${error.error}`);
    }

    const tokens = await response.json();
    
    // ⚠️ SECURITY WARNING: Handle with extreme care
    await this.handleUserCredentials(username, password, tokens);
    
    return tokens;
  }

  // ⚠️ SECURITY WARNING: Never store passwords!
  async handleUserCredentials(username, password, tokens) {
    // ❌ NEVER: Store passwords
    // await this.storePassword(username, password);
    
    // ✅ RECOMMENDED: Use for token management only
    // Never log or persist passwords
    // Use immediately for token exchange, then discard
    
    // ✅ If you must support ROPC, follow these guidelines:
    this.validateROPCSupport();
    this.logROPCUsage(username);
    this.schedulePasswordDeletion();
  }
}
```
