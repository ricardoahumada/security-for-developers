# Full PKCE Flow Implementation

```javascript
class PKCEOAuthFlow {
  constructor(config) {
    this.config = config;
  }

  async initiateAuth() {
    // Step 1: Generate code verifier and challenge
    const codeVerifier = this.generateCodeVerifier();
    const codeChallenge = await this.generateCodeChallenge(codeVerifier);
    
    // Step 2: Generate state for CSRF protection
    const state = this.generateRandomString(32);
    
    // Step 3: Store verification data
    sessionStorage.setItem('pkce_code_verifier', codeVerifier);
    sessionStorage.setItem('oauth_state', state);
    
    // Step 4: Build authorization URL
    const authUrl = this.buildAuthorizationUrl(codeChallenge, state);
    
    // Step 5: Redirect to authorization server
    window.location.href = authUrl;
  }

  buildAuthorizationUrl(codeChallenge, state) {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state: state
    });

    return `${this.config.authorizationEndpoint}?${params.toString()}`;
  }

  async handleCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    const storedState = sessionStorage.getItem('oauth_state');
    const codeVerifier = sessionStorage.getItem('pkce_code_verifier');

    // Validate state and retrieve stored values
    if (state !== storedState) {
      throw new Error('State mismatch - potential CSRF attack');
    }

    // Exchange code with proof of code verifier
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

    const response = await fetch(this.config.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams(tokenRequest)
    });

    if (!response.ok) {
      throw new Error('Token exchange failed');
    }

    const tokens = await response.json();
    return this.handleTokens(tokens);
  }
}
```