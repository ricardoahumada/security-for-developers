# PKCE Security Best Practices

## Code Verifier Storage

```javascript
// ❌ NEVER: Store code verifier in localStorage
class InsecurePKCEClient {
  async initiateLogin() {
    const codeVerifier = await this.generateCodeVerifier();
    // VULNERABLE: Persists across browser restarts
    localStorage.setItem('pkce_code_verifier', codeVerifier);
    // ... continue OAuth flow
  }
}

// ✅ SECURE: Store in sessionStorage (temporary)
class SecurePKCEClient {
  async initiateLogin() {
    const codeVerifier = await this.generateCodeVerifier();
    // SECURE: Cleared when browser tab closes
    sessionStorage.setItem('pkce_code_verifier', codeVerifier);
    // ... continue OAuth flow
  }
}

// ✅ SECURE: Store in memory (React state/ref)
class ReactPKCEClient {
  async initiateLogin() {
    const codeVerifier = await this.generateCodeVerifier();
    // SECURE: Only in component state, cleared on unmount
    this.setState({ codeVerifier });
    // ... continue OAuth flow
  }
}
```

## Token Storage Security

```javascript
// ❌ NEVER: Store tokens in localStorage
class InsecureTokenStorage {
  storeTokens(tokens) {
    // VULNERABLE: Accessible to JavaScript, persists
    localStorage.setItem('access_token', tokens.access_token);
  }
}

// ✅ SECURE: Use HTTP-only cookies (server-side)
class SecureCookieStorage {
  storeTokens(tokens, userId) {
    // Set HTTP-only cookie (not accessible to JavaScript)
    document.cookie = `access_token=${tokens.access_token}; HttpOnly; Secure; SameSite=Strict`;
  }
}

// ✅ SECURE: Use secure storage (mobile)
class SecureMobileStorage {
  async storeTokens(tokens) {
    // iOS Keychain / Android Keystore
    await Keychain.setItem('access_token', tokens.access_token);
  }
}
```

## State Parameter with PKCE

```javascript
// ✅ SECURE: Combine PKCE with state validation
class CombinedPKCEStateClient {
  async initiateLogin() {
    const codeVerifier = await this.generateCodeVerifier();
    const codeChallenge = await this.generateCodeChallenge(codeVerifier);
    
    // Create secure state with context
    const state = {
      userContext: this.getUserContext(),
      timestamp: Date.now(),
      nonce: crypto.randomBytes(16).toString('hex'),
      codeVerifierHash: await this.hashCodeVerifier(codeVerifier)
    };
    
    const stateString = JSON.stringify(state);
    const stateSignature = await this.signState(stateString);
    const finalState = `${stateString}.${stateSignature}`;
    
    // Store code verifier and state
    sessionStorage.setItem('pkce_code_verifier', codeVerifier);
    sessionStorage.setItem('oauth_state', finalState);
    
    // Continue with OAuth flow...
  }
  
  async validateCallback(code, state) {
    const storedState = sessionStorage.getItem('oauth_state');
    const storedVerifier = sessionStorage.getItem('pkce_code_verifier');
    
    // Validate state structure
    if (!storedState || !storedVerifier) {
      throw new Error('Missing PKCE parameters');
    }
    
    // Parse and validate state
    const [stateData, signature] = storedState.split('.');
    const expectedSignature = await this.signState(stateData);
    
    if (signature !== expectedSignature) {
      throw new Error('State tampering detected');
    }
    
    // Validate timestamp (prevent replay)
    const stateObj = JSON.parse(stateData);
    const age = Date.now() - stateObj.timestamp;
    if (age > 30 * 60 * 1000) { // 30 minutes
      throw new Error('State expired');
    }
    
    // Validate code verifier matches
    const verifierHash = await this.hashCodeVerifier(storedVerifier);
    if (verifierHash !== stateObj.codeVerifierHash) {
      throw new Error('Code verifier mismatch');
    }
    
    return { code, codeVerifier: storedVerifier };
  }
}
```