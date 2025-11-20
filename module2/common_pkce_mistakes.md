# Common PKCE Implementation Mistakes

## Mistake 1: Using Plain Method Instead of S256

```javascript
// ❌ VULNERABLE: Using plain method
const codeChallenge = codeVerifier; // Plain method - discouraged!

// ✅ SECURE: Use S256 method
const codeChallenge = await generateCodeChallenge(codeVerifier); // S256 method
```

## Mistake 2: Storing Code Verifier in Wrong Storage

```javascript
// ❌ VULNERABLE: LocalStorage persistence
localStorage.setItem('pkce_code_verifier', codeVerifier);

// ✅ SECURE: SessionStorage for temporary storage
sessionStorage.setItem('pkce_code_verifier', codeVerifier);

// ✅ SECURE: React state for component lifetime
const [codeVerifier, setCodeVerifier] = useState(null);

// ✅ SECURE: Mobile secure storage
await Keychain.setItem('code_verifier', codeVerifier);
```

## Mistake 3: Not Validating State and Code Verifier

```javascript
// ❌ VULNERABLE: Missing validation
async handleCallback(code) {
  const codeVerifier = sessionStorage.getItem('pkce_code_verifier');
  const tokens = await exchangeCodeForTokens(code, codeVerifier);
  return tokens;
}

// ✅ SECURE: Proper validation
async handleCallback(code, state) {
  // Validate state
  const storedState = sessionStorage.getItem('oauth_state');
  if (state !== storedState) {
    throw new Error('CSRF attack detected');
  }
  
  // Validate code verifier
  const codeVerifier = sessionStorage.getItem('pkce_code_verifier');
  if (!codeVerifier) {
    throw new Error('Missing code verifier');
  }
  
  // Clean up
  sessionStorage.removeItem('oauth_state');
  sessionStorage.removeItem('pkce_code_verifier');
  
  const tokens = await exchangeCodeForTokens(code, codeVerifier);
  return tokens;
}
```

## Mistake 4: Weak Random Number Generation

```javascript
// ❌ VULNERABLE: Weak random generation
function generateWeakCodeVerifier() {
  return Math.random().toString(36).substring(2, 15); // Predictable!
}

// ✅ SECURE: Cryptographically secure random
function generateSecureCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode.apply(null, array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
```

---
