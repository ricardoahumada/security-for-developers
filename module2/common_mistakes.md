# Common Implementation Mistakes

## Mistake 1: Weak State Parameter Generation

```javascript
// VULNERABLE: Predictable state
function generateWeakState() {
  return Math.random().toString(36); // Predictable!
}

// SECURE: Cryptographically secure state
function generateSecureState() {
  return crypto.randomBytes(32).toString('hex');
}
```

## Mistake 2: No State Validation

```javascript
// VULNERABLE: No state validation
app.get('/oauth/callback', async (req, res) => {
  const { code } = req.query;
  
  // Missing state validation - vulnerable to CSRF!
  const tokens = await exchangeCodeForTokens(code);
  res.json(tokens);
});

// SECURE: Proper state validation
app.get('/oauth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  
  // Validate state parameter
  if (!state) {
    return res.status(400).json({ error: 'Missing state parameter' });
  }
  
  if (state !== req.session.oauthState) {
    return res.status(400).json({ error: 'Invalid state parameter' });
  }
  
  // Clear stored state
  delete req.session.oauthState;
  
  if (error) {
    return res.status(400).json({ error });
  }
  
  const tokens = await exchangeCodeForTokens(code);
  res.json(tokens);
});
```

## Mistake 3: Client Secrets in Code

```javascript
// VULNERABLE: Hardcoded client secret
const clientSecret = 'your-actual-secret-12345';

// SECURE: Environment variable
const clientSecret = process.env.OAUTH_CLIENT_SECRET;
```

## Mistake 4: No Token Storage Security

```javascript
// VULNERABLE: Insecure token storage
function storeTokens(tokens) {
  localStorage.setItem('access_token', tokens.access_token);
  localStorage.setItem('refresh_token', tokens.refresh_token);
}

// SECURE: Server-side token storage
function storeTokens(tokens, userId) {
  const hashedTokens = {
    access_token: hashToken(tokens.access_token),
    refresh_token: hashToken(tokens.refresh_token),
    expires_at: tokens.expires_in,
    user_id: userId
  };
  
  database.user_tokens.insert(hashedTokens);
}
```
