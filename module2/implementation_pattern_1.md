# Pattern 1: Express.js Implementation

```javascript
const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const session = require('express-session');

const app = express();

// OAuth 2.0 Configuration
const oauthConfig = {
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: 'https://myapp.com/auth/google/callback',
  authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  scope: ['openid', 'email', 'profile']
};

// Step 1: Initiate OAuth flow
app.get('/auth/google', (req, res) => {
  const state = crypto.randomBytes(32).toString('hex');
  
  // Store state in session
  req.session.oauthState = state;
  
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: oauthConfig.clientId,
    redirect_uri: oauthConfig.redirectUri,
    scope: oauthConfig.scope.join(' '),
    state: state
  });
  
  res.redirect(`${oauthConfig.authorizationUrl}?${params.toString()}`);
});

// Step 2: Handle OAuth callback
app.get('/auth/google/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;
    
    // Handle errors
    if (error) {
      return res.redirect(`/login?error=${error}`);
    }
    
    // Validate state (CSRF protection)
    if (state !== req.session.oauthState) {
      throw new Error('Invalid state parameter');
    }
    
    // Clear session state
    delete req.session.oauthState;
    
    // Exchange code for tokens
    const tokens = await exchangeCodeForTokens(code);
    
    // Get user info
    const userInfo = await getUserInfo(tokens.access_token);
    
    // Create user session
    req.session.user = {
      id: userInfo.id,
      email: userInfo.email,
      name: userInfo.name,
      tokens: tokens
    };
    
    res.redirect('/dashboard');
    
  } catch (error) {
    console.error('OAuth callback error:', error.message);
    res.redirect('/login?error=oauth_failed');
  }
});

// Token exchange function
async function exchangeCodeForTokens(code) {
  const tokenResponse = await axios.post(oauthConfig.tokenUrl, {
    grant_type: 'authorization_code',
    client_id: oauthConfig.clientId,
    client_secret: oauthConfig.clientSecret,
    code: code,
    redirect_uri: oauthConfig.redirectUri
  }, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });
  
  return tokenResponse.data;
}

// Get user info with access token
async function getUserInfo(accessToken) {
  const userResponse = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });
  
  return userResponse.data;
}

// Protected route middleware
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/auth/google');
  }
  next();
}

// Protected route example
app.get('/dashboard', requireAuth, (req, res) => {
  res.json({
    message: 'Welcome to dashboard!',
    user: req.session.user
  });
});
```

