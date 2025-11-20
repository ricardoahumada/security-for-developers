# Pattern 2: Python Flask Implementation

```python
from flask import Flask, request, redirect, session, jsonify
import requests
import secrets
import base64
import urllib.parse

app = Flask(__name__)
app.secret_key = 'your-secret-key'

# OAuth 2.0 Configuration
OAUTH_CONFIG = {
    'client_id': 'your-client-id',
    'client_secret': 'your-client-secret',
    'authorization_url': 'https://accounts.google.com/o/oauth2/v2/auth',
    'token_url': 'https://oauth2.googleapis.com/token',
    'userinfo_url': 'https://www.googleapis.com/oauth2/v2/userinfo',
    'redirect_uri': 'https://yourapp.com/auth/callback',
    'scope': ['openid', 'email', 'profile']
}

@app.route('/auth/google')
def auth_google():
    # Generate secure state
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Build authorization URL
    params = {
        'response_type': 'code',
        'client_id': OAUTH_CONFIG['client_id'],
        'redirect_uri': OAUTH_CONFIG['redirect_uri'],
        'scope': ' '.join(OAUTH_CONFIG['scope']),
        'state': state
    }
    
    auth_url = f"{OAUTH_CONFIG['authorization_url']}?{urllib.parse.urlencode(params)}"
    return redirect(auth_url)

@app.route('/auth/callback')
def auth_callback():
    try:
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        
        # Handle errors
        if error:
            return redirect(f"/login?error={error}")
        
        # Validate state (CSRF protection)
        if state != session.get('oauth_state'):
            raise ValueError('Invalid state parameter')
        
        # Clear session state
        session.pop('oauth_state', None)
        
        # Exchange code for tokens
        tokens = exchange_code_for_tokens(code)
        
        # Get user information
        user_info = get_user_info(tokens['access_token'])
        
        # Store user session
        session['user'] = {
            'id': user_info['id'],
            'email': user_info['email'],
            'name': user_info['name'],
            'tokens': tokens
        }
        
        return redirect('/dashboard')
        
    except Exception as e:
        print(f"OAuth callback error: {e}")
        return redirect('/login?error=oauth_failed')

def exchange_code_for_tokens(code):
    """Exchange authorization code for access tokens"""
    token_data = {
        'grant_type': 'authorization_code',
        'client_id': OAUTH_CONFIG['client_id'],
        'client_secret': OAUTH_CONFIG['client_secret'],
        'code': code,
        'redirect_uri': OAUTH_CONFIG['redirect_uri']
    }
    
    response = requests.post(OAUTH_CONFIG['token_url'], data=token_data)
    
    if response.status_code != 200:
        raise ValueError(f"Token exchange failed: {response.text}")
    
    return response.json()

def get_user_info(access_token):
    """Get user information using access token"""
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(OAUTH_CONFIG['userinfo_url'], headers=headers)
    
    if response.status_code != 200:
        raise ValueError(f"Failed to get user info: {response.text}")
    
    return response.json()

@app.route('/dashboard')
def dashboard():
    """Protected dashboard route"""
    if 'user' not in session:
        return redirect('/auth/google')
    
    return jsonify({
        'message': 'Welcome to dashboard!',
        'user': session['user']
    })

@app.route('/api/profile')
def api_profile():
    """API route requiring authentication"""
    if 'user' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    
    # Make API call with user's access token
    user_token = session['user']['tokens']['access_token']
    headers = {'Authorization': f'Bearer {user_token}'}
    
    # Example: Get user's Google Drive files
    response = requests.get('https://www.googleapis.com/drive/v3/files', headers=headers)
    
    if response.status_code == 401:
        # Token might be expired, try refresh
        tokens = refresh_user_token(session['user']['tokens'])
        session['user']['tokens'] = tokens
        return redirect('/api/profile')
    
    return jsonify(response.json())

def refresh_user_token(tokens):
    """Refresh expired access token"""
    refresh_data = {
        'grant_type': 'refresh_token',
        'client_id': OAUTH_CONFIG['client_id'],
        'client_secret': OAUTH_CONFIG['client_secret'],
        'refresh_token': tokens['refresh_token']
    }
    
    response = requests.post(OAUTH_CONFIG['token_url'], data=refresh_data)
    
    if response.status_code != 200:
        raise ValueError("Token refresh failed")
    
    new_tokens = response.json()
    
    # Keep the same refresh token if not provided
    if 'refresh_token' not in new_tokens:
        new_tokens['refresh_token'] = tokens['refresh_token']
    
    return new_tokens

if __name__ == '__main__':
    app.run(debug=True)
```
