# Example: React Native Banking App

```javascript
import React, { useEffect } from 'react';
import { View, Button } from 'react-native';

const BankingApp = () => {
  const initiateOAuth = async () => {
    const config = {
      clientId: 'mobile-banking-app',
      authorizationEndpoint: 'https://bank-oauth.com/authorize',
      tokenEndpoint: 'https://bank-oauth.com/token',
      redirectUri: 'mobile-banking://callback',
      scopes: 'account:read transaction:read'
    };

    const oauth = new PKCEOAuthFlow(config);
    await oauth.initiateAuth();
  };

  useEffect(() => {
    // Handle redirect from banking OAuth
    if (window.location.href.startsWith('mobile-banking://callback')) {
      const oauth = new PKCEOAuthFlow(config);
      oauth.handleCallback().then(tokens => {
        // Store tokens securely (consider using Keychain on iOS, Keystore on Android)
        secureStoreTokens(tokens);
      });
    }
  }, []);

  return (
    <View>
      <Button title="Connect Bank Account" onPress={initiateOAuth} />
    </View>
  );
};
```