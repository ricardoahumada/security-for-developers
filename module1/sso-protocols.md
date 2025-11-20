# SSO Protocol Standards

## SAML (Security Assertion Markup Language)

**Overview**: XML-based protocol for enterprise SSO
**Best for**: Traditional enterprise applications, B2B integrations
**Advantages**: Mature, widely adopted in enterprises, complex rule support
**Disadvantages**: Complex implementation, XML parsing overhead

**SAML Assertion Example**:
```xml
<saml:Assertion ID="12345" Version="2.0" IssueInstant="2023-11-03T16:00:31Z">
    <saml:Issuer>https://company-idp.com</saml:Issuer>
    <saml:Subject>
        <saml:NameID>john.doe@company.com</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData Recipient="https://app.company.com" 
                                         NotOnOrAfter="2023-11-03T16:30:31Z"/>
        </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:AttributeStatement>
        <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue>john.doe@company.com</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="groups" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue>developers</saml:AttributeValue>
            <saml:AttributeValue>senior-level</saml:AttributeValue>
        </saml:Attribute>
    </saml:AttributeStatement>
</saml:Assertion>
```

## OpenID Connect (OIDC)

**Overview**: Modern authentication layer built on top of OAuth 2.0
**Best for**: Modern web applications, mobile apps, API authentication
**Advantages**: JSON-based, RESTful APIs, mobile-friendly, smaller tokens
**Disadvantages**: Newer standard, may lack enterprise features

**OIDC Token Example**:
```json
{
  "iss": "https://accounts.google.com",
  "sub": "10769150350006150715113082367",
  "aud": "my-app.apps.googleusercontent.com",
  "email": "john.doe@company.com",
  "email_verified": true,
  "name": "John Doe",
  "picture": "https://lh5.googleusercontent.com/-b0-k99i/AAAAAAAAAAI/AAAAAAAA/eu_cQ/photo.jpg",
  "given_name": "John",
  "family_name": "Doe",
  "locale": "en",
  "iat": 1353601026,
  "exp": 1353604926
}
```