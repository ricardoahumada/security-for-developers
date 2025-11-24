# SSO Architecture Examples

## Overview

This file contains comprehensive SSO architecture patterns, configurations, and implementation examples. These examples complement Topic 2 of the Security Fundamentals module.

## Example 1: Centralized SSO Hub Architecture

### Architecture Components

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import datetime, timedelta, timezone
import json

@dataclass
class User:
    id: str
    email: str
    roles: List[str]
    attributes: Dict[str, any]
    created_at: datetime

@dataclass
class Application:
    id: str
    name: str
    sso_enabled: bool
    allowed_domains: List[str]
    required_attributes: List[str]

@dataclass
class Session:
    id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    applications: List[str]

class SSOIdentityProvider:
    """Central SSO Identity Provider"""
    
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.applications: Dict[str, Application] = {}
        self.sessions: Dict[str, Session] = {}
        self.federation_partners: Dict[str, dict] = {}
    
    def register_application(self, app: Application):
        """Register a new application with the SSO"""
        self.applications[app.id] = app
        print(f"Application '{app.name}' registered with SSO")
    
    def authenticate_user(self, email: str, password: str, 
                         application_id: str) -> Optional[str]:
        """Authenticate user and create SSO session"""
        
        # Find user (simplified - in production, verify password hash)
        user = next((u for u in self.users.values() if u.email == email), None)
        if not user:
            return None
        
        # Check if application allows this domain
        app = self.applications.get(application_id)
        if not app or not app.sso_enabled:
            return None
        
        user_domain = email.split('@')[1]
        if user_domain not in app.allowed_domains:
            return None
        
        # Create SSO session
        session_id = self._create_session(user.id, application_id)
        return session_id
    
    def _create_session(self, user_id: str, application_id: str) -> str:
        """Create SSO session"""
        session_id = f"sso_session_{user_id}_{datetime.now(timezone.utc).timestamp()}"
        
        session = Session(
            id=session_id,
            user_id=user_id,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
            applications=[application_id]
        )
        
        self.sessions[session_id] = session
        return session_id
    
    def validate_session(self, session_id: str, application_id: str) -> Optional[User]:
        """Validate SSO session for application access"""
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        # Check session expiry
        if datetime.now(timezone.utc) > session.expires_at:
            del self.sessions[session_id]
            return None
        
        # Check if application is authorized
        if application_id not in session.applications:
            return None
        
        # Return user with filtered attributes
        user = self.users[session.user_id]
        app = self.applications[application_id]
        
        filtered_attributes = {
            key: value for key, value in user.attributes.items()
            if key in app.required_attributes
        }
        
        return User(
            id=user.id,
            email=user.email,
            roles=user.roles,
            attributes=filtered_attributes,
            created_at=user.created_at
        )

class ServiceProvider(ABC):
    """Abstract Service Provider"""
    
    def __init__(self, app_id: str, app_name: str, sso_provider: SSOIdentityProvider):
        self.app_id = app_id
        self.app_name = app_name
        self.sso_provider = sso_provider
    
    @abstractmethod
    def handle_sso_login(self, session_id: str):
        pass
    
    def send_sso_request(self, email: str) -> str:
        """Send SSO authentication request"""
        return f"SAMLRequest for {email} to {self.app_name}"

class SalesforceSP(ServiceProvider):
    """Salesforce as Service Provider"""
    
    def __init__(self, sso_provider: SSOIdentityProvider):
        app = Application(
            id="salesforce",
            name="Salesforce CRM",
            sso_enabled=True,
            allowed_domains=["company.com", "partners.company.com"],
            required_attributes=["email", "first_name", "last_name", "role"]
        )
        super().__init__(app.id, app.name, sso_provider)
        sso_provider.register_application(app)
    
    def handle_sso_login(self, session_id: str):
        user = self.sso_provider.validate_session(session_id, self.app_id)
        if user:
            print(f"✅ User {user.email} logged into {self.app_name}")
            print(f"   Attributes: {user.attributes}")
            return True
        else:
            print(f"❌ SSO validation failed for {self.app_name}")
            return False

class SlackSP(ServiceProvider):
    """Slack as Service Provider"""
    
    def __init__(self, sso_provider: SSOIdentityProvider):
        app = Application(
            id="slack",
            name="Slack",
            sso_enabled=True,
            allowed_domains=["company.com"],
            required_attributes=["email", "first_name", "last_name", "department"]
        )
        super().__init__(app.id, app.name, sso_provider)
        sso_provider.register_application(app)
    
    def handle_sso_login(self, session_id: str):
        user = self.sso_provider.validate_session(session_id, self.app_id)
        if user:
            print(f"✅ User {user.email} logged into {self.app_name}")
            print(f"   Attributes: {user.attributes}")
            return True
        else:
            print(f"❌ SSO validation failed for {self.app_name}")
            return False

# Usage Example
def demonstrate_centralized_sso():
    print("=== Centralized SSO Hub Architecture Demo ===\n")
    
    # Initialize SSO
    sso_provider = SSOIdentityProvider()
    
    # Register users
    users = [
        User("1", "john@company.com", ["manager"], {
            "first_name": "John", "last_name": "Doe", 
            "department": "Sales", "role": "manager"
        }, datetime.now(timezone.utc)),
        User("2", "jane@partners.company.com", ["analyst"], {
            "first_name": "Jane", "last_name": "Smith",
            "department": "Analytics", "role": "analyst"
        }, datetime.now(timezone.utc))
    ]
    
    for user in users:
        sso_provider.users[user.id] = user
    
    # Initialize service providers
    salesforce = SalesforceSP(sso_provider)
    slack = SlackSP(sso_provider)
    
    # User authentication flow
    print("1. User john@company.com authenticates with SSO")
    session_id = sso_provider.authenticate_user("john@company.com", "password", "salesforce")
    
    if session_id:
        print(f"   SSO Session created: {session_id[:20]}...")
        
        # Access Salesforce
        print("\n2. User accesses Salesforce")
        salesforce.handle_sso_login(session_id)
        
        # Access Slack (same session)
        print("\n3. User accesses Slack (same session)")
        slack.handle_sso_login(session_id)
        
        # Partner user tries to access Slack
        print("\n4. Partner user tries to access Slack")
        session_id_2 = sso_provider.authenticate_user("jane@partners.company.com", "password", "salesforce")
        if session_id_2:
            salesforce.handle_sso_login(session_id_2)
        else:
            print("   ❌ Partner user not allowed in Salesforce")
    
    print("\n=== Benefits Demonstrated ===")
    print("✓ Single authentication for multiple applications")
    print("✓ Centralized user management")
    print("✓ Domain-based access control")
    print("✓ Attribute filtering per application")

demonstrate_centralized_sso()
```

## Example 2: Federated SSO with Partner Organizations

```python
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
import hashlib
import time
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass

@dataclass
class User:
    id: str
    email: str
    roles: List[str]
    attributes: Dict[str, any]
    created_at: datetime

class FederationPartner:
    """Represents a partner organization in federation"""
    
    def __init__(self, partner_id: str, name: str, entity_id: str, 
                 certificate: str, endpoints: Dict[str, str]):
        self.partner_id = partner_id
        self.name = name
        self.entity_id = entity_id
        self.certificate = certificate
        self.endpoints = endpoints

class FederatedSSO:
    """Federated SSO implementation for partner organizations"""
    
    def __init__(self):
        self.local_users: Dict[str, User] = {}
        self.partners: Dict[str, FederationPartner] = {}
        self.trust_relationships: Dict[str, Dict[str, str]] = {}
    
    def establish_federation_trust(self, partner: FederationPartner, 
                                 our_entity_id: str, our_cert: str):
        """Establish federation trust with partner"""
        self.partners[partner.partner_id] = partner
        
        # Create trust relationship
        self.trust_relationships[partner.partner_id] = {
            'our_entity_id': our_entity_id,
            'their_entity_id': partner.entity_id,
            'our_cert': our_cert,
            'their_cert': partner.certificate,
            'established': datetime.now(timezone.utc)
        }
        
        print(f"✅ Federation trust established with {partner.name}")
    
    def create_saml_assertion(self, user: User, audience: str, 
                            issuer: str) -> str:
        """Create SAML assertion for partner organization"""
        
        # Create SAML assertion XML (simplified)
        assertion = ET.Element("saml:Assertion")
        assertion.set("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
        assertion.set("ID", f"_{hashlib.md5(user.id.encode()).hexdigest()}")
        assertion.set("IssueInstant", datetime.now(timezone.utc).isoformat())
        
        # Issuer
        issuer_elem = ET.SubElement(assertion, "saml:Issuer")
        issuer_elem.text = issuer
        
        # Subject
        subject = ET.SubElement(assertion, "saml:Subject")
        name_id = ET.SubElement(subject, "saml:NameID")
        name_id.text = user.email
        name_id.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        
        # Conditions
        conditions = ET.SubElement(assertion, "saml:Conditions")
        conditions.set("NotBefore", datetime.now(timezone.utc).isoformat())
        conditions.set("NotOnOrAfter", (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
        
        audience_restriction = ET.SubElement(conditions, "saml:AudienceRestriction")
        audience_elem = ET.SubElement(audience_restriction, "saml:Audience")
        audience_elem.text = audience
        
        # Attributes
        attribute_statement = ET.SubElement(assertion, "saml:AttributeStatement")
        
        # Map user attributes to SAML attributes
        saml_attributes = {
            "email": user.email,
            "firstName": user.attributes.get("first_name", ""),
            "lastName": user.attributes.get("last_name", ""),
            "department": user.attributes.get("department", ""),
            "roles": ",".join(user.roles)
        }
        
        for attr_name, attr_value in saml_attributes.items():
            attribute = ET.SubElement(attribute_statement, "saml:Attribute")
            attribute.set("Name", f"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/{attr_name}")
            attribute.set("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
            
            attribute_value = ET.SubElement(attribute, "saml:AttributeValue")
            attribute_value.text = str(attr_value)
        
        # Convert to string
        return ET.tostring(assertion, encoding='unicode')
    
    def validate_federated_user(self, saml_assertion: str, 
                               partner_id: str) -> Optional[User]:
        """Validate SAML assertion from federated partner"""
        
        # In production, this would:
        # 1. Validate XML signature
        # 2. Check certificate
        # 3. Verify audience and issuer
        # 4. Check time conditions
        
        try:
            root = ET.fromstring(saml_assertion)
            
            # Extract NameID
            name_id_elem = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID")
            if name_id_elem is None:
                return None
            
            email = name_id_elem.text
            
            # Extract attributes
            attributes = {}
            for attr_elem in root.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"):
                attr_name = attr_elem.get("Name")
                attr_value_elem = attr_elem.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
                if attr_value_elem is not None:
                    attributes[attr_name] = attr_value_elem.text
            
            # Create or find user
            user_id = f"fed_{partner_id}_{hashlib.md5(email.encode()).hexdigest()[:8]}"
            
            user = User(
                id=user_id,
                email=email,
                roles=["federated_user"],  # Default role for federated users
                attributes=attributes,
                created_at=datetime.now(timezone.utc)
            )
            
            self.local_users[user_id] = user
            return user
            
        except ET.ParseError:
            return None
    
    def initiate_federated_sso(self, user_email: str, partner_id: str) -> str:
        """Initiate SSO to federated partner"""
        
        partner = self.partners.get(partner_id)
        if not partner:
            raise ValueError(f"Partner {partner_id} not found")
        
        user = next((u for u in self.local_users.values() if u.email == user_email), None)
        if not user:
            raise ValueError(f"User {user_email} not found")
        
        # Create SAML assertion
        saml_assertion = self.create_saml_assertion(
            user, partner.entity_id, "https://our-sso.company.com"
        )
        
        return saml_assertion

# Usage Example
def demonstrate_federated_sso():
    print("\n=== Federated SSO Architecture Demo ===\n")
    
    # Initialize federated SSO
    federated_sso = FederatedSSO()
    
    # Add local user
    local_user = User("local1", "alice@company.com", ["employee"], {
        "first_name": "Alice", "last_name": "Johnson",
        "department": "Engineering"
    }, datetime.now(timezone.utc))
    federated_sso.local_users[local_user.id] = local_user
    
    # Establish federation with partner company
    partner_cert = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
    partner = FederationPartner(
        partner_id="partner_acme",
        name="Acme Corporation",
        entity_id="https://idp.acme.com",
        certificate=partner_cert,
        endpoints={
            "sso": "https://idp.acme.com/sso",
            "slo": "https://idp.acme.com/slo"
        }
    )
    
    our_cert = "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
    federated_sso.establish_federation_trust(
        partner, "https://our-sso.company.com", our_cert
    )
    
    # Initiate federated SSO
    print("1. User alice@company.com initiates SSO to Acme Corporation")
    saml_assertion = federated_sso.initiate_federated_sso(
        "alice@company.com", "partner_acme"
    )
    print(f"   SAML Assertion created (truncated):")
    print(f"   {saml_assertion[:200]}...")
    
    # Partner validates and creates user
    print("\n2. Acme Corporation validates SAML assertion")
    validated_user = federated_sso.validate_federated_user(
        saml_assertion, "partner_acme"
    )
    
    if validated_user:
        print(f"   ✅ Federated user created: {validated_user.email}")
        print(f"   User ID: {validated_user.id}")
        print(f"   Attributes: {validated_user.attributes}")
    
    print("\n=== Federation Benefits Demonstrated ===")
    print("✓ Cross-organization SSO")
    print("✓ Trust relationships between organizations")
    print("✓ Attribute exchange between systems")
    print("✓ Seamless partner access")

demonstrate_federated_sso()
```

## Example 3: Cloud-First SSO Implementation

```python
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta, timezone

class CloudProvider(Enum):
    AZURE_AD = "azure_ad"
    OKTA = "okta"
    AUTH0 = "auth0"
    GOOGLE_WORKSPACE = "google_workspace"

@dataclass
class CloudSSOConfig:
    provider: CloudProvider
    tenant_id: str
    client_id: str
    client_secret: str
    domain: str
    metadata_url: str

class CloudSSOAdapter:
    """Adapter for cloud SSO providers"""
    
    def __init__(self, config: CloudSSOConfig):
        self.config = config
        self.provider_handlers = {
            CloudProvider.AZURE_AD: self._handle_azure_ad,
            CloudProvider.OKTA: self._handle_okta,
            CloudProvider.AUTH0: self._handle_auth0,
            CloudProvider.GOOGLE_WORKSPACE: self._handle_google_workspace
        }
    
    def authenticate_user(self, token: str) -> Optional[Dict[str, Any]]:
        """Authenticate user using cloud SSO provider"""
        handler = self.provider_handlers.get(self.config.provider)
        if not handler:
            return None
        
        return handler(token)
    
    def _handle_azure_ad(self, token: str) -> Dict[str, Any]:
        """Handle Azure AD authentication"""
        # Simulate Azure AD token validation
        if token.startswith("eyJ"):
            return {
                "sub": "user123",
                "name": "John Doe",
                "preferred_username": "john@company.onmicrosoft.com",
                "roles": ["User", "GroupMember"],
                "tid": self.config.tenant_id,
                "email": "john@company.com",
                "groups": ["Engineering", "Developers"],
                "scp": "User.Read"
            }
        return None
    
    def _handle_okta(self, token: str) -> Dict[str, Any]:
        """Handle Okta authentication"""
        # Simulate Okta token validation
        if token.startswith("okta_"):
            return {
                "sub": "user123",
                "email": "john@company.com",
                "given_name": "John",
                "family_name": "Doe",
                "groups": ["Employees", "Engineering"],
                "org_id": self.config.tenant_id
            }
        return None
    
    def _handle_auth0(self, token: str) -> Dict[str, Any]:
        """Handle Auth0 authentication"""
        # Simulate Auth0 token validation
        if token.startswith("eyJ"):
            return {
                "sub": "auth0|user123",
                "email": "john@company.com",
                "name": "John Doe",
                "https://company.com/roles": ["employee"],
                "https://company.com/permissions": ["read:data", "write:data"],
                "azp": self.config.client_id
            }
        return None
    
    def _handle_google_workspace(self, token: str) -> Dict[str, Any]:
        """Handle Google Workspace authentication"""
        # Simulate Google Workspace token validation
        if token.startswith("ya29."):
            return {
                "sub": "user123",
                "email": "john@company.com",
                "email_verified": True,
                "given_name": "John",
                "family_name": "Doe",
                "hd": "company.com",
                "picture": "https://example.com/photo.jpg"
            }
        return None

class CloudFirstSSOOrchestrator:
    """Orchestrator for cloud-first SSO architecture"""
    
    def __init__(self):
        self.adapters: Dict[str, CloudSSOAdapter] = {}
        self.applications: Dict[str, Dict[str, Any]] = {}
        self.user_sessions: Dict[str, Dict[str, Any]] = {}
    
    def register_cloud_provider(self, provider_name: str, config: CloudSSOConfig):
        """Register cloud SSO provider adapter"""
        self.adapters[provider_name] = CloudSSOAdapter(config)
        print(f"✅ Registered {config.provider.value} as SSO provider: {provider_name}")
    
    def register_application(self, app_id: str, allowed_providers: List[str]):
        """Register application with allowed SSO providers"""
        self.applications[app_id] = {
            "allowed_providers": allowed_providers,
            "mappings": {}  # Provider-specific attribute mappings
        }
        print(f"✅ Registered application: {app_id}")
    
    def authenticate_to_application(self, application_id: str, 
                                  provider_name: str, token: str) -> Optional[Dict[str, Any]]:
        """Authenticate user to application using cloud SSO"""
        
        app = self.applications.get(application_id)
        if not app:
            return None
        
        if provider_name not in app["allowed_providers"]:
            return None
        
        adapter = self.adapters.get(provider_name)
        if not adapter:
            return None
        
        # Authenticate with cloud provider
        user_info = adapter.authenticate_user(token)
        if not user_info:
            return None
        
        # Map provider-specific attributes to application requirements
        mapped_user = self._map_user_attributes(user_info, provider_name, application_id)
        
        return mapped_user
    
    def _map_user_attributes(self, user_info: Dict[str, Any], 
                           provider_name: str, app_id: str) -> Dict[str, Any]:
        """Map provider-specific user attributes to application format"""
        
        # Define attribute mappings for each provider
        mappings = {
            "azure_ad": {
                "sub": "user_id",
                "email": "email",
                "given_name": "first_name",
                "family_name": "last_name",
                "groups": "roles"
            },
            "okta": {
                "sub": "user_id",
                "email": "email",
                "given_name": "first_name",
                "family_name": "last_name",
                "groups": "roles"
            },
            "auth0": {
                "sub": "user_id",
                "email": "email",
                "name": "full_name",
                "https://company.com/roles": "roles"
            },
            "google_workspace": {
                "sub": "user_id",
                "email": "email",
                "given_name": "first_name",
                "family_name": "last_name"
            }
        }
        
        provider_mappings = mappings.get(provider_name, {})
        mapped_user = {}
        
        for provider_attr, app_attr in provider_mappings.items():
            if provider_attr in user_info:
                mapped_user[app_attr] = user_info[provider_attr]
        
        # Add provider and authentication info
        mapped_user.update({
            "provider": provider_name,
            "provider_user_id": user_info.get("sub"),
            "authenticated_at": datetime.now(timezone.utc),
            "permissions": self._extract_permissions(user_info, provider_name)
        })
        
        return mapped_user
    
    def _extract_permissions(self, user_info: Dict[str, Any], provider_name: str) -> List[str]:
        """Extract permissions based on provider and user attributes"""
        permissions = []
        
        if provider_name == "azure_ad":
            if "groups" in user_info:
                permissions.extend(user_info["groups"])
        elif provider_name == "okta":
            if "groups" in user_info:
                permissions.extend(user_info["groups"])
        elif provider_name == "auth0":
            perms_key = "https://company.com/permissions"
            if perms_key in user_info:
                permissions.extend(user_info[perms_key])
        
        return permissions

# Usage Example
def demonstrate_cloud_first_sso():
    print("\n=== Cloud-First SSO Architecture Demo ===\n")
    
    # Initialize orchestrator
    orchestrator = CloudFirstSSOOrchestrator()
    
    # Register cloud providers
    azure_config = CloudSSOConfig(
        provider=CloudProvider.AZURE_AD,
        tenant_id="your-tenant-id",
        client_id="your-client-id",
        client_secret="your-client-secret",
        domain="company.onmicrosoft.com",
        metadata_url="https://login.microsoftonline.com/tenant-id/federationmetadata/2007-06/federationmetadata.xml?app-id=client-id"
    )
    
    okta_config = CloudSSOConfig(
        provider=CloudProvider.OKTA,
        tenant_id="okta-domain",
        client_id="okta-client-id",
        client_secret="okta-client-secret",
        domain="company.okta.com",
        metadata_url="https://company.okta.com/metadata"
    )
    
    orchestrator.register_cloud_provider("azure_main", azure_config)
    orchestrator.register_cloud_provider("okta_backup", okta_config)
    
    # Register applications
    orchestrator.register_application("app1", ["azure_main", "okta_backup"])
    orchestrator.register_application("app2", ["azure_main"])
    
    # Simulate user authentication flows
    print("\n1. User authenticates to App1 using Azure AD")
    azure_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."
    user = orchestrator.authenticate_to_application("app1", "azure_main", azure_token)
    
    if user:
        print(f"   ✅ Authentication successful")
        print(f"   User: {user.get('email')}")
        print(f"   Roles: {user.get('roles')}")
        print(f"   Provider: {user.get('provider')}")
    
    print("\n2. Same user accesses App1 (token validation)")
    user2 = orchestrator.authenticate_to_application("app1", "azure_main", azure_token)
    if user2:
        print(f"   ✅ Seamless access to App1")
    
    print("\n3. User tries to access App2 (allowed)")
    user3 = orchestrator.authenticate_to_application("app2", "azure_main", azure_token)
    if user3:
        print(f"   ✅ Access granted to App2")
    
    print("\n4. User tries to access App2 with wrong provider")
    okta_token = "okta_token_example"
    user4 = orchestrator.authenticate_to_application("app2", "okta_backup", okta_token)
    if user4:
        print(f"   ✅ Cross-provider authentication works")
    else:
        print(f"   ❌ Provider not allowed for this application")
    
    print("\n=== Cloud-First Benefits Demonstrated ===")
    print("✓ Multiple cloud provider support")
    print("✓ Application-specific provider configuration")
    print("✓ Attribute mapping and normalization")
    print("✓ Permission extraction and management")
    print("✓ Provider failover and redundancy")

demonstrate_cloud_first_sso()
```

## Example 4: SSO Configuration Management

```yaml
# SSO Configuration Example (config/sso_config.yaml)
identity_providers:
  primary_azure_ad:
    type: azure_ad
    tenant_id: "12345678-1234-1234-1234-123456789012"
    client_id: "app-client-id"
    client_secret: "${AZURE_CLIENT_SECRET}"
    domain: "company.onmicrosoft.com"
    metadata_url: "https://login.microsoftonline.com/tenant-id/federationmetadata/2007-06/federationmetadata.xml"
    
    attribute_mapping:
      email: "user.mail"
      first_name: "user.givenname"
      last_name: "user.surname"
      roles: "user.groups"
      department: "user.department"
    
    authentication_policies:
      require_mfa: true
      allowed_locations: ["US", "CA"]
      session_timeout: 28800  # 8 hours
  
  backup_okta:
    type: okta
    domain: "company.okta.com"
    client_id: "okta-client-id"
    client_secret: "${OKTA_CLIENT_SECRET}"
    
    attribute_mapping:
      email: "email"
      first_name: "firstName"
      last_name: "lastName"
      roles: "groups"
    
    authentication_policies:
      require_mfa: true
      session_timeout: 14400  # 4 hours

service_providers:
  salesforce:
    entity_id: "https://company.my.salesforce.com"
    assertion_consumer_service_url: "https://company.my.salesforce.com"
    name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    encrypted_assertion: true
    required_attributes:
      - email
      - first_name
      - last_name
      - roles
    
  slack:
    entity_id: "https://slack.com"
    assertion_consumer_service_url: "https://company.slack.com/sso/saml"
    name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    required_attributes:
      - email
      - first_name
      - last_name
      - department

federation_partners:
  acme_corp:
    entity_id: "https://idp.acme.com"
    certificate: "${ACME_CERTIFICATE}"
    metadata_url: "https://idp.acme.com/metadata"
    attribute_mapping:
      email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
      first_name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
      last_name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
    
    trust_policy:
      lifetime_hours: 1
      require_signed_assertions: true
      allowed_audiences:
        - "https://our-sso.company.com"

security_settings:
  certificate_validation: true
  signature_algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  encryption_algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
  
  session_management:
    default_timeout: 28800
    sliding_expiration: true
    concurrent_sessions: 5
    
  monitoring:
    enable_audit_logging: true
    failed_login_threshold: 5
    anomaly_detection: true
    alert_on_unusual_activity: true
```

## Example 5: SSO Migration Strategy

```python
from enum import Enum
from typing import List, Dict, Set
import time
from datetime import datetime, timezone

class MigrationPhase(Enum):
    ASSESSMENT = "assessment"
    PILOT = "pilot"
    ROLLOUT = "rollout"
    OPTIMIZATION = "optimization"

class SSOMigrationPlanner:
    """SSO Migration Strategy Planner"""
    
    def __init__(self):
        self.legacy_apps: Dict[str, Dict] = {}
        self.target_state: Dict[str, Dict] = {}
        self.migration_plan: List[Dict] = []
        self.dependencies: Dict[str, Set[str]] = {}
        self.risk_assessments: Dict[str, Dict] = {}
    
    def add_legacy_application(self, app_id: str, app_info: Dict):
        """Add legacy application to migration scope"""
        self.legacy_apps[app_id] = {
            "name": app_info.get("name"),
            "users": app_info.get("user_count", 0),
            "criticality": app_info.get("criticality", "medium"),
            "technology": app_info.get("tech_stack", "unknown"),
            "authentication_method": app_info.get("auth_method", "local"),
            "sso_readiness": app_info.get("sso_readiness", "low"),
            "integration_complexity": app_info.get("complexity", "medium")
        }
        
        # Auto-calculate migration priority
        priority = self._calculate_migration_priority(app_id)
        self.legacy_apps[app_id]["migration_priority"] = priority
    
    def _calculate_migration_priority(self, app_id: str) -> str:
        """Calculate migration priority based on various factors"""
        app = self.legacy_apps[app_id]
        score = 0
        
        # User count factor
        if app["users"] > 10000:
            score += 3
        elif app["users"] > 1000:
            score += 2
        else:
            score += 1
        
        # Criticality factor
        criticality_scores = {"high": 3, "medium": 2, "low": 1}
        score += criticality_scores.get(app["criticality"], 2)
        
        # SSO readiness factor
        readiness_scores = {"high": 3, "medium": 2, "low": 1}
        score += readiness_scores.get(app["sso_readiness"], 1)
        
        # Technology factor
        if app["technology"] in ["modern_web", "cloud_native"]:
            score += 2
        elif app["technology"] == "enterprise_software":
            score += 1
        else:
            score += 0
        
        if score >= 8:
            return "high"
        elif score >= 5:
            return "medium"
        else:
            return "low"
    
    def define_migration_phases(self):
        """Define migration phases based on application assessment"""
        
        # Phase 1: High priority, low complexity applications
        phase1_apps = [
            app_id for app_id, app in self.legacy_apps.items()
            if app["migration_priority"] == "high" and 
               app["integration_complexity"] in ["low", "medium"]
        ]
        
        # Phase 2: Medium priority applications
        phase2_apps = [
            app_id for app_id, app in self.legacy_apps.items()
            if app["migration_priority"] == "medium"
        ]
        
        # Phase 3: Low priority or high complexity applications
        phase3_apps = [
            app_id for app_id, app in self.legacy_apps.items()
            if app["migration_priority"] == "low" or 
               app["integration_complexity"] == "high"
        ]
        
        self.migration_plan = [
            {
                "phase": "Phase 1 - Quick Wins",
                "duration_weeks": 8,
                "applications": phase1_apps,
                "objectives": "Demonstrate SSO value with low-risk applications",
                "success_criteria": [
                    "User satisfaction > 90%",
                    "Support ticket reduction > 50%",
                    "Zero security incidents"
                ]
            },
            {
                "phase": "Phase 2 - Core Systems",
                "duration_weeks": 12,
                "applications": phase2_apps,
                "objectives": "Migrate core business applications",
                "success_criteria": [
                    "All core applications SSO-enabled",
                    "User adoption > 85%",
                    "Successful security audit"
                ]
            },
            {
                "phase": "Phase 3 - Remaining Systems",
                "duration_weeks": 16,
                "applications": phase3_apps,
                "objectives": "Complete migration of legacy systems",
                "success_criteria": [
                    "100% application coverage",
                    "Legacy auth deprecation",
                    "Full monitoring and reporting"
                ]
            }
        ]
    
    def assess_migration_risks(self):
        """Assess risks for each application migration"""
        for app_id, app in self.legacy_apps.items():
            risks = []
            mitigation_strategies = []
            
            # Technical risks
            if app["technology"] == "legacy":
                risks.append("Incompatible with modern SSO protocols")
                mitigation_strategies.append("Deploy SAML gateway or API adapter")
            
            if app["integration_complexity"] == "high":
                risks.append("Complex integration requirements")
                mitigation_strategies.append("Engage specialized integration team")
            
            # Business risks
            if app["criticality"] == "high":
                risks.append("Business-critical system downtime")
                mitigation_strategies.append("Implement blue-green deployment")
            
            # User adoption risks
            if app["users"] > 5000:
                risks.append("Large user base training requirements")
                mitigation_strategies.append("Comprehensive change management program")
            
            self.risk_assessments[app_id] = {
                "risk_level": "high" if len(risks) >= 3 else "medium" if len(risks) >= 2 else "low",
                "risks": risks,
                "mitigation_strategies": mitigation_strategies,
                "estimated_effort": self._estimate_migration_effort(app),
                "rollback_plan": self._create_rollback_plan(app_id)
            }
    
    def _estimate_migration_effort(self, app: Dict) -> str:
        """Estimate migration effort based on application characteristics"""
        complexity_score = {
            "low": 1,
            "medium": 2,
            "high": 3
        }[app["integration_complexity"]]
        
        readiness_score = {
            "high": 1,
            "medium": 2,
            "low": 3
        }[app["sso_readiness"]]
        
        total_score = complexity_score + readiness_score
        
        if total_score <= 2:
            return "Low effort (1-2 weeks)"
        elif total_score <= 4:
            return "Medium effort (3-6 weeks)"
        else:
            return "High effort (6+ weeks)"
    
    def _create_rollback_plan(self, app_id: str) -> Dict:
        """Create rollback plan for application"""
        return {
            "triggers": [
                "Security incident",
                "User adoption < 70%",
                "Critical functionality failure"
            ],
            "rollback_procedure": [
                "Notify all users of rollback",
                "Restore previous authentication system",
                "Validate all functionality",
                "Document lessons learned"
            ],
            "estimated_downtime": "1-2 hours",
            "communication_plan": "Email to users + status page updates"
        }
    
    def generate_migration_report(self) -> str:
        """Generate comprehensive migration report"""
        report = []
        report.append("# SSO Migration Strategy Report")
        report.append(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
        
        # Executive Summary
        total_apps = len(self.legacy_apps)
        total_users = sum(app["users"] for app in self.legacy_apps.values())
        
        report.append("## Executive Summary")
        report.append(f"- Total applications: {total_apps}")
        report.append(f"- Total users affected: {total_users:,}")
        report.append(f"- Estimated timeline: {sum(phase['duration_weeks'] for phase in self.migration_plan)} weeks")
        report.append("")
        
        # Application Assessment
        report.append("## Application Assessment")
        for app_id, app in self.legacy_apps.items():
            report.append(f"### {app['name']} ({app_id})")
            report.append(f"- Users: {app['users']:,}")
            report.append(f"- Technology: {app['technology']}")
            report.append(f"- Migration Priority: {app['migration_priority']}")
            report.append(f"- Estimated Effort: {self.risk_assessments[app_id]['estimated_effort']}")
            report.append(f"- Risk Level: {self.risk_assessments[app_id]['risk_level']}")
            report.append("")
        
        # Migration Phases
        report.append("## Migration Plan")
        for phase in self.migration_plan:
            report.append(f"### {phase['phase']}")
            report.append(f"Duration: {phase['duration_weeks']} weeks")
            report.append(f"Applications: {', '.join(phase['applications'])}")
            report.append(f"Objectives: {phase['objectives']}")
            report.append("Success Criteria:")
            for criteria in phase['success_criteria']:
                report.append(f"  - {criteria}")
            report.append("")
        
        return "\n".join(report)

# Usage Example
def demonstrate_migration_planning():
    print("\n=== SSO Migration Strategy Demo ===\n")
    
    planner = SSOMigrationPlanner()
    
    # Add legacy applications
    apps = [
        {
            "name": "Legacy CRM",
            "user_count": 15000,
            "criticality": "high",
            "tech_stack": "legacy_java",
            "auth_method": "custom",
            "sso_readiness": "low",
            "complexity": "high"
        },
        {
            "name": "Employee Portal",
            "user_count": 8000,
            "criticality": "high",
            "tech_stack": "modern_web",
            "auth_method": "ldap",
            "sso_readiness": "high",
            "complexity": "low"
        },
        {
            "name": "Project Management Tool",
            "user_count": 3000,
            "criticality": "medium",
            "tech_stack": "cloud_saas",
            "auth_method": "local",
            "sso_readiness": "medium",
            "complexity": "medium"
        }
    ]
    
    for i, app in enumerate(apps, 1):
        planner.add_legacy_application(f"app_{i}", app)
    
    # Plan migration
    planner.define_migration_phases()
    planner.assess_migration_risks()
    
    # Generate report
    report = planner.generate_migration_report()
    print(report)
    
    print("\n=== Migration Strategy Benefits ===")
    print("✓ Risk-based prioritization")
    print("✓ Phased rollout approach")
    print("✓ Comprehensive rollback planning")
    print("✓ Success metrics and monitoring")

demonstrate_migration_planning()
```

## Key Takeaways

1. **Centralized SSO Hub**: Single point of authentication for multiple applications
2. **Federated SSO**: Cross-organization trust relationships and attribute exchange
3. **Cloud-First Architecture**: Leveraging cloud providers for SSO infrastructure
4. **Configuration Management**: Centralized configuration for SSO providers and applications
5. **Migration Strategy**: Risk-based phased migration approach

## Best Practices for SSO Implementation

1. **Start Small**: Begin with low-risk applications to prove concept
2. **Monitor Everything**: Comprehensive logging and monitoring from day one
3. **Plan for Failures**: Robust fallback mechanisms and rollback procedures
4. **User Communication**: Clear communication about changes and benefits
5. **Continuous Improvement**: Regular assessment and optimization of SSO performance

---

**Note**: This code is for educational purposes. In production, additional security measures, error handling, and compliance considerations should be implemented.
