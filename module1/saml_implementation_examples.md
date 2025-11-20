# SAML Implementation Examples

## Overview

This file contains comprehensive SAML implementation examples, XML configurations, and integration patterns. These examples complement Topic 4 of the Security Fundamentals module.

## Example 1: Basic SAML Assertion Creation

### SAML Assertion Generator

```python
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime, timedelta
import base64
import hashlib
import secrets
from typing import Dict, List, Optional

class SAMLAssertionBuilder:
    """Build SAML 2.0 assertions with proper XML structure"""
    
    SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
    DS_NS = "http://www.w3.org/2000/09/xmldsig#"
    ENCRYPTION_NS = "http://www.w3.org/2001/04/xmlenc#"
    
    def __init__(self, issuer_id: str, signing_key: str):
        self.issuer_id = issuer_id
        self.signing_key = signing_key
    
    def create_saml_assertion(self, user_id: str, email: str, 
                            attributes: Dict[str, str], 
                            audience: str,
                            session_not_on_or_after: datetime = None) -> str:
        """Create complete SAML assertion"""
        
        # Set default session timeout
        if not session_not_on_or_after:
            session_not_on_or_after = datetime.utcnow() + timedelta(hours=8)
        
        # Create assertion element
        assertion = ET.Element(f"{{{self.SAML_NS}}}Assertion")
        assertion.set("ID", f"_{secrets.token_hex(16)}")
        assertion.set("Version", "2.0")
        assertion.set("IssueInstant", datetime.utcnow().isoformat())
        
        # Add issuer
        issuer = ET.SubElement(assertion, f"{{{self.SAML_NS}}}Issuer")
        issuer.text = self.issuer_id
        
        # Add signature (simplified - in production use proper XML signing)
        signature = self._create_signature()
        assertion.append(signature)
        
        # Add subject
        subject = self._create_subject(email, audience, session_not_on_or_after)
        assertion.append(subject)
        
        # Add conditions
        conditions = self._create_conditions(audience, session_not_on_or_after)
        assertion.append(conditions)
        
        # Add attribute statement
        attribute_statement = self._create_attribute_statement(attributes)
        assertion.append(attribute_statement)
        
        # Convert to pretty XML string
        return self._format_xml(assertion)
    
    def _create_subject(self, email: str, recipient: str, 
                       not_on_or_after: datetime) -> ET.Element:
        """Create SAML subject element"""
        
        subject = ET.Element(f"{{{self.SAML_NS}}}Subject")
        
        # NameID
        name_id = ET.SubElement(subject, f"{{{self.SAML_NS}}}NameID")
        name_id.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        name_id.text = email
        
        # SubjectConfirmation
        subject_confirmation = ET.SubElement(subject, f"{{{self.SAML_NS}}}SubjectConfirmation")
        subject_confirmation.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
        
        subject_confirmation_data = ET.SubElement(
            subject_confirmation, 
            f"{{{self.SAML_NS}}}SubjectConfirmationData"
        )
        subject_confirmation_data.set("Recipient", recipient)
        subject_confirmation_data.set("NotOnOrAfter", not_on_or_after.isoformat())
        
        return subject
    
    def _create_conditions(self, audience: str, not_on_or_after: datetime) -> ET.Element:
        """Create SAML conditions element"""
        
        conditions = ET.Element(f"{{{self.SAML_NS}}}Conditions")
        conditions.set("NotBefore", datetime.utcnow().isoformat())
        conditions.set("NotOnOrAfter", not_on_or_after.isoformat())
        
        # Audience restriction
        audience_restriction = ET.SubElement(
            conditions, 
            f"{{{self.SAML_NS}}}AudienceRestriction"
        )
        
        audience_element = ET.SubElement(
            audience_restriction, 
            f"{{{self.SAML_NS}}}Audience"
        )
        audience_element.text = audience
        
        return conditions
    
    def _create_attribute_statement(self, attributes: Dict[str, str]) -> ET.Element:
        """Create SAML attribute statement"""
        
        attribute_statement = ET.SubElement(
            f"{{{self.SAML_NS}}}AttributeStatement"
        )
        
        for attr_name, attr_value in attributes.items():
            attribute = ET.SubElement(
                attribute_statement, 
                f"{{{self.SAML_NS}}}Attribute"
            )
            attribute.set("Name", attr_name)
            attribute.set("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
            
            attribute_value = ET.SubElement(
                attribute, 
                f"{{{self.SAML_NS}}}AttributeValue"
            )
            attribute_value.set("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
            attribute_value.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
            attribute_value.set("xsi:type", "xs:string")
            attribute_value.text = str(attr_value)
        
        return attribute_statement
    
    def _create_signature(self) -> ET.Element:
        """Create XML signature (simplified)"""
        
        signature = ET.Element(f"{{{self.DS_NS}}}Signature")
        
        signed_info = ET.SubElement(signature, f"{{{self.DS_NS}}}SignedInfo")
        
        canonicalization_method = ET.SubElement(
            signed_info, 
            f"{{{self.DS_NS}}}CanonicalizationMethod"
        )
        canonicalization_method.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
        
        signature_method = ET.SubElement(
            signed_info, 
            f"{{{self.DS_NS}}}SignatureMethod"
        )
        signature_method.set("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
        
        reference = ET.SubElement(signed_info, f"{{{self.DS_NS}}}Reference")
        reference.set("URI", "")
        
        transforms = ET.SubElement(reference, f"{{{self.DS_NS}}}Transforms")
        
        transform = ET.SubElement(transforms, f"{{{self.DS_NS}}}Transform")
        transform.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
        
        digest_method = ET.SubElement(reference, f"{{{self.DS_NS}}}DigestMethod")
        digest_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
        
        digest_value = ET.SubElement(reference, f"{{{self.DS_NS}}}DigestValue")
        digest_value.text = "placeholder"  # In production, calculate actual digest
        
        signature_value = ET.SubElement(signature, f"{{{self.DS_NS}}}SignatureValue")
        signature_value.text = "placeholder"  # In production, calculate actual signature
        
        return signature
    
    def _format_xml(self, element: ET.Element) -> str:
        """Format XML with proper indentation"""
        
        rough_string = ET.tostring(element, encoding='unicode')
        reparsed = minidom.parseString(rough_string)
        
        # Remove extra whitespace
        return reparsed.toprettyxml(indent="  ").split('\n', 1)[1]

class SAMLResponseBuilder:
    """Build SAML responses"""
    
    def __init__(self, assertion_builder: SAMLAssertionBuilder):
        self.assertion_builder = assertion_builder
    
    def create_saml_response(self, in_response_to: str, 
                           destination: str, 
                           user_id: str, 
                           email: str,
                           attributes: Dict[str, str],
                           status_code: str = "urn:oasis:names:tc:SAML:2.0:status:Success") -> str:
        """Create complete SAML response"""
        
        # Create response element
        response = ET.Element("samlp:Response")
        response.set("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
        response.set("ID", f"_{secrets.token_hex(16)}")
        response.set("Version", "2.0")
        response.set("IssueInstant", datetime.utcnow().isoformat())
        response.set("Destination", destination)
        response.set("InResponseTo", in_response_to)
        
        # Add issuer
        issuer = ET.SubElement(response, f"{{{self.assertion_builder.SAML_NS}}}Issuer")
        issuer.text = self.assertion_builder.issuer_id
        
        # Add status
        status = self._create_status(status_code)
        response.append(status)
        
        # Add assertion
        assertion = self.assertion_builder.create_saml_assertion(
            user_id, email, attributes, destination
        )
        
        # Parse assertion and append to response
        assertion_element = ET.fromstring(assertion)
        response.append(assertion_element)
        
        return self._format_xml(response)
    
    def _create_status(self, status_code: str) -> ET.Element:
        """Create SAML status element"""
        
        status = ET.SubElement("samlp:Status")
        
        status_code_element = ET.SubElement(status, "samlp:StatusCode")
        status_code_element.set("Value", status_code)
        
        return status

# Usage Example
def demonstrate_saml_assertion_creation():
    print("=== SAML Assertion Creation Demo ===\n")
    
    # Initialize SAML components
    issuer_id = "https://idp.company.com"
    signing_key = "saml_signing_key_2025"
    
    assertion_builder = SAMLAssertionBuilder(issuer_id, signing_key)
    response_builder = SAMLResponseBuilder(assertion_builder)
    
    # User attributes
    user_attributes = {
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "john@company.com",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": "John",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": "Doe",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Employee",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": "John Doe"
    }
    
    # Create SAML assertion
    print("1. Creating SAML assertion")
    assertion = assertion_builder.create_saml_assertion(
        user_id="user123",
        email="john@company.com",
        attributes=user_attributes,
        audience="https://sp.company.com"
    )
    
    print("SAML Assertion (truncated):")
    print(assertion[:300] + "...")
    
    # Create SAML response
    print("\n2. Creating SAML response")
    response = response_builder.create_saml_response(
        in_response_to="saml_request_id_123",
        destination="https://sp.company.com/saml/acs",
        user_id="user123",
        email="john@company.com",
        attributes=user_attributes
    )
    
    print("SAML Response (truncated):")
    print(response[:300] + "...")
    
    print("\n=== SAML Components Created ===")
    print("✓ SAML Assertion with proper structure")
    print("✓ XML signature placeholders")
    print("✓ Subject and conditions")
    print("✓ Attribute statements")
    print("✓ SAML response wrapper")

demonstrate_saml_assertion_creation()
```

## Example 2: SAML IdP Metadata Configuration

### Identity Provider Configuration

```python
from typing import Dict, List
import ssl
import urllib.request
from datetime import datetime

class SAMLIdentityProvider:
    """SAML Identity Provider implementation"""
    
    def __init__(self, entity_id: str, organization_info: Dict[str, str]):
        self.entity_id = entity_id
        self.organization_info = organization_info
        self.certificate = self._generate_certificate()
        self.services = {}
        self.contacts = []
    
    def _generate_certificate(self) -> str:
        """Generate X.509 certificate (simplified)"""
        # In production, use proper certificate generation
        return """-----BEGIN CERTIFICATE-----
MIICtTCCAZ0CAQAwDQYJKoZIhvcNAQEFBQAwEjEQMA4GA1UEAwwHdGVzdC1jYTAe
Fw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAwMDBaMBIxEDAOBgNVBAMMB3Rlc3Qt
Y2EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1...
-----END CERTIFICATE-----"""
    
    def add_single_sign_on_service(self, binding: str, location: str):
        """Add SSO service endpoint"""
        
        if 'sso' not in self.services:
            self.services['sso'] = []
        
        self.services['sso'].append({
            'binding': binding,
            'location': location,
            'index': len(self.services['sso']) + 1
        })
    
    def add_single_logout_service(self, binding: str, location: str):
        """Add SLO service endpoint"""
        
        if 'slo' not in self.services:
            self.services['slo'] = []
        
        self.services['slo'].append({
            'binding': binding,
            'location': location,
            'index': len(self.services['slo']) + 1
        })
    
    def add_attribute_service(self, binding: str, location: str):
        """Add attribute service endpoint"""
        
        if 'attribute' not in self.services:
            self.services['attribute'] = []
        
        self.services['attribute'].append({
            'binding': binding,
            'location': location,
            'index': len(self.services['attribute']) + 1
        })
    
    def add_contact(self, contact_type: str, given_name: str, 
                   email_address: str, telephone_number: str = None):
        """Add contact information"""
        
        self.contacts.append({
            'type': contact_type,
            'givenName': given_name,
            'emailAddress': email_address,
            'telephoneNumber': telephone_number
        })
    
    def generate_metadata(self) -> str:
        """Generate IdP metadata XML"""
        
        metadata = []
        metadata.append('<?xml version="1.0" encoding="UTF-8"?>')
        metadata.append(f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"')
        metadata.append(f'    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"')
        metadata.append(f'    entityID="{self.entity_id}"')
        metadata.append(f'    cacheDuration="PT604800S">')  # 7 days
        
        # Organization information
        metadata.append('  <md:Organization>')
        metadata.append(f'    <md:OrganizationName xml:lang="en">{self.organization_info["name"]}</md:OrganizationName>')
        metadata.append(f'    <md:OrganizationDisplayName xml:lang="en">{self.organization_info["display_name"]}</md:OrganizationDisplayName>')
        metadata.append(f'    <md:OrganizationURL xml:lang="en">{self.organization_info["url"]}</md:OrganizationURL>')
        metadata.append('  </md:Organization>')
        
        # Contact information
        for contact in self.contacts:
            metadata.append(f'  <md:ContactPerson contactType="{contact["type"]}">')
            metadata.append(f'    <md:GivenName>{contact["givenName"]}</md:GivenName>')
            metadata.append(f'    <md:EmailAddress>{contact["emailAddress"]}</md:EmailAddress>')
            if contact.get('telephoneNumber'):
                metadata.append(f'    <md:TelephoneNumber>{contact["telephoneNumber"]}</md:TelephoneNumber>')
            metadata.append('  </md:ContactPerson>')
        
        # IDP SSO Descriptor
        metadata.append('  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">')
        
        # Key descriptor
        metadata.append('    <md:KeyDescriptor use="signing">')
        metadata.append('      <ds:KeyInfo>')
        metadata.append('        <ds:X509Data>')
        metadata.append(f'          <ds:X509Certificate>{self.certificate}</ds:X509Certificate>')
        metadata.append('        </ds:X509Data>')
        metadata.append('      </ds:KeyInfo>')
        metadata.append('    </md:KeyDescriptor>')
        
        # Name ID format
        metadata.append('    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>')
        metadata.append('    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>')
        
        # SSO services
        if 'sso' in self.services:
            for service in self.services['sso']:
                metadata.append(f'    <md:SingleSignOnService Binding="{service["binding"]}" ')
                metadata.append(f'                              Location="{service["location"]}" />')
        
        # SLO services
        if 'slo' in self.services:
            for service in self.services['slo']:
                metadata.append(f'    <md:SingleLogoutService Binding="{service["binding"]}" ')
                metadata.append(f'                              Location="{service["location"]}" />')
        
        # Attribute services
        if 'attribute' in self.services:
            for service in self.services['attribute']:
                metadata.append(f'    <md:AttributeService Binding="{service["binding"]}" ')
                metadata.append(f'                              Location="{service["location"]}" />')
        
        metadata.append('  </md:IDPSSODescriptor>')
        metadata.append('</md:EntityDescriptor>')
        
        return '\n'.join(metadata)

class ServiceProvider:
    """SAML Service Provider implementation"""
    
    def __init__(self, entity_id: str, acs_url: str):
        self.entity_id = entity_id
        self.acs_url = acs_url
        self.supported_bindings = [
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        ]
        self.assertion_consumer_service = {
            'binding': "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            'location': acs_url,
            'index': 1,
            'isDefault': True
        }
    
    def generate_metadata(self) -> str:
        """Generate SP metadata XML"""
        
        metadata = []
        metadata.append('<?xml version="1.0" encoding="UTF-8"?>')
        metadata.append(f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"')
        metadata.append(f'    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"')
        metadata.append(f'    entityID="{self.entity_id}"')
        metadata.append(f'    cacheDuration="PT604800S">')
        
        # SP SSO Descriptor
        metadata.append('  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">')
        
        # Key descriptor
        metadata.append('    <md:KeyDescriptor use="signing">')
        metadata.append('      <ds:KeyInfo>')
        metadata.append('        <ds:X509Data>')
        metadata.append('          <ds:X509Certificate>SP-CERTIFICATE-HERE</ds:X509Certificate>')
        metadata.append('        </ds:X509Data>')
        metadata.append('      </ds:KeyInfo>')
        metadata.append('    </md:KeyDescriptor>')
        
        # Name ID format
        metadata.append('    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>')
        
        # Assertion Consumer Service
        acs = self.assertion_consumer_service
        metadata.append(f'    <md:AssertionConsumerService Binding="{acs["binding"]}" ')
        metadata.append(f'                              Location="{acs["location"]}" ')
        metadata.append(f'                              index="{acs["index"]}" ')
        metadata.append(f'                              isDefault="{acs["isDefault"]}" />')
        
        metadata.append('  </md:SPSSODescriptor>')
        metadata.append('</md:EntityDescriptor>')
        
        return '\n'.join(metadata)

# Usage Example
def demonstrate_saml_metadata_configuration():
    print("=== SAML IdP and SP Metadata Demo ===\n")
    
    # Create Identity Provider
    idp = SAMLIdentityProvider(
        entity_id="https://idp.company.com",
        organization_info={
            "name": "Company Corporation",
            "display_name": "Company Corp",
            "url": "https://www.company.com"
        }
    )
    
    # Add IdP services
    idp.add_single_sign_on_service(
        binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        location="https://idp.company.com/sso"
    )
    
    idp.add_single_logout_service(
        binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        location="https://idp.company.com/slo"
    )
    
    idp.add_attribute_service(
        binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
        location="https://idp.company.com/attribute"
    )
    
    # Add contacts
    idp.add_contact(
        contact_type="technical",
        given_name="John Admin",
        email_address="admin@company.com",
        telephone_number="+1-555-0123"
    )
    
    idp.add_contact(
        contact_type="support",
        given_name="Jane Support",
        email_address="support@company.com"
    )
    
    # Generate IdP metadata
    print("1. IdP Metadata")
    idp_metadata = idp.generate_metadata()
    print("IdP Metadata (first 500 characters):")
    print(idp_metadata[:500] + "...")
    
    # Create Service Provider
    sp = ServiceProvider(
        entity_id="https://app.company.com",
        acs_url="https://app.company.com/saml/acs"
    )
    
    # Generate SP metadata
    print("\n2. SP Metadata")
    sp_metadata = sp.generate_metadata()
    print("SP Metadata:")
    print(sp_metadata)
    
    # Save metadata to files (for demonstration)
    print("\n=== Metadata Files Generated ===")
    print("✓ IdP metadata configuration complete")
    print("✓ SP metadata configuration complete")
    print("✓ Ready for federation setup")

demonstrate_saml_metadata_configuration()
```

## Example 3: SAML SSO Flow Implementation

### Complete SSO Flow Handler

```python
import urllib.parse
import urllib.request
from typing import Dict, Optional
import base64

class SAMLSSOHandler:
    """Handle complete SAML SSO flow"""
    
    def __init__(self, idp_metadata: str, sp_metadata: str, 
                 sp_private_key: str, idp_certificate: str):
        self.idp_metadata = self._parse_metadata(idp_metadata)
        self.sp_metadata = self._parse_metadata(sp_metadata)
        self.sp_private_key = sp_private_key
        self.idp_certificate = idp_certificate
        self.saml_requests = {}  # Store pending requests
    
    def _parse_metadata(self, metadata: str) -> Dict:
        """Parse SAML metadata (simplified)"""
        # In production, use proper XML parsing
        return {
            "entity_id": "placeholder",
            "sso_service": {"location": "https://idp.com/sso"},
            "certificate": self.idp_certificate
        }
    
    def create_authentication_request(self, relay_state: str = None) -> Dict[str, str]:
        """Create SAML authentication request"""
        
        # Generate request ID
        request_id = f"req_{secrets.token_hex(8)}"
        
        # Create SAML request
        auth_request = self._build_authentication_request(request_id)
        
        # Encode request for transmission
        encoded_request = base64.b64encode(auth_request.encode()).decode()
        
        # Store request for validation
        self.saml_requests[request_id] = {
            "relay_state": relay_state,
            "created_at": datetime.utcnow(),
            "request": auth_request
        }
        
        # Get IdP SSO URL
        sso_url = self.idp_metadata["sso_service"]["location"]
        
        # Build redirect URL
        redirect_params = {
            "SAMLRequest": encoded_request,
            "RelayState": relay_state or ""
        }
        
        redirect_url = f"{sso_url}?{urllib.parse.urlencode(redirect_params)}"
        
        return {
            "redirect_url": redirect_url,
            "request_id": request_id,
            "encoded_request": encoded_request
        }
    
    def _build_authentication_request(self, request_id: str) -> str:
        """Build SAML authentication request XML"""
        
        request = []
        request.append('<?xml version="1.0" encoding="UTF-8"?>')
        request.append(f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"')
        request.append(f'    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"')
        request.append(f'    ID="{request_id}"')
        request.append(f'    Version="2.0"')
        request.append(f'    IssueInstant="{datetime.utcnow().isoformat()}"')
        request.append(f'    Destination="{self.idp_metadata["sso_service"]["location"]}"')
        request.append(f'    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"')
        request.append(f'    AssertionConsumerServiceURL="{self.sp_metadata.get("acs_url")}"')
        request.append(f'    >')
        
        # Issuer
        request.append(f'  <saml:Issuer>{self.sp_metadata["entity_id"]}</saml:Issuer>')
        
        # Name ID Policy
        request.append('  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"')
        request.append('                      AllowCreate="true" />')
        
        # Requested Auth Context
        request.append('  <samlp:RequestedAuthnContext Comparison="exact">')
        request.append('    <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">')
        request.append('      urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport')
        request.append('    </saml:AuthnContextClassRef>')
        request.append('  </samlp:RequestedAuthnContext>')
        
        request.append('</samlp:AuthnRequest>')
        
        return '\n'.join(request)
    
    def process_authentication_response(self, saml_response: str, 
                                      relay_state: str) -> Dict[str, any]:
        """Process SAML authentication response from IdP"""
        
        try:
            # Decode and parse response
            decoded_response = self._decode_saml_response(saml_response)
            response_data = self._parse_saml_response(decoded_response)
            
            # Validate response
            validation_result = self._validate_response(response_data, relay_state)
            
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "error": validation_result["error"]
                }
            
            # Extract user information
            user_info = self._extract_user_info(response_data)
            
            # Create session
            session_id = self._create_user_session(user_info)
            
            return {
                "success": True,
                "user": user_info,
                "session_id": session_id,
                "relay_state": relay_state
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Response processing failed: {str(e)}"
            }
    
    def _decode_saml_response(self, encoded_response: str) -> str:
        """Decode base64 SAML response"""
        try:
            # Handle URL-encoded response
            decoded_bytes = base64.b64decode(encoded_response + "==")  # Add padding if needed
            return decoded_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Failed to decode SAML response: {e}")
    
    def _parse_saml_response(self, response_xml: str) -> Dict:
        """Parse SAML response XML (simplified)"""
        # In production, use proper XML parsing with namespace support
        try:
            root = ET.fromstring(response_xml)
            
            return {
                "in_response_to": root.get("InResponseTo"),
                "destination": root.get("Destination"),
                "assertion": response_xml,  # Store full assertion for validation
                "issuer": self._find_element_text(root, ".//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
            }
        except ET.ParseError as e:
            raise ValueError(f"Invalid SAML response XML: {e}")
    
    def _find_element_text(self, root, xpath: str) -> Optional[str]:
        """Find element text using simplified xpath"""
        try:
            element = root.find(xpath)
            return element.text if element is not None else None
        except Exception:
            return None
    
    def _validate_response(self, response_data: Dict, relay_state: str) -> Dict[str, any]:
        """Validate SAML response"""
        
        errors = []
        
        # Check InResponseTo
        in_response_to = response_data.get("in_response_to")
        if in_response_to not in self.saml_requests:
            errors.append("Invalid InResponseTo - request not found")
        
        # Check destination
        expected_destination = self.sp_metadata.get("acs_url")
        actual_destination = response_data.get("destination")
        if actual_destination != expected_destination:
            errors.append(f"Invalid destination. Expected: {expected_destination}, Got: {actual_destination}")
        
        # Check issuer
        expected_issuer = self.idp_metadata.get("entity_id")
        actual_issuer = response_data.get("issuer")
        if actual_issuer != expected_issuer:
            errors.append(f"Invalid issuer. Expected: {expected_issuer}, Got: {actual_issuer}")
        
        # Check relay state
        if relay_state:
            stored_request = self.saml_requests.get(in_response_to)
            if stored_request and stored_request["relay_state"] != relay_state:
                errors.append("Relay state mismatch")
        
        # Validate assertion signature (simplified)
        # In production, verify XML signature against IdP certificate
        
        if errors:
            return {"valid": False, "error": "; ".join(errors)}
        
        # Clean up processed request
        if in_response_to in self.saml_requests:
            del self.saml_requests[in_response_to]
        
        return {"valid": True}
    
    def _extract_user_info(self, response_data: Dict) -> Dict[str, any]:
        """Extract user information from SAML assertion"""
        
        assertion_xml = response_data.get("assertion")
        root = ET.fromstring(assertion_xml)
        
        # Extract NameID
        name_id = self._find_element_text(
            root, 
            ".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID"
        )
        
        # Extract attributes
        attributes = {}
        attribute_elements = root.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute")
        
        for attr in attribute_elements:
            attr_name = attr.get("Name")
            attr_value_elem = attr.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
            if attr_value_elem is not None:
                attributes[attr_name] = attr_value_elem.text
        
        # Extract session index
        session_index = self._find_element_text(
            root,
            ".//{urn:oasis:names:tc:SAML:2.0:assertion}SessionIndex"
        )
        
        return {
            "name_id": name_id,
            "attributes": attributes,
            "session_index": session_index
        }
    
    def _create_user_session(self, user_info: Dict) -> str:
        """Create user session based on SAML assertion"""
        
        session_id = secrets.token_urlsafe(32)
        
        # Store session information
        session_data = {
            "user_id": user_info["name_id"],
            "attributes": user_info["attributes"],
            "session_index": user_info["session_index"],
            "created_at": datetime.utcnow(),
            "sso_source": "saml"
        }
        
        # In production, store in database or session store
        # For demo, just return the session ID
        return session_id

class SAMLIntegrationExample:
    """Example SAML integration patterns"""
    
    @staticmethod
    def django_saml_integration():
        """Example Django SAML integration"""
        
        django_config = """
# settings.py
SAML_CONFIG = {
    'entityid': 'https://your-app.com/saml/metadata/',
    'service': {
        'sp': {
            'name': 'Your App',
            'endpoints': {
                'assertion_consumer_service': [
                    ('https://your-app.com/saml/acs/', 
                     saml2.BINDING_HTTP_POST),
                ],
                'single_logout_service': [
                    ('https://your-app.com/saml/ls/', 
                     saml2.BINDING_HTTP_REDIRECT),
                ],
            },
            'required_attributes': ['email', 'first_name', 'last_name'],
            'optional_attributes': ['department', 'title'],
        },
    },
    'key_file': 'saml.key',
    'cert_file': 'saml.crt',
    'metadata': {
        'remote': [
            {
                'url': 'https://your-idp.com/metadata/',
            },
        ],
    },
}
        """
        
        return django_config
    
    @staticmethod
    def flask_saml_integration():
        """Example Flask SAML integration"""
        
        flask_code = """
from flask import Flask, redirect, request, session
import saml2

app = Flask(__name__)
app.secret_key = 'your-secret-key'

# Initialize SAML client
config = {
    'entityid': 'https://your-app.com/saml/metadata/',
    'service': {
        'sp': {
            'endpoints': {
                'assertion_consumer_service': [
                    ('/saml/acs', saml2.BINDING_HTTP_POST),
                ],
            },
        },
    },
    'key_file': 'saml.key',
    'cert_file': 'saml.crt',
}

saml_client = saml2.SAML2Client(config)

@app.route('/saml/login')
def saml_login():
    authn_request = saml_client.prepare_for_authenticate()
    return redirect(authn_request['headers'][0][1])

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    authn_response = saml_client.parse_authn_request(
        request.form['SAMLResponse']
    )
    
    if authn_response.ok:
        session['user'] = authn_response.get_identity()
        return redirect('/dashboard')
    
    return 'SAML authentication failed'
        """
        
        return flask_code

# Usage Example
def demonstrate_saml_sso_flow():
    print("=== SAML SSO Flow Demo ===\n")
    
    # Create SAML handler
    idp_metadata = """
    <EntityDescriptor entityID="https://idp.company.com">
        <IDPSSODescriptor>
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                  Location="https://idp.company.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
    """
    
    sp_metadata = {
        "entity_id": "https://app.company.com",
        "acs_url": "https://app.company.com/saml/acs"
    }
    
    sso_handler = SAMLSSOHandler(
        idp_metadata=idp_metadata,
        sp_metadata=sp_metadata,
        sp_private_key="sp_private_key",
        idp_certificate="idp_certificate"
    )
    
    # Step 1: Create authentication request
    print("1. Creating SAML authentication request")
    auth_request = sso_handler.create_authentication_request(
        relay_state="user_redirect_state"
    )
    
    print(f"Request ID: {auth_request['request_id']}")
    print(f"Redirect URL: {auth_request['redirect_url']}")
    
    # Step 2: Simulate IdP response (in real scenario, this comes from IdP)
    print("\n2. Simulating IdP SAML response")
    
    # This would normally come from the IdP after user authentication
    mock_saml_response = base64.b64encode(b"""
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml:Issuer>https://idp.company.com</saml:Issuer>
        <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        </samlp:Status>
        <saml:Assertion>
            <saml:NameID>john@company.com</saml:NameID>
            <saml:AttributeStatement>
                <saml:Attribute Name="email">
                    <saml:AttributeValue>john@company.com</saml:AttributeValue>
                </saml:Attribute>
                <saml:Attribute Name="firstName">
                    <saml:AttributeValue>John</saml:AttributeValue>
                </saml:Attribute>
                <saml:Attribute Name="lastName">
                    <saml:AttributeValue>Doe</saml:AttributeValue>
                </saml:Attribute>
            </saml:AttributeStatement>
        </saml:Assertion>
    </samlp:Response>
    """.replace(b'\n', b'').strip()).decode()
    
    # Step 3: Process authentication response
    print("3. Processing SAML authentication response")
    auth_result = sso_handler.process_authentication_response(
        mock_saml_response,
        "user_redirect_state"
    )
    
    if auth_result["success"]:
        print("✅ SAML authentication successful")
        print(f"User: {auth_result['user']['name_id']}")
        print(f"Session ID: {auth_result['session_id']}")
        print(f"Attributes: {auth_result['user']['attributes']}")
    else:
        print(f"❌ SAML authentication failed: {auth_result['error']}")
    
    # Integration examples
    print("\n=== Integration Examples ===")
    integration = SAMLIntegrationExample()
    print("Django SAML configuration available")
    print("Flask SAML integration code available")
    
    print("\n=== SSO Flow Benefits ===")
    print("✓ Browser-based SSO experience")
    print("✓ Centralized authentication")
    print("✓ Standard SAML protocol compliance")
    print("✓ Cross-domain identity federation")

demonstrate_saml_sso_flow()
```

## Example 4: SAML Security and Best Practices

### SAML Security Hardening

```python
import re
from typing import Dict, List, Set
from datetime import datetime, timedelta

class SAMLSecurityManager:
    """SAML Security Best Practices Implementation"""
    
    def __init__(self):
        self.security_config = {
            "require_signed_assertions": True,
            "require_signed_requests": True,
            "max_assertion_age": timedelta(hours=8),
            "allowed_clock_skew": timedelta(minutes=5),
            "require_encrypted_assertions": False,
            "validate_issuer": True,
            "validate_audience": True,
            "prevent_replay_attacks": True,
            "allowed_issuers": set(),
            "allowed_audiences": set()
        }
        
        self.seen_assertion_ids: Set[str] = set()
        self.blacklisted_assertions: Dict[str, datetime] = {}
    
    def validate_saml_assertion(self, assertion_xml: str, 
                              expected_issuer: str = None,
                              expected_audience: str = None) -> Dict[str, any]:
        """Comprehensive SAML assertion validation"""
        
        validation_result = {
            "valid": False,
            "errors": [],
            "warnings": [],
            "assertion_data": None
        }
        
        try:
            # Parse assertion
            root = ET.fromstring(assertion_xml)
            
            # Extract basic information
            assertion_id = root.get("ID")
            issuer = self._find_element_text(root, ".//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
            
            validation_result["assertion_data"] = {
                "assertion_id": assertion_id,
                "issuer": issuer,
                "issue_instant": self._parse_saml_datetime(root.get("IssueInstant"))
            }
            
            # Validate issuer
            if self.security_config["validate_issuer"]:
                if expected_issuer and issuer != expected_issuer:
                    validation_result["errors"].append(f"Invalid issuer: expected {expected_issuer}, got {issuer}")
                elif not self.security_config["allowed_issuers"] or issuer not in self.security_config["allowed_issuers"]:
                    validation_result["errors"].append(f"Untrusted issuer: {issuer}")
            
            # Validate timestamps
            timestamp_errors = self._validate_timestamps(root)
            validation_result["errors"].extend(timestamp_errors)
            
            # Validate signature
            if self.security_config["require_signed_assertions"]:
                signature_errors = self._validate_signature(root)
                validation_result["errors"].extend(signature_errors)
            
            # Validate audience
            if self.security_config["validate_audience"]:
                audience_errors = self._validate_audience(root, expected_audience)
                validation_result["errors"].extend(audience_errors)
            
            # Check for replay attacks
            if self.security_config["prevent_replay_attacks"]:
                replay_errors = self._check_replay_attacks(assertion_id)
                validation_result["errors"].extend(replay_errors)
            
            # Validate conditions
            condition_errors = self._validate_conditions(root)
            validation_result["errors"].extend(condition_errors)
            
            # Validation complete
            validation_result["valid"] = len(validation_result["errors"]) == 0
            
        except ET.ParseError as e:
            validation_result["errors"].append(f"Invalid XML: {e}")
        except Exception as e:
            validation_result["errors"].append(f"Validation error: {e}")
        
        return validation_result
    
    def _validate_timestamps(self, root: ET.Element) -> List[str]:
        """Validate SAML assertion timestamps"""
        
        errors = []
        
        # Check IssueInstant
        issue_instant = root.get("IssueInstant")
        if issue_instant:
            try:
                issue_time = self._parse_saml_datetime(issue_instant)
                now = datetime.utcnow()
                
                # Check for future issue times (clock skew tolerance)
                max_future = now + self.security_config["allowed_clock_skew"]
                if issue_time > max_future:
                    errors.append(f"IssueInstant in the future: {issue_instant}")
                
                # Check assertion age
                age = now - issue_time
                if age > self.security_config["max_assertion_age"]:
                    errors.append(f"Assertion too old: {age.total_seconds()} seconds")
                
            except ValueError as e:
                errors.append(f"Invalid IssueInstant format: {e}")
        
        # Check Conditions NotOnOrAfter
        not_on_or_after = self._find_element_text(
            root,
            ".//{urn:oasis:names:tc:SAML:2.0:assertion}Conditions/@NotOnOrAfter"
        )
        
        if not_on_or_after:
            try:
                not_on_or_after_time = self._parse_saml_datetime(not_on_or_after)
                now = datetime.utcnow()
                
                if now > not_on_or_after_time:
                    errors.append(f"Assertion expired at: {not_on_or_after}")
                
            except ValueError as e:
                errors.append(f"Invalid NotOnOrAfter format: {e}")
        
        return errors
    
    def _validate_signature(self, root: ET.Element) -> List[str]:
        """Validate SAML assertion signature (simplified)"""
        
        errors = []
        
        signature = root.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
        if not signature:
            if self.security_config["require_signed_assertions"]:
                errors.append("Missing required signature")
        else:
            # In production, validate signature against trusted certificate
            # This is a simplified check
            signature_value = signature.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
            if signature_value is None or not signature_value.text:
                errors.append("Invalid signature structure")
        
        return errors
    
    def _validate_audience(self, root: ET.Element, expected_audience: str = None) -> List[str]:
        """Validate SAML audience restriction"""
        
        errors = []
        
        audiences = root.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Audience")
        if not audiences:
            if self.security_config["validate_audience"]:
                errors.append("Missing audience restriction")
        else:
            allowed_audiences = set()
            for audience in audiences:
                if audience.text:
                    allowed_audiences.add(audience.text)
            
            if expected_audience and expected_audience not in allowed_audiences:
                errors.append(f"Expected audience '{expected_audience}' not found in assertion")
            elif self.security_config["allowed_audiences"]:
                if not allowed_audiences.intersection(self.security_config["allowed_audiences"]):
                    errors.append(f"No allowed audiences found. Expected one of: {self.security_config['allowed_audiences']}")
        
        return errors
    
    def _check_replay_attacks(self, assertion_id: str) -> List[str]:
        """Check for replay attacks using assertion ID tracking"""
        
        errors = []
        
        if assertion_id in self.seen_assertion_ids:
            errors.append(f"Assertion ID already seen - possible replay attack: {assertion_id}")
        
        if assertion_id in self.blacklisted_assertions:
            errors.append(f"Assertion ID is blacklisted: {assertion_id}")
        
        # Store assertion ID for future checks
        self.seen_assertion_ids.add(assertion_id)
        
        # Clean up old assertion IDs (keep last 1000)
        if len(self.seen_assertion_ids) > 1000:
            self.seen_assertion_ids = set(list(self.seen_assertion_ids)[-1000:])
        
        return errors
    
    def _validate_conditions(self, root: ET.Element) -> List[str]:
        """Validate SAML conditions"""
        
        errors = []
        
        conditions = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Conditions")
        if conditions is not None:
            not_before = conditions.get("NotBefore")
            not_on_or_after = conditions.get("NotOnOrAfter")
            
            now = datetime.utcnow()
            
            if not_before:
                try:
                    not_before_time = self._parse_saml_datetime(not_before)
                    if now < not_before_time - self.security_config["allowed_clock_skew"]:
                        errors.append(f"Assertion not yet valid (NotBefore): {not_before}")
                except ValueError:
                    errors.append(f"Invalid NotBefore format: {not_before}")
            
            if not_on_or_after:
                try:
                    not_on_or_after_time = self._parse_saml_datetime(not_on_or_after)
                    if now > not_on_or_after_time + self.security_config["allowed_clock_skew"]:
                        errors.append(f"Assertion expired (NotOnOrAfter): {not_on_or_after}")
                except ValueError:
                    errors.append(f"Invalid NotOnOrAfter format: {not_on_or_after}")
        
        return errors
    
    def _find_element_text(self, root: ET.Element, xpath: str) -> Optional[str]:
        """Find element text using simplified xpath"""
        try:
            element = root.find(xpath)
            return element.text if element is not None else None
        except Exception:
            return None
    
    def _parse_saml_datetime(self, datetime_str: str) -> datetime:
        """Parse SAML datetime format"""
        # SAML uses ISO 8601 format
        return datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))

class SAMLSConfigurationValidator:
    """Validate SAML configuration for security best practices"""
    
    @staticmethod
    def validate_metadata(metadata_xml: str) -> Dict[str, any]:
        """Validate SAML metadata for security issues"""
        
        validation_result = {
            "valid": True,
            "issues": [],
            "recommendations": []
        }
        
        try:
            root = ET.fromstring(metadata_xml)
            
            # Check certificate validation
            certificates = root.findall(".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
            if not certificates:
                validation_result["issues"].append("No X.509 certificates found in metadata")
                validation_result["valid"] = False
            
            # Check entity ID
            entity_id = root.get("entityID")
            if not entity_id:
                validation_result["issues"].append("Missing entityID in metadata")
                validation_result["valid"] = False
            
            # Check for required services
            sso_services = root.findall(".//{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService")
            if not sso_services:
                validation_result["issues"].append("No SSO service endpoints found")
                validation_result["recommendations"].append("Add SSO service endpoints for proper functionality")
            
            # Check bindings
            supported_bindings = set()
            for service in sso_services:
                binding = service.get("Binding")
                if binding:
                    supported_bindings.add(binding)
            
            recommended_bindings = {
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            }
            
            if not supported_bindings.intersection(recommended_bindings):
                validation_result["recommendations"].append(
                    "Consider supporting HTTP-POST and HTTP-Redirect bindings for better compatibility"
                )
            
        except ET.ParseError as e:
            validation_result["valid"] = False
            validation_result["issues"].append(f"Invalid XML in metadata: {e}")
        
        return validation_result

# Usage Example
def demonstrate_saml_security():
    print("=== SAML Security Best Practices Demo ===\n")
    
    security_manager = SAMLSecurityManager()
    validator = SAMLSConfigurationValidator()
    
    # Configure allowed issuers and audiences
    security_manager.security_config["allowed_issuers"] = {
        "https://idp.company.com",
        "https://partner.acme.com"
    }
    
    security_manager.security_config["allowed_audiences"] = {
        "https://app.company.com",
        "https://portal.company.com"
    }
    
    # Example valid SAML assertion
    valid_assertion = """
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_abc123" 
                    Version="2.0" 
                    IssueInstant="2025-11-15T06:21:12Z">
        <saml:Issuer>https://idp.company.com</saml:Issuer>
        <saml:Conditions NotOnOrAfter="2025-11-15T14:21:12Z">
            <saml:AudienceRestriction>
                <saml:Audience>https://app.company.com</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:Subject>
            <saml:NameID>user@company.com</saml:NameID>
        </saml:Subject>
        <saml:Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
            <saml:SignedInfo>
                <saml:SignatureValue>placeholder</saml:SignatureValue>
            </saml:SignedInfo>
        </saml:Signature>
    </saml:Assertion>
    """
    
    # Example invalid SAML assertion
    invalid_assertion = """
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_abc123">
        <saml:Issuer>https://evil-idp.com</saml:Issuer>
    </saml:Assertion>
    """
    
    # Test validation
    print("1. Validating legitimate SAML assertion")
    valid_result = security_manager.validate_saml_assertion(
        valid_assertion,
        expected_issuer="https://idp.company.com",
        expected_audience="https://app.company.com"
    )
    
    print(f"Valid: {valid_result['valid']}")
    if not valid_result['valid']:
        print(f"Errors: {valid_result['errors']}")
    
    print("\n2. Validating malicious SAML assertion")
    invalid_result = security_manager.validate_saml_assertion(
        invalid_assertion,
        expected_issuer="https://idp.company.com",
        expected_audience="https://app.company.com"
    )
    
    print(f"Valid: {invalid_result['valid']}")
    if not invalid_result['valid']:
        print(f"Errors: {invalid_result['errors']}")
    
    # Test replay attack detection
    print("\n3. Testing replay attack detection")
    
    # Submit same assertion twice
    security_manager.validate_saml_assertion(valid_assertion)
    replay_result = security_manager.validate_saml_assertion(valid_assertion)
    
    print(f"Replay attack detected: {len(replay_result['errors']) > 0}")
    if replay_result['errors']:
        print(f"Error: {replay_result['errors'][0]}")
    
    # Test metadata validation
    print("\n4. Validating SAML metadata")
    
    sample_metadata = """
    <?xml version="1.0" encoding="UTF-8"?>
    <EntityDescriptor entityID="https://idp.company.com"
                      xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
        <IDPSSODescriptor>
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                  Location="https://idp.company.com/sso"/>
            <KeyDescriptor use="signing">
                <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <X509Data>
                        <X509Certificate>cert_data_here</X509Certificate>
                    </X509Data>
                </KeyInfo>
            </KeyDescriptor>
        </IDPSSODescriptor>
    </EntityDescriptor>
    """
    
    metadata_validation = validator.validate_metadata(sample_metadata)
    print(f"Metadata valid: {metadata_validation['valid']}")
    if metadata_validation['issues']:
        print(f"Issues: {metadata_validation['issues']}")
    if metadata_validation['recommendations']:
        print(f"Recommendations: {metadata_validation['recommendations']}")
    
    print("\n=== SAML Security Benefits ===")
    print("✓ Timestamp validation and clock skew handling")
    print("✓ Issuer and audience verification")
    print("✓ Replay attack prevention")
    print("✓ Signature validation")
    print("✓ Comprehensive condition checking")
    print("✓ Metadata security validation")

demonstrate_saml_security()
```

## Key Takeaways

1. **XML Structure**: Proper SAML assertion structure with required elements
2. **Metadata Configuration**: Complete IdP and SP metadata for federation
3. **SSO Flow**: End-to-end SAML authentication flow handling
4. **Security Hardening**: Comprehensive validation and attack prevention
5. **Best Practices**: Industry-standard SAML security implementations

## SAML Implementation Checklist

- [ ] Proper XML namespace declarations
- [ ] Unique assertion IDs and session indexes
- [ ] Time-bound conditions with appropriate expiration
- [ ] Digital signatures on assertions
- [ ] Audience restrictions for security
- [ ] Replay attack prevention
- [ ] Certificate validation
- [ ] Secure metadata exchange
- [ ] Proper binding selection
- [ ] Error handling and logging

---

**Note**: This code is for educational purposes. In production, additional security measures, proper XML signing, certificate validation, and compliance considerations should be implemented.