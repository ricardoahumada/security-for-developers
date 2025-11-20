# SAML Debugging Tools

## 1. SAML Response Inspector

```javascript
function parseSamlResponse(response) {
    try {
        // Base64 decode the response
        const decoded = atob(response);
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(decoded, "text/xml");
        
        // Extract key information
        const assertion = xmlDoc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")[0];
        const issuer = xmlDoc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer")[0];
        const nameId = xmlDoc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "NameID")[0];
        
        console.log("Issuer:", issuer ? issuer.textContent : "Not found");
        console.log("NameID:", nameId ? nameId.textContent : "Not found");
        console.log("Assertion ID:", assertion ? assertion.getAttribute("ID") : "Not found");
        
        // Check for errors
        const statusCodes = xmlDoc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol", "StatusCode");
        if (statusCodes.length > 0) {
            console.log("Status:", statusCodes[0].getAttribute("Value"));
        }
        
        return {
            valid: true,
            issuer: issuer ? issuer.textContent : null,
            nameId: nameId ? nameId.textContent : null,
            assertionId: assertion ? assertion.getAttribute("ID") : null
        };
        
    } catch (error) {
        console.error("Error parsing SAML response:", error);
        return { valid: false, error: error.message };
    }
}
```

## 2. Certificate Chain Validator

```python
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

def validate_certificate_chain(hostname, port=443):
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect and get certificate
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                
        # Parse certificate
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        # Extract key information
        subject = cert.subject
        issuer = cert.issuer
        
        return {
            'valid': True,
            'subject': subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            'issuer': issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            'not_after': cert.not_valid_after,
            'not_before': cert.not_valid_before,
            'serial_number': cert.serial_number
        }
        
    except Exception as e:
        return {
            'valid': False,
            'error': str(e)
        }
```