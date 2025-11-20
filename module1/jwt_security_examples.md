# JWT Security Examples

## Overview

This file contains comprehensive JWT security examples, vulnerability demonstrations, and best practices. These examples complement Topic 3 of the Security Fundamentals module.

## Example 1: Secure JWT Implementation

### JWT Generation and Validation

```python
import jwt
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from dataclasses import dataclass
import json

@dataclass
class User:
    id: str
    email: str
    roles: list[str]
    permissions: list[str]
    department: str

class JWTSecurityManager:
    """Secure JWT implementation with best practices"""
    
    def __init__(self, secret_key: str = None):
        # Use strong secret key or generate one
        self.secret_key = secret_key or self._generate_secret_key()
        self.algorithm = "HS256"
        self.access_token_expiry = timedelta(minutes=15)
        self.refresh_token_expiry = timedelta(days=7)
        self.issuer = "DataFlow Pro API"
        self.audience = "DataFlow Pro Clients"
    
    def _generate_secret_key(self) -> str:
        """Generate cryptographically secure secret key"""
        return secrets.token_urlsafe(32)
    
    def create_access_token(self, user: User, session_id: str = None) -> str:
        """Create short-lived access token"""
        
        # Generate session ID if not provided
        if not session_id:
            session_id = secrets.token_urlsafe(16)
        
        now = datetime.utcnow()
        
        # Define claims
        payload = {
            # Registered claims
            "iss": self.issuer,
            "sub": user.id,
            "aud": self.audience,
            "exp": now + self.access_token_expiry,
            "nbf": now,
            "iat": now,
            "jti": session_id,
            
            # Public claims
            "email": user.email,
            "roles": user.roles,
            "permissions": user.permissions,
            "department": user.department,
            "token_type": "access",
            
            # Additional security claims
            "auth_method": "password",  # How user authenticated
            "session_created": now.isoformat()
        }
        
        # Create JWT
        token = jwt.encode(
            payload=payload,
            key=self.secret_key,
            algorithm=self.algorithm,
            headers={
                "kid": "key_id_2025",  # Key ID for key rotation
                "typ": "JWT"
            }
        )
        
        return token
    
    def create_refresh_token(self, user_id: str, session_id: str) -> str:
        """Create refresh token for obtaining new access tokens"""
        
        now = datetime.utcnow()
        
        payload = {
            "iss": self.issuer,
            "sub": user_id,
            "aud": self.audience,
            "exp": now + self.refresh_token_expiry,
            "nbf": now,
            "iat": now,
            "jti": f"refresh_{session_id}",
            "token_type": "refresh",
            "linked_session": session_id
        }
        
        token = jwt.encode(
            payload=payload,
            key=self.secret_key,
            algorithm=self.algorithm
        )
        
        return token
    
    def validate_token(self, token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """Validate JWT token with comprehensive checks"""
        
        try:
            # Decode token with all validation checks
            payload = jwt.decode(
                jwt=token,
                key=self.secret_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=self.audience,
                options={
                    "require": ["exp", "nbf", "iat", "iss", "sub", "aud"],
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True
                }
            )
            
            # Additional business logic validation
            if payload.get("token_type") != token_type:
                return None
            
            # Check for reasonable token age (prevent replay attacks)
            age = datetime.utcnow() - datetime.fromisoformat(payload["iat"])
            if token_type == "access" and age > timedelta(hours=24):
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            print("❌ Token expired")
            return None
        except jwt.InvalidTokenError as e:
            print(f"❌ Invalid token: {e}")
            return None
        except Exception as e:
            print(f"❌ Token validation error: {e}")
            return None
    
    def rotate_secret_key(self) -> str:
        """Rotate secret key for enhanced security"""
        old_key = self.secret_key
        self.secret_key = self._generate_secret_key()
        
        # In production, you'd:
        # 1. Store old key for token validation during transition
        # 2. Update all services with new key
        # 3. Gradually transition tokens
        # 4. Remove old key after transition period
        
        print(f"🔄 Secret key rotated")
        return old_key

class TokenBlacklist:
    """Token blacklist for immediate revocation"""
    
    def __init__(self):
        self.blacklisted_tokens: Dict[str, datetime] = {}
        self.blacklisted_sessions: set[str] = set()
    
    def blacklist_token(self, jti: str, expiry: datetime):
        """Add token to blacklist"""
        self.blacklisted_tokens[jti] = expiry
    
    def blacklist_session(self, session_id: str):
        """Blacklist entire session"""
        self.blacklisted_sessions.add(session_id)
    
    def is_blacklisted(self, jti: str, session_id: str = None) -> bool:
        """Check if token or session is blacklisted"""
        if jti in self.blacklisted_tokens:
            return True
        
        if session_id and session_id in self.blacklisted_sessions:
            return True
        
        return False
    
    def cleanup_expired(self):
        """Remove expired blacklist entries"""
        now = datetime.utcnow()
        expired_jtis = [
            jti for jti, expiry in self.blacklisted_tokens.items()
            if now > expiry
        ]
        
        for jti in expired_jtis:
            del self.blacklisted_tokens[jti]

# Usage Example
def demonstrate_secure_jwt():
    print("=== Secure JWT Implementation Demo ===\n")
    
    # Initialize security manager
    jwt_manager = JWTSecurityManager()
    blacklist = TokenBlacklist()
    
    # Create user
    user = User(
        id="user123",
        email="john@company.com",
        roles=["employee", "developer"],
        permissions=["read:data", "write:data", "delete:user"],
        department="Engineering"
    )
    
    # Generate tokens
    print("1. Creating access and refresh tokens")
    access_token = jwt_manager.create_access_token(user)
    refresh_token = jwt_manager.create_refresh_token(user.id, "session123")
    
    print(f"Access Token (first 50 chars): {access_token[:50]}...")
    print(f"Refresh Token (first 50 chars): {refresh_token[:50]}...")
    
    # Decode and display token contents
    print("\n2. Token contents:")
    decoded_access = jwt.decode(access_token, options={"verify_signature": False})
    print("Access Token Claims:")
    for key, value in decoded_access.items():
        if key not in ['iat', 'nbf', 'exp']:  # Skip timestamps for readability
            print(f"  {key}: {value}")
    
    # Validate token
    print("\n3. Validating access token")
    is_valid = jwt_manager.validate_token(access_token)
    if is_valid:
        print("✅ Token validation successful")
        print(f"  User ID: {is_valid['sub']}")
        print(f"  Permissions: {is_valid['permissions']}")
    else:
        print("❌ Token validation failed")
    
    # Demonstrate token expiration
    print("\n4. Testing token expiration")
    # Create expired token (modify expiry for demo)
    expired_payload = jwt_manager.validate_token(access_token)
    if expired_payload:
        expired_payload['exp'] = datetime.utcnow() - timedelta(minutes=1)
        expired_token = jwt.encode(
            expired_payload, jwt_manager.secret_key, algorithm="HS256"
        )
        
        is_valid = jwt_manager.validate_token(expired_token)
        print(f"Expired token validation: {'✅ Valid' if is_valid else '❌ Invalid'}")
    
    # Demonstrate blacklisting
    print("\n5. Testing token blacklisting")
    # Parse token to get JTI
    decoded = jwt.decode(access_token, options={"verify_signature": False})
    jti = decoded['jti']
    session_id = decoded.get('linked_session')
    
    # Blacklist the token
    expiry = datetime.fromtimestamp(decoded['exp'])
    blacklist.blacklist_token(jti, expiry)
    
    # Check blacklist
    is_blacklisted = blacklist.is_blacklisted(jti)
    print(f"Token blacklisted: {'✅ Yes' if is_blacklisted else '❌ No'}")
    
    print("\n=== Security Benefits Demonstrated ===")
    print("✓ Short-lived access tokens with refresh mechanism")
    print("✓ Comprehensive token validation")
    print("✓ Token blacklisting for immediate revocation")
    print("✓ Key rotation capability")
    print("✓ Minimal sensitive data in payload")

demonstrate_secure_jwt()
```

## Example 2: JWT Security Vulnerabilities and Mitigation

### Vulnerability Demonstration

```python
import jwt
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

class JWTVulnerabilityDemo:
    """Demonstrate common JWT vulnerabilities and mitigations"""
    
    def __init__(self):
        self.weak_secret = "secret"  # VERY WEAK secret
        self.strong_secret = secrets.token_urlsafe(32)
        
        # Generate RSA key pair for asymmetric signing
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def vulnerability_1_weak_secret(self) -> tuple[str, str, bool]:
        """Demonstrate vulnerability: weak secret"""
        
        # Create token with weak secret
        weak_payload = {"user": "alice", "admin": False}
        weak_token = jwt.encode(weak_payload, self.weak_secret, algorithm="HS256")
        
        # Attacker tries to modify token (set admin=True)
        # Since we know the secret, we can easily recreate token
        malicious_payload = {"user": "alice", "admin": True}
        malicious_token = jwt.encode(malicious_payload, self.weak_secret, algorithm="HS256")
        
        # Validate with original secret
        try:
            decoded = jwt.decode(malicious_token, self.weak_secret, algorithms=["HS256"])
            return weak_token, malicious_token, True  # Vulnerable
        except jwt.InvalidTokenError:
            return weak_token, malicious_token, False  # Secure
    
    def vulnerability_2_algorithm_confusion(self) -> tuple[str, str, bool]:
        """Demonstrate vulnerability: algorithm confusion (none)"""
        
        # Create token with RSA algorithm
        payload = {"user": "alice", "admin": False}
        rsa_token = jwt.encode(payload, self.private_key, algorithm="RS256")
        
        # Attacker modifies header to use "none" algorithm
        # This bypasses signature verification
        header, payload_part, _ = rsa_token.split('.')
        
        # Modify header to use "none" algorithm
        modified_header = jwt.get_unverified_header(rsa_token)
        modified_header["alg"] = "none"
        
        # Re-encode with "none" algorithm
        none_token = jwt.encode(payload, key=None, algorithm=None, headers=modified_header)
        
        # Try to validate (this would succeed if not properly protected)
        try:
            # Proper validation should reject "none" algorithm
            decoded = jwt.decode(none_token, options={"verify_signature": False})
            # But this bypasses signature check entirely
            return rsa_token, none_token, True  # Vulnerable
        except jwt.InvalidTokenError:
            return rsa_token, none_token, False
    
    def vulnerability_3_key_confusion_hs256_rs256(self) -> tuple[str, str, bool]:
        """Demonstrate vulnerability: HS256/RS256 key confusion"""
        
        # Some implementations mistakenly use RSA public key with HS256
        public_key_pem = self.public_key.public_key_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        payload = {"user": "alice", "admin": False}
        
        # Create token with RS256 using private key
        rsa_token = jwt.encode(payload, self.private_key, algorithm="RS256")
        
        # Attacker creates token with HS256 using RSA public key
        # If server accepts HS256 and uses RSA key, this works
        malicious_payload = {"user": "alice", "admin": True}
        hs256_token = jwt.encode(malicious_payload, public_key_pem, algorithm="HS256")
        
        # Validate both with RSA public key and HS256
        try:
            # This would work if server incorrectly uses HS256 with RSA key
            jwt.decode(hs256_token, public_key_pem, algorithms=["HS256"])
            return rsa_token, hs256_token, True  # Vulnerable
        except (jwt.InvalidTokenError, jwt.InvalidSignatureError):
            return rsa_token, hs256_token, False  # Secure
    
    def vulnerability_4_token_expansion(self) -> tuple[str, str, bool]:
        """Demonstrate vulnerability: token time extension"""
        
        now = datetime.utcnow()
        payload = {
            "user": "alice",
            "exp": now + timedelta(minutes=30)
        }
        
        original_token = jwt.encode(payload, self.strong_secret, algorithm="HS256")
        
        # Attacker extends expiration
        extended_payload = {
            "user": "alice",
            "exp": now + timedelta(days=30)  # Much longer expiration
        }
        
        extended_token = jwt.encode(extended_payload, self.strong_secret, algorithm="HS256")
        
        # Validate (both are valid with same secret)
        try:
            jwt.decode(extended_token, self.strong_secret, algorithms=["HS256"])
            # Both tokens work, demonstrating lack of integrity protection
            return original_token, extended_token, True  # Vulnerable
        except jwt.InvalidTokenError:
            return original_token, extended_token, False

class JWTAttacker:
    """JWT attack simulation"""
    
    @staticmethod
    def brute_force_secret(token: str, wordlist: list[str]) -> Optional[str]:
        """Brute force weak JWT secret"""
        
        for secret in wordlist:
            try:
                jwt.decode(token, secret, algorithms=["HS256"])
                return secret
            except jwt.InvalidTokenError:
                continue
        return None
    
    @staticmethod
    def modify_jwt_header(token: str, new_algorithm: str = None) -> str:
        """Modify JWT header"""
        header = jwt.get_unverified_header(token)
        
        if new_algorithm:
            header["alg"] = new_algorithm
        
        # Re-encode with modified header
        payload = jwt.decode(token, options={"verify_signature": False})
        return jwt.encode(payload, key=None, algorithm=None, headers=header)

def demonstrate_jwt_attacks():
    print("\n=== JWT Vulnerability Demonstration ===\n")
    
    demo = JWTVulnerabilityDemo()
    attacker = JWTAttacker()
    
    # Test vulnerability 1: Weak secret
    print("1. Weak Secret Vulnerability")
    original, malicious, vulnerable = demo.vulnerability_1_weak_secret()
    print(f"   Original token admin claim: {jwt.decode(original, options={'verify_signature': False})['admin']}")
    print(f"   Malicious token admin claim: {jwt.decode(malicious, options={'verify_signature': False})['admin']}")
    print(f"   Status: {'❌ VULNERABLE' if vulnerable else '✅ SECURE'}")
    
    # Test vulnerability 2: Algorithm confusion
    print("\n2. Algorithm Confusion (none)")
    original, modified, vulnerable = demo.vulnerability_2_algorithm_confusion()
    print(f"   Modified algorithm: {jwt.get_unverified_header(modified)['alg']}")
    print(f"   Status: {'❌ VULNERABLE' if vulnerable else '✅ SECURE'}")
    
    # Test vulnerability 3: Key confusion
    print("\n3. HS256/RS256 Key Confusion")
    original, malicious, vulnerable = demo.vulnerability_3_key_confusion_hs256_rs256()
    print(f"   Original algorithm: {jwt.get_unverified_header(original)['alg']}")
    print(f"   Malicious algorithm: {jwt.get_unverified_header(malicious)['alg']}")
    print(f"   Status: {'❌ VULNERABLE' if vulnerable else '✅ SECURE'}")
    
    # Test brute force attack
    print("\n4. Brute Force Attack")
    weak_token = jwt.encode({"user": "admin", "admin": True}, "password123", algorithm="HS256")
    wordlist = ["123456", "password", "admin", "password123", "secret"]
    
    found_secret = attacker.brute_force_secret(weak_token, wordlist)
    print(f"   Wordlist: {wordlist}")
    print(f"   Found secret: {found_secret}")
    print(f"   Status: {'❌ VULNERABLE' if found_secret else '✅ SECURE'}")
    
    print("\n=== Attack Mitigation ===")
    print("✓ Use strong, randomly generated secrets")
    print("✓ Enforce specific algorithms")
    print("✓ Validate algorithm matches key type")
    print("✓ Implement rate limiting for brute force protection")

demonstrate_jwt_attacks()
```

## Example 3: JWT Security Best Practices Implementation

```python
from enum import Enum
from typing import Dict, List, Optional, Set
import json
import redis
import hmac
import time

class TokenStatus(Enum):
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    BLACKLISTED = "blacklisted"
    INVALID = "invalid"

class AdvancedJWTSecurityManager:
    """Advanced JWT security implementation with comprehensive protections"""
    
    def __init__(self):
        # Strong cryptographic secrets
        self.access_secret = secrets.token_urlsafe(64)
        self.refresh_secret = secrets.token_urlsafe(64)
        
        # Algorithm restrictions
        self.allowed_algorithms = {"HS256", "RS256", "ES256"}
        
        # Token storage (in production, use Redis or similar)
        self.token_registry: Dict[str, dict] = {}
        self.active_sessions: Set[str] = set()
        
        # Security configurations
        self.max_token_age = timedelta(hours=24)
        self.max_refresh_age = timedelta(days=30)
        self.rate_limits = {
            "token_creation": 100,  # per minute
            "token_validation": 1000,  # per minute
            "refresh_attempts": 10  # per minute
        }
        
        # Rate limiting counters
        self.rate_counters = {
            "token_creation": {},
            "token_validation": {},
            "refresh_attempts": {}
        }
    
    def create_secure_token_pair(self, user: User, device_id: str = None, 
                                ip_address: str = None) -> Dict[str, str]:
        """Create secure access and refresh token pair"""
        
        # Rate limiting check
        if not self._check_rate_limit("token_creation", "global"):
            raise ValueError("Rate limit exceeded for token creation")
        
        # Generate unique session ID
        session_id = secrets.token_urlsafe(32)
        
        # Create fingerprint for device tracking
        fingerprint = self._create_device_fingerprint(device_id, ip_address)
        
        # Create access token
        access_token = self._create_access_token(
            user, session_id, fingerprint
        )
        
        # Create refresh token
        refresh_token = self._create_refresh_token(
            user.id, session_id, fingerprint
        )
        
        # Register session
        self._register_session(session_id, user, device_id, ip_address)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "session_id": session_id,
            "expires_in": 900,  # 15 minutes
            "token_type": "Bearer"
        }
    
    def _create_access_token(self, user: User, session_id: str, 
                           fingerprint: str) -> str:
        """Create secure access token"""
        
        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=15)
        
        payload = {
            # Registered claims
            "iss": "dataflow-api",
            "sub": user.id,
            "aud": "dataflow-clients",
            "exp": expires_at,
            "nbf": now,
            "iat": now,
            "jti": secrets.token_urlsafe(16),
            
            # Custom claims
            "email": user.email,
            "roles": user.roles,
            "permissions": user.permissions,
            "department": user.department,
            "session_id": session_id,
            "fingerprint": fingerprint,
            "token_type": "access",
            
            # Security claims
            "key_version": "2025.1",
            "auth_method": "password+mfa"
        }
        
        return jwt.encode(payload, self.access_secret, algorithm="HS256")
    
    def _create_refresh_token(self, user_id: str, session_id: str, 
                            fingerprint: str) -> str:
        """Create secure refresh token"""
        
        now = datetime.utcnow()
        expires_at = now + timedelta(days=7)
        
        payload = {
            "iss": "dataflow-api",
            "sub": user_id,
            "aud": "dataflow-clients",
            "exp": expires_at,
            "nbf": now,
            "iat": now,
            "jti": f"refresh_{session_id}",
            "session_id": session_id,
            "fingerprint": fingerprint,
            "token_type": "refresh",
            "key_version": "2025.1"
        }
        
        return jwt.encode(payload, self.refresh_secret, algorithm="HS256")
    
    def _create_device_fingerprint(self, device_id: str, ip_address: str) -> str:
        """Create device fingerprint for session binding"""
        if not device_id and not ip_address:
            return "unknown"
        
        components = [device_id or "", ip_address or ""]
        fingerprint_data = "|".join(components)
        
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
    
    def _register_session(self, session_id: str, user: User, 
                        device_id: str, ip_address: str):
        """Register session for monitoring and management"""
        
        self.active_sessions.add(session_id)
        self.token_registry[session_id] = {
            "user_id": user.id,
            "created_at": datetime.utcnow(),
            "last_activity": datetime.utcnow(),
            "device_id": device_id,
            "ip_address": ip_address,
            "status": "active",
            "token_count": 0
        }
    
    def validate_access_token(self, token: str, expected_fingerprint: str = None) -> Dict[str, any]:
        """Comprehensive token validation"""
        
        # Rate limiting
        if not self._check_rate_limit("token_validation", "global"):
            raise ValueError("Rate limit exceeded for token validation")
        
        try:
            # Parse token without verification first
            unverified = jwt.get_unverified_claims(token)
            session_id = unverified.get("session_id")
            
            # Check session status
            if session_id and session_id not in self.active_sessions:
                return {"status": TokenStatus.INVALID, "reason": "Session not active"}
            
            # Validate token with all security checks
            payload = jwt.decode(
                token,
                self.access_secret,
                algorithms=["HS256"],
                issuer="dataflow-api",
                audience="dataflow-clients",
                options={
                    "require": ["exp", "nbf", "iat", "iss", "sub", "aud", "jti", "session_id"],
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True
                }
            )
            
            # Additional security checks
            if expected_fingerprint and payload.get("fingerprint") != expected_fingerprint:
                self._handle_security_violation(session_id, "fingerprint_mismatch")
                return {"status": TokenStatus.INVALID, "reason": "Device fingerprint mismatch"}
            
            # Check token age
            token_age = datetime.utcnow() - datetime.fromtimestamp(payload["iat"])
            if token_age > self.max_token_age:
                return {"status": TokenStatus.EXPIRED, "reason": "Token too old"}
            
            # Update session activity
            if session_id in self.token_registry:
                self.token_registry[session_id]["last_activity"] = datetime.utcnow()
                self.token_registry[session_id]["token_count"] += 1
            
            return {
                "status": TokenStatus.VALID,
                "payload": payload,
                "user_id": payload["sub"],
                "session_id": session_id
            }
            
        except jwt.ExpiredSignatureError:
            return {"status": TokenStatus.EXPIRED, "reason": "Token expired"}
        except jwt.InvalidTokenError as e:
            return {"status": TokenStatus.INVALID, "reason": f"Invalid token: {e}"}
        except Exception as e:
            return {"status": TokenStatus.INVALID, "reason": f"Validation error: {e}"}
    
    def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, str]]:
        """Refresh access token using refresh token"""
        
        # Rate limiting
        if not self._check_rate_limit("refresh_attempts", "global"):
            raise ValueError("Rate limit exceeded for refresh attempts")
        
        try:
            # Validate refresh token
            payload = jwt.decode(
                refresh_token,
                self.refresh_secret,
                algorithms=["HS256"],
                issuer="dataflow-api",
                audience="dataflow-clients"
            )
            
            session_id = payload["session_id"]
            user_id = payload["sub"]
            
            # Check if session is still active
            if session_id not in self.active_sessions:
                return None
            
            session = self.token_registry.get(session_id)
            if not session or session["status"] != "active":
                return None
            
            # Create new access token
            user = User(
                id=user_id,
                email="user@example.com",  # In real app, fetch from database
                roles=["user"],
                permissions=["read"],
                department="IT"
            )
            
            new_access_token = self._create_access_token(
                user, session_id, payload["fingerprint"]
            )
            
            return {
                "access_token": new_access_token,
                "expires_in": 900,
                "token_type": "Bearer"
            }
            
        except jwt.InvalidTokenError:
            return None
    
    def revoke_session(self, session_id: str, reason: str = "manual"):
        """Revoke session and invalidate all tokens"""
        
        if session_id in self.active_sessions:
            self.active_sessions.remove(session_id)
            
            if session_id in self.token_registry:
                self.token_registry[session_id]["status"] = "revoked"
                self.token_registry[session_id]["revoked_at"] = datetime.utcnow()
                self.token_registry[session_id]["revocation_reason"] = reason
    
    def revoke_all_user_sessions(self, user_id: str, reason: str = "user_logout"):
        """Revoke all sessions for a user"""
        
        sessions_to_revoke = [
            session_id for session_id, session in self.token_registry.items()
            if session["user_id"] == user_id and session["status"] == "active"
        ]
        
        for session_id in sessions_to_revoke:
            self.revoke_session(session_id, reason)
    
    def _check_rate_limit(self, operation: str, key: str) -> bool:
        """Check rate limiting for operations"""
        now = time.time()
        minute_window = int(now // 60)
        
        if operation not in self.rate_counters:
            self.rate_counters[operation] = {}
        
        if minute_window not in self.rate_counters[operation]:
            self.rate_counters[operation][minute_window] = {}
        
        if key not in self.rate_counters[operation][minute_window]:
            self.rate_counters[operation][minute_window][key] = 0
        
        current_count = self.rate_counters[operation][minute_window][key]
        limit = self.rate_limits[operation]
        
        if current_count >= limit:
            return False
        
        self.rate_counters[operation][minute_window][key] += 1
        return True
    
    def _handle_security_violation(self, session_id: str, violation_type: str):
        """Handle security violations"""
        
        print(f"🚨 Security violation detected: {violation_type} for session {session_id}")
        
        # Log violation
        if session_id in self.token_registry:
            session = self.token_registry[session_id]
            if "violations" not in session:
                session["violations"] = []
            
            session["violations"].append({
                "type": violation_type,
                "timestamp": datetime.utcnow(),
                "ip_address": session.get("ip_address"),
                "device_id": session.get("device_id")
            })
        
        # Auto-revoke after 3 violations
        if session_id in self.token_registry:
            violation_count = len(self.token_registry[session_id].get("violations", []))
            if violation_count >= 3:
                self.revoke_session(session_id, "security_violations")
    
    def get_active_sessions(self, user_id: str) -> List[Dict]:
        """Get all active sessions for user"""
        
        return [
            {
                "session_id": session_id,
                **session_data
            }
            for session_id, session_data in self.token_registry.items()
            if session_data["user_id"] == user_id and session_data["status"] == "active"
        ]

# Usage Example
def demonstrate_advanced_security():
    print("\n=== Advanced JWT Security Demo ===\n")
    
    security_manager = AdvancedJWTSecurityManager()
    
    # Create user and generate tokens
    user = User(
        id="user123",
        email="john@company.com",
        roles=["employee"],
        permissions=["read:data"],
        department="Engineering"
    )
    
    print("1. Creating secure token pair")
    tokens = security_manager.create_secure_token_pair(
        user=user,
        device_id="device_abc123",
        ip_address="192.168.1.100"
    )
    
    print(f"Access Token: {tokens['access_token'][:50]}...")
    print(f"Session ID: {tokens['session_id']}")
    
    # Validate access token
    print("\n2. Validating access token")
    validation_result = security_manager.validate_access_token(
        tokens['access_token'],
        "fingerprint_hash"  # Should match original
    )
    
    print(f"Validation Status: {validation_result['status'].value}")
    if validation_result['status'] == TokenStatus.VALID:
        print(f"User ID: {validation_result['user_id']}")
    
    # Demonstrate security violation
    print("\n3. Testing security violation detection")
    wrong_fingerprint = security_manager.validate_access_token(
        tokens['access_token'],
        "wrong_fingerprint"
    )
    print(f"Wrong fingerprint validation: {wrong_fingerprint['status'].value}")
    print(f"Reason: {wrong_fingerprint['reason']}")
    
    # Refresh token
    print("\n4. Refreshing access token")
    refreshed = security_manager.refresh_access_token(tokens['refresh_token'])
    if refreshed:
        print(f"New access token: {refreshed['access_token'][:50]}...")
    
    # Get active sessions
    print("\n5. Listing active sessions")
    sessions = security_manager.get_active_sessions("user123")
    for session in sessions:
        print(f"Session: {session['session_id']}")
        print(f"Device: {session.get('device_id')}")
        print(f"IP: {session.get('ip_address')}")
    
    # Revoke session
    print("\n6. Revoking session")
    security_manager.revoke_session(tokens['session_id'], "user_request")
    print("Session revoked")
    
    print("\n=== Advanced Security Features ===")
    print("✓ Comprehensive token validation")
    print("✓ Device fingerprinting")
    print("✓ Session management")
    print("✓ Rate limiting")
    print("✓ Security violation detection")
    print("✓ Automatic session revocation")

demonstrate_advanced_security()
```

## Example 4: JWT Security Audit Checklist

```python
class JWTSecurityAuditor:
    """JWT Security Audit Tool"""
    
    def __init__(self):
        self.audit_results = {}
        self.critical_issues = []
        self.recommendations = []
    
    def audit_jwt_configuration(self, config: Dict) -> Dict:
        """Comprehensive JWT security audit"""
        
        self.audit_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "config": config,
            "issues": [],
            "recommendations": [],
            "score": 0
        }
        
        # Run all audit checks
        self._check_secret_strength(config.get("secret_key", ""))
        self._check_algorithm_restrictions(config.get("allowed_algorithms", []))
        self._check_token_expiration(config.get("access_token_expiry", 0))
        self._check_payload_safety(config.get("payload_fields", []))
        self._check_validation_settings(config.get("validation_options", {}))
        self._check_key_management(config.get("key_rotation", {}))
        self._check_rate_limiting(config.get("rate_limits", {}))
        
        # Calculate security score
        self._calculate_security_score()
        
        return self.audit_results
    
    def _check_secret_strength(self, secret: str):
        """Check JWT secret strength"""
        
        issues = []
        recommendations = []
        score = 0
        
        if len(secret) < 32:
            issues.append("Secret key is too short (< 32 characters)")
            recommendations.append("Use a secret key of at least 32 characters")
        elif len(secret) >= 32:
            score += 25
        
        # Check for common weak secrets
        weak_secrets = ["secret", "password", "123456", "admin", "jwt_secret"]
        if secret.lower() in weak_secrets:
            issues.append("Secret key is commonly used and insecure")
            recommendations.append("Generate a cryptographically random secret")
        else:
            score += 25
        
        if not secret or not isinstance(secret, str):
            issues.append("Secret key is empty or invalid")
            recommendations.append("Provide a valid secret key")
        
        self.audit_results["issues"].extend(issues)
        self.audit_results["recommendations"].extend(recommendations)
        self.audit_results["secret_score"] = score
    
    def _check_algorithm_restrictions(self, allowed_algorithms: List[str]):
        """Check algorithm restrictions"""
        
        issues = []
        recommendations = []
        score = 0
        
        if "none" in [alg.lower() for alg in allowed_algorithms]:
            issues.append("Algorithm 'none' is allowed (security risk)")
            recommendations.append("Remove 'none' algorithm from allowed list")
        else:
            score += 15
        
        if len(allowed_algorithms) == 1 and allowed_algorithms[0] in ["HS256", "RS256"]:
            score += 10
        else:
            recommendations.append("Limit allowed algorithms to necessary ones only")
        
        recommended_algorithms = {"HS256", "RS256", "ES256"}
        if any(alg in allowed_algorithms for alg in recommended_algorithms):
            score += 15
        
        self.audit_results["issues"].extend(issues)
        self.audit_results["recommendations"].extend(recommendations)
        self.audit_results["algorithm_score"] = score
    
    def _check_token_expiration(self, expiry_seconds: int):
        """Check token expiration configuration"""
        
        issues = []
        recommendations = []
        score = 0
        
        if expiry_seconds > 3600:  # 1 hour
            issues.append(f"Access token expiration too long ({expiry_seconds}s)")
            recommendations.append("Keep access token expiration under 1 hour")
        elif expiry_seconds <= 3600 and expiry_seconds >= 300:  # 5 minutes to 1 hour
            score += 20
        
        if expiry_seconds < 300:  # 5 minutes
            recommendations.append("Consider increasing expiration for better UX")
        
        self.audit_results["issues"].extend(issues)
        self.audit_results["recommendations"].extend(recommendations)
        self.audit_results["expiration_score"] = score
    
    def _check_payload_safety(self, payload_fields: List[str]):
        """Check for sensitive data in payload"""
        
        sensitive_fields = ["password", "ssn", "credit_card", "secret", "token"]
        issues = []
        recommendations = []
        score = 20  # Start with base score
        
        for field in payload_fields:
            if any(sensitive in field.lower() for sensitive in sensitive_fields):
                issues.append(f"Potentially sensitive field in payload: {field}")
                recommendations.append(f"Remove {field} from payload or encrypt it")
                score -= 5
        
        if score < 0:
            score = 0
        
        self.audit_results["issues"].extend(issues)
        self.audit_results["recommendations"].extend(recommendations)
        self.audit_results["payload_score"] = score
    
    def _check_validation_settings(self, validation_options: Dict):
        """Check JWT validation settings"""
        
        issues = []
        recommendations = []
        score = 0
        
        required_options = [
            "verify_signature", "verify_exp", "verify_nbf", 
            "verify_iat", "verify_iss", "verify_aud"
        ]
        
        for option in required_options:
            if not validation_options.get(option, True):
                issues.append(f"{option} verification is disabled")
                recommendations.append(f"Enable {option} verification")
            else:
                score += 5
        
        self.audit_results["issues"].extend(issues)
        self.audit_results["recommendations"].extend(recommendations)
        self.audit_results["validation_score"] = score
    
    def _check_key_management(self, key_rotation: Dict):
        """Check key rotation configuration"""
        
        issues = []
        recommendations = []
        score = 0
        
        rotation_enabled = key_rotation.get("enabled", False)
        rotation_interval = key_rotation.get("interval_days", 0)
        
        if not rotation_enabled:
            issues.append("Key rotation is not enabled")
            recommendations.append("Enable automatic key rotation")
        elif rotation_interval > 90:
            issues.append("Key rotation interval too long (> 90 days)")
            recommendations.append("Rotate keys every 30-90 days")
        else:
            score += 15
        
        self.audit_results["issues"].extend(issues)
        self.audit_results["recommendations"].extend(recommendations)
        self.audit_results["key_management_score"] = score
    
    def _check_rate_limiting(self, rate_limits: Dict):
        """Check rate limiting configuration"""
        
        issues = []
        recommendations = []
        score = 0
        
        required_limits = ["token_creation", "token_validation", "refresh_attempts"]
        
        for limit_type in required_limits:
            if limit_type not in rate_limits:
                issues.append(f"Rate limiting not configured for {limit_type}")
                recommendations.append(f"Add rate limiting for {limit_type}")
            else:
                limit_value = rate_limits[limit_type]
                if isinstance(limit_value, dict) and "requests_per_minute" in limit_value:
                    rpm = limit_value["requests_per_minute"]
                    if rpm > 1000:  # Very permissive
                        recommendations.append(f"Consider lowering rate limit for {limit_type}")
                    else:
                        score += 5
                else:
                    recommendations.append(f"Configure proper rate limit structure for {limit_type}")
        
        self.audit_results["issues"].extend(issues)
        self.audit_results["recommendations"].extend(recommendations)
        self.audit_results["rate_limiting_score"] = score
    
    def _calculate_security_score(self):
        """Calculate overall JWT security score"""
        
        score_components = [
            self.audit_results.get("secret_score", 0),
            self.audit_results.get("algorithm_score", 0),
            self.audit_results.get("expiration_score", 0),
            self.audit_results.get("payload_score", 0),
            self.audit_results.get("validation_score", 0),
            self.audit_results.get("key_management_score", 0),
            self.audit_results.get("rate_limiting_score", 0)
        ]
        
        total_score = sum(score_components)
        max_score = 150  # Theoretical maximum
        
        percentage = (total_score / max_score) * 100
        self.audit_results["score"] = round(percentage, 1)
        
        # Determine security level
        if percentage >= 80:
            self.audit_results["security_level"] = "HIGH"
        elif percentage >= 60:
            self.audit_results["security_level"] = "MEDIUM"
        else:
            self.audit_results["security_level"] = "LOW"
    
    def generate_audit_report(self) -> str:
        """Generate human-readable audit report"""
        
        report = []
        report.append("# JWT Security Audit Report")
        report.append(f"Generated: {self.audit_results['timestamp']}")
        report.append("")
        
        # Summary
        report.append("## Summary")
        report.append(f"**Security Score:** {self.audit_results['score']}/100")
        report.append(f"**Security Level:** {self.audit_results['security_level']}")
        report.append(f"**Total Issues:** {len(self.audit_results['issues'])}")
        report.append(f"**Total Recommendations:** {len(self.audit_results['recommendations'])}")
        report.append("")
        
        # Issues
        if self.audit_results["issues"]:
            report.append("## Security Issues")
            for i, issue in enumerate(self.audit_results["issues"], 1):
                report.append(f"{i}. ❌ {issue}")
            report.append("")
        
        # Recommendations
        if self.audit_results["recommendations"]:
            report.append("## Recommendations")
            for i, rec in enumerate(self.audit_results["recommendations"], 1):
                report.append(f"{i}. 💡 {rec}")
            report.append("")
        
        # Score Breakdown
        report.append("## Score Breakdown")
        components = [
            ("Secret Strength", self.audit_results.get("secret_score", 0), 50),
            ("Algorithm Restrictions", self.audit_results.get("algorithm_score", 0), 40),
            ("Token Expiration", self.audit_results.get("expiration_score", 0), 20),
            ("Payload Safety", self.audit_results.get("payload_score", 0), 20),
            ("Validation Settings", self.audit_results.get("validation_score", 0), 30),
            ("Key Management", self.audit_results.get("key_management_score", 0), 15),
            ("Rate Limiting", self.audit_results.get("rate_limiting_score", 0), 15)
        ]
        
        for component, score, max_score in components:
            percentage = (score / max_score) * 100 if max_score > 0 else 0
            report.append(f"- **{component}:** {score}/{max_score} ({percentage:.1f}%)")
        
        return "\n".join(report)

# Usage Example
def demonstrate_security_audit():
    print("\n=== JWT Security Audit Demo ===\n")
    
    auditor = JWTSecurityAuditor()
    
    # Example JWT configuration to audit
    jwt_config = {
        "secret_key": "my_very_secure_secret_key_32_chars_long",
        "allowed_algorithms": ["HS256", "RS256"],
        "access_token_expiry": 900,  # 15 minutes
        "payload_fields": ["user_id", "email", "roles", "permissions"],
        "validation_options": {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_iss": True,
            "verify_aud": True
        },
        "key_rotation": {
            "enabled": True,
            "interval_days": 30
        },
        "rate_limits": {
            "token_creation": {"requests_per_minute": 100},
            "token_validation": {"requests_per_minute": 1000},
            "refresh_attempts": {"requests_per_minute": 10}
        }
    }
    
    # Run audit
    audit_results = auditor.audit_jwt_configuration(jwt_config)
    
    # Generate and display report
    report = auditor.generate_audit_report()
    print(report)
    
    print("\n=== Audit Tool Benefits ===")
    print("✓ Automated security assessment")
    print("✓ Industry-standard best practices")
    print("✓ Actionable recommendations")
    print("✓ Quantified security scoring")
    print("✓ Compliance verification")

demonstrate_security_audit()
```

## Key Takeaways

1. **Strong Secret Management**: Use cryptographically random secrets, minimum 32 characters
2. **Algorithm Restrictions**: Always restrict allowed algorithms, never allow "none"
3. **Comprehensive Validation**: Validate all JWT claims and additional security checks
4. **Token Lifecycle Management**: Short access tokens with refresh mechanism
5. **Security Monitoring**: Track token usage, detect anomalies, and respond to violations

## Security Checklist

- [ ] Secret key is strong and randomly generated
- [ ] Algorithm is restricted and verified
- [ ] Token expiration is reasonable (< 1 hour)
- [ ] No sensitive data in payload
- [ ] All validation checks enabled
- [ ] Rate limiting implemented
- [ ] Session management and revocation capability
- [ ] Device fingerprinting for session binding
- [ ] Comprehensive logging and monitoring
- [ ] Regular security audits and key rotation

---

**Note**: This code is for educational purposes. In production, additional security measures, error handling, and compliance considerations should be implemented.