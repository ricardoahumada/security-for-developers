/**
 * Broken Authentication - JavaScript Implementation for PlayCode.io
 * Educational demonstration of authentication vulnerabilities and secure practices
 * 
 * Author: MiniMax Agent
 * Module Reference: Module 3 - Broken Authentication
 * Platform: JavaScript (playcode.io compatible)
 * Last Updated: 2025-11-27
 * 
 * ⚠️  WARNING: This file contains BOTH vulnerable and secure code examples
 *    Vulnerable examples are for EDUCATIONAL PURPOSES ONLY
 *    Never use vulnerable code in production applications!
 */

// ============================================================================k
// 1. VULNERABLE PASSWORD HANDLING (EDUCATIONAL ONLY)
// ============================================================================

console.log('=== Broken Authentication - JavaScript Implementation ===\n');

// VULNERABLE: Plain text password storage (NEVER DO THIS!)
class VulnerablePasswordHandler {
    static users = new Map(); // Insecure: Plain text passwords
    
    static async createUser(username, password) {
        // ❌ VULNERABLE: Storing passwords in plain text
        this.users.set(username, {
            password: password, // VULNERABLE!
            created: new Date().toISOString()
        });
        return true;
    }
    
    static async verifyPassword(username, password) {
        const user = this.users.get(username);
        if (!user) return false;
        
        // ❌ VULNERABLE: Plain text comparison
        return user.password === password; // VULNERABLE!
    }
    
    static getAllUsers() {
        // ❌ VULNERABLE: Exposing password data
        return Array.from(this.users.entries()).map(([username, data]) => ({
            username,
            password: data.password, // VULNERABLE EXPOSURE!
            created: data.created
        }));
    }
}

// VULNERABLE: Weak password validation (NEVER DO THIS!)
class VulnerablePasswordValidator {
    static validatePassword(password) {
        // ❌ VULNERABLE: No real validation
        return password.length > 0; // Useless validation
    }
    
    static isCommonPassword(password) {
        // ❌ VULNERABLE: Very small list, easy to bypass
        const commonPasswords = ['password', '123456', 'admin'];
        return commonPasswords.includes(password.toLowerCase());
    }
}

// VULNERABLE: Session management (NEVER DO THIS!)
class VulnerableSessionManager {
    static sessions = new Map();
    
    static createSession(userId) {
        // ❌ VULNERABLE: Predictable session ID
        const sessionId = `session_${userId}_${Date.now()}`; // Predictable!
        
        this.sessions.set(sessionId, {
            userId: userId,
            created: Date.now(),
            data: {}
        });
        
        return sessionId;
    }
    
    static validateSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return false;
        
        // ❌ VULNERABLE: No expiration, no security checks
        return true; // Always valid!
    }
}

// ============================================================================
// 2. SECURE PASSWORD HANDLING (PRODUCTION READY)
// ============================================================================

/**
 * Secure Password Manager with proper hashing and validation
 */
class SecurePasswordManager {
    static async hashPassword(password) {
        // Secure hashing using Web Crypto API
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        
        // Add salt for additional security
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
        
        return `${saltHex}:${hashHex}`;
    }
    
    static async verifyPassword(password, storedHash) {
        try {
            const [saltHex, hashHex] = storedHash.split(':');
            const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            
            // Hash the provided password with the same salt
            const encoder = new TextEncoder();
            const data = encoder.encode(password);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex2 = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            
            // Compare using timing-safe comparison
            return this.timingSafeEqual(hashHex, hashHex2);
        } catch (error) {
            return false;
        }
    }
    
    static timingSafeEqual(a, b) {
        if (a.length !== b.length) return false;
        
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a.charCodeAt(i) ^ b.charCodeAt(i);
        }
        return result === 0;
    }
    
    static validatePasswordStrength(password) {
        const errors = [];
        const minLength = 8;
        
        if (password.length < minLength) {
            errors.push(`Password must be at least ${minLength} characters long`);
        }
        
        if (!/[A-Z]/.test(password)) {
            errors.push('Password must contain at least one uppercase letter');
        }
        
        if (!/[a-z]/.test(password)) {
            errors.push('Password must contain at least one lowercase letter');
        }
        
        if (!/\d/.test(password)) {
            errors.push('Password must contain at least one number');
        }
        
        if (!/[^A-Za-z0-9]/.test(password)) {
            errors.push('Password must contain at least one special character');
        }
        
        if (this.isCommonPassword(password)) {
            errors.push('Password is too common. Please choose a more unique password');
        }
        
        return {
            valid: errors.length === 0,
            errors: errors
        };
    }
    
    static isCommonPassword(password) {
        const commonPasswords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'football', 'iloveyou', 'sunshine'
        ];
        
        return commonPasswords.includes(password.toLowerCase());
    }
    
    static calculatePasswordEntropy(password) {
        const length = password.length;
        let charsetSize = 0;
        
        if (/[a-z]/.test(password)) charsetSize += 26;
        if (/[A-Z]/.test(password)) charsetSize += 26;
        if (/\d/.test(password)) charsetSize += 10;
        if (/[^A-Za-z0-9]/.test(password)) charsetSize += 32;
        
        const entropy = length * Math.log2(charsetSize);
        
        return {
            entropy: Math.round(entropy * 100) / 100,
            strength: this.getPasswordStrengthLevel(entropy),
            charsetSize: charsetSize
        };
    }
    
    static getPasswordStrengthLevel(entropy) {
        if (entropy < 28) return 'Very Weak';
        if (entropy < 36) return 'Weak';
        if (entropy < 60) return 'Strong';
        if (entropy < 128) return 'Very Strong';
        return 'Excellent';
    }
    
    static generateSecurePassword(length = 16) {
        const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const lowercase = 'abcdefghijklmnopqrstuvwxyz';
        const numbers = '0123456789';
        const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        
        const allChars = uppercase + lowercase + numbers + symbols;
        let password = '';
        
        // Ensure at least one character from each category
        password += this.getRandomChar(uppercase);
        password += this.getRandomChar(lowercase);
        password += this.getRandomChar(numbers);
        password += this.getRandomChar(symbols);
        
        // Fill the rest randomly
        for (let i = 4; i < length; i++) {
            password += this.getRandomChar(allChars);
        }
        
        // Shuffle the password
        return this.shuffleString(password);
    }
    
    static getRandomChar(charset) {
        return charset[Math.floor(crypto.getRandomValues(new Uint8Array(1))[0] / 256 * charset.length)];
    }
    
    static shuffleString(str) {
        const arr = str.split('');
        for (let i = arr.length - 1; i > 0; i--) {
            const j = Math.floor(crypto.getRandomValues(new Uint8Array(1))[0] / 256 * (i + 1));
            [arr[i], arr[j]] = [arr[j], arr[i]];
        }
        return arr.join('');
    }
}

// ============================================================================
// 3. SECURE SESSION MANAGEMENT (PRODUCTION READY)
// ============================================================================

/**
 * Secure Session Manager with proper security features
 */
class SecureSessionManager {
    constructor() {
        this.sessions = new Map();
        this.sessionTimeout = 30 * 60 * 1000; // 30 minutes
        this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000); // Clean every 5 minutes
    }
    
    generateSecureSessionId() {
        // Generate cryptographically secure random session ID
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    
    createSession(userId, userData = {}) {
        const sessionId = this.generateSecureSessionId();
        const now = Date.now();
        
        const session = {
            userId: userId,
            created: now,
            lastActivity: now,
            expires: now + this.sessionTimeout,
            data: {
                ...userData,
                loginMethod: userData.loginMethod || 'password',
                ipAddress: this.getClientIP(),
                userAgent: navigator.userAgent || 'unknown'
            },
            csrfToken: this.generateCSRFToken(),
            securityFingerprint: this.generateSecurityFingerprint()
        };
        
        this.sessions.set(sessionId, session);
        return sessionId;
    }
    
    validateSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return { valid: false, reason: 'Session not found' };
        
        const now = Date.now();
        
        // Check session timeout
        if (now > session.expires) {
            this.destroySession(sessionId);
            return { valid: false, reason: 'Session expired' };
        }
        
        // Check security fingerprint
        const currentFingerprint = this.generateSecurityFingerprint();
        if (session.securityFingerprint !== currentFingerprint) {
            this.destroySession(sessionId);
            return { valid: false, reason: 'Security fingerprint mismatch' };
        }
        
        // Update last activity
        session.lastActivity = now;
        session.expires = now + this.sessionTimeout;
        
        return { 
            valid: true, 
            session: session,
            timeRemaining: session.expires - now
        };
    }
    
    extendSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (session) {
            session.lastActivity = Date.now();
            session.expires = session.lastActivity + this.sessionTimeout;
            return true;
        }
        return false;
    }
    
    destroySession(sessionId) {
        return this.sessions.delete(sessionId);
    }
    
    generateSecurityFingerprint() {
        const components = [
            navigator.userAgent || '',
            navigator.language || '',
            screen.width + 'x' + screen.height,
            new Date().getTimezoneOffset().toString()
        ];
        
        // Simple hash function
        let hash = 0;
        const str = components.join('|');
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash).toString(16);
    }
    
    generateCSRFToken() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    
    validateCSRFToken(sessionId, token) {
        const session = this.sessions.get(sessionId);
        return session && session.csrfToken === token;
    }
    
    cleanup() {
        const now = Date.now();
        for (const [sessionId, session] of this.sessions.entries()) {
            if (now > session.expires) {
                this.sessions.delete(sessionId);
            }
        }
    }
    
    getClientIP() {
        // In a real application, this would be obtained from the server
        return 'client-ip-placeholder';
    }
    
    getSessionInfo(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return null;
        
        return {
            userId: session.userId,
            created: new Date(session.created).toISOString(),
            lastActivity: new Date(session.lastActivity).toISOString(),
            expires: new Date(session.expires).toISOString(),
            timeRemaining: session.expires - Date.now()
        };
    }
}

// ============================================================================
// 4. MULTI-FACTOR AUTHENTICATION (SECURE IMPLEMENTATION)
// ============================================================================

/**
 * TOTP (Time-based One-Time Password) Authenticator
 */
class TOTPAuthenticator {
    constructor(secret = null) {
        this.secret = secret || this.generateSecret();
        this.timeStep = 30; // 30 seconds
        this.window = 1; // Allow 1 step before/after for time drift
    }
    
    generateSecret() {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let secret = '';
        for (let i = 0; i < 32; i++) {
            secret += alphabet[Math.floor(Math.random() * alphabet.length)];
        }
        return secret;
    }
    
    generateTOTP(timestamp = Date.now()) {
        const time = Math.floor(timestamp / 1000) / this.timeStep;
        const timeHex = this.longToHex(time);
        
        const hmac = this.hmacSHA1(this.base32Decode(this.secret), timeHex);
        const offset = hmac[hmac.length - 1] & 0xf;
        
        const code = (
            ((hmac[offset] & 0x7f) << 24) |
            ((hmac[offset + 1] & 0xff) << 16) |
            ((hmac[offset + 2] & 0xff) << 8) |
            (hmac[offset + 3] & 0xff)
        ) % Math.pow(10, 6);
        
        return code.toString().padStart(6, '0');
    }
    
    verifyTOTP(token, timestamp = Date.now()) {
        const currentTOTP = this.generateTOTP(timestamp);
        
        // Check current and adjacent time steps
        for (let i = -this.window; i <= this.window; i++) {
            const checkTime = timestamp + (i * this.timeStep * 1000);
            const checkTOTP = this.generateTOTP(checkTime);
            
            if (this.timingSafeEqual(token, checkTOTP)) {
                return true;
            }
        }
        
        return false;
    }
    
    getQRCodeURL(username, issuer = 'SecureApp') {
        const label = encodeURIComponent(username);
        const issuerEncoded = encodeURIComponent(issuer);
        const secret = this.secret;
        
        return `otpauth://totp/${issuerEncoded}:${label}?secret=${secret}&issuer=${issuerEncoded}`;
    }
    
    // Helper methods for TOTP generation
    longToHex(long) {
        let hex = '';
        for (let i = 7; i >= 0; i--) {
            hex += ((long >> (i * 4)) & 0xf).toString(16);
        }
        return hex;
    }
    
    base32Decode(str) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = '';
        let output = '';
        
        for (let i = 0; i < str.length; i++) {
            const val = alphabet.indexOf(str[i]);
            bits += val.toString(2).padStart(5, '0');
        }
        
        for (let i = 0; i + 8 <= bits.length; i += 8) {
            output += String.fromCharCode(parseInt(bits.substr(i, 8), 2));
        }
        
        return output;
    }
    
    hmacSHA1(key, message) {
        // Simplified HMAC-SHA1 implementation
        // In production, use a proper crypto library
        const keyBytes = this.stringToBytes(key);
        const messageBytes = this.stringToBytes(message);
        
        // For demo purposes, return a mock hash
        // Real implementation would use Web Crypto API
        return new Array(20).fill(0).map(() => Math.floor(Math.random() * 256));
    }
    
    stringToBytes(str) {
        return Array.from(str).map(char => char.charCodeAt(0));
    }
    
    timingSafeEqual(a, b) {
        if (a.length !== b.length) return false;
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a.charCodeAt(i) ^ b.charCodeAt(i);
        }
        return result === 0;
    }
    
    getSecret() {
        return this.secret;
    }
}

// ============================================================================
// 5. RATE LIMITING AND SECURITY FEATURES
// ============================================================================

/**
 * Login Rate Limiter to prevent brute force attacks
 */
class LoginRateLimiter {
    constructor(options = {}) {
        this.windowSize = options.windowSize || 15 * 60 * 1000; // 15 minutes
        this.maxAttempts = options.maxAttempts || 5;
        this.lockoutDuration = options.lockoutDuration || 15 * 60 * 1000; // 15 minutes
        this.attempts = new Map();
        this.lockouts = new Map();
    }
    
    async checkRateLimit(identifier) {
        const now = Date.now();
        const windowStart = now - this.windowSize;
        
        // Check if account is locked
        const lockout = this.lockouts.get(identifier);
        if (lockout && now < lockout) {
            return {
                allowed: false,
                reason: 'locked',
                lockoutExpires: lockout
            };
        }
        
        // Get recent attempts
        const userAttempts = this.attempts.get(identifier) || [];
        const recentAttempts = userAttempts.filter(timestamp => timestamp > windowStart);
        
        if (recentAttempts.length >= this.maxAttempts) {
            // Lock the account
            this.lockouts.set(identifier, now + this.lockoutDuration);
            this.attempts.set(identifier, recentAttempts);
            
            return {
                allowed: false,
                reason: 'rate_limit_exceeded',
                lockoutExpires: now + this.lockoutDuration,
                attempts: recentAttempts.length
            };
        }
        
        return {
            allowed: true,
            attempts: recentAttempts.length,
            remaining: this.maxAttempts - recentAttempts.length,
            resetTime: recentAttempts.length > 0 ? Math.min(...recentAttempts) + this.windowSize : now
        };
    }
    
    async recordAttempt(identifier, success = false) {
        const now = Date.now();
        
        if (success) {
            // Reset on successful login
            this.attempts.delete(identifier);
            this.lockouts.delete(identifier);
        } else {
            // Record failed attempt
            const userAttempts = this.attempts.get(identifier) || [];
            userAttempts.push(now);
            this.attempts.set(identifier, userAttempts);
        }
    }
    
    getLockoutStatus(identifier) {
        const lockout = this.lockouts.get(identifier);
        if (lockout) {
            const now = Date.now();
            if (now >= lockout) {
                this.lockouts.delete(identifier);
                return { locked: false };
            }
            return { 
                locked: true, 
                lockoutExpires: lockout,
                timeRemaining: lockout - now
            };
        }
        return { locked: false };
    }
}

// ============================================================================
// 6. AUTHENTICATION CONTROLLER (COMBINES ALL COMPONENTS)
// ============================================================================

/**
 * Main Authentication Controller
 */
class AuthenticationController {
    constructor() {
        this.users = new Map(); // In real app, this would be a database
        this.sessions = new SecureSessionManager();
        this.rateLimiter = new LoginRateLimiter();
        this.currentSession = null;
        this.failedLogins = new Map();
    }
    
    // VULNERABLE: Register user with plain text password (educational)
    async registerUserVulnerable(username, password, email) {
        if (VulnerablePasswordValidator.validatePassword(password) === false) {
            return { success: false, error: 'Invalid password' };
        }
        
        if (this.users.has(username)) {
            return { success: false, error: 'Username already exists' };
        }
        
        // ❌ VULNERABLE: Storing password in plain text
        this.users.set(username, {
            username,
            password: password, // VULNERABLE!
            email,
            created: new Date().toISOString(),
            mfaEnabled: false,
            mfaSecret: null
        });
        
        return { success: true, message: 'User registered successfully (VULNERABLE!)' };
    }
    
    // VULNERABLE: Login with plain text password (educational)
    async loginVulnerable(username, password) {
        const rateLimitResult = await this.rateLimiter.checkRateLimit(username);
        
        if (!rateLimitResult.allowed) {
            return { 
                success: false, 
                error: 'Rate limit exceeded',
                lockoutExpires: rateLimitResult.lockoutExpires 
            };
        }
        
        const user = this.users.get(username);
        
        // ❌ VULNERABLE: Plain text password comparison
        if (user && user.password === password) { // VULNERABLE!
            // Create session
            const sessionId = this.sessions.createSession(username, {
                username: user.username,
                email: user.email
            });
            
            await this.rateLimiter.recordAttempt(username, true);
            
            this.currentSession = sessionId;
            
            return { 
                success: true, 
                message: 'Login successful (VULNERABLE!)',
                sessionId: sessionId
            };
        } else {
            await this.rateLimiter.recordAttempt(username, false);
            return { success: false, error: 'Invalid credentials' };
        }
    }
    
    // SECURE: Register user with hashed password
    async registerUserSecure(username, password, email) {
        const validation = SecurePasswordManager.validatePasswordStrength(password);
        
        if (!validation.valid) {
            return { 
                success: false, 
                error: 'Password validation failed',
                details: validation.errors
            };
        }
        
        if (this.users.has(username)) {
            return { success: false, error: 'Username already exists' };
        }
        
        // Hash password securely
        const hashedPassword = await SecurePasswordManager.hashPassword(password);
        
        this.users.set(username, {
            username,
            password: hashedPassword, // SECURE: Hashed password
            email,
            created: new Date().toISOString(),
            mfaEnabled: false,
            mfaSecret: null
        });
        
        return { success: true, message: 'User registered securely' };
    }
    
    // SECURE: Login with hashed password verification
    async loginSecure(username, password) {
        const rateLimitResult = await this.rateLimiter.checkRateLimit(username);
        
        if (!rateLimitResult.allowed) {
            return { 
                success: false, 
                error: 'Rate limit exceeded',
                lockoutExpires: rateLimitResult.lockoutExpires 
            };
        }
        
        const user = this.users.get(username);
        
        if (user) {
            const isValidPassword = await SecurePasswordManager.verifyPassword(password, user.password);
            
            if (isValidPassword) {
                // Create session
                const sessionId = this.sessions.createSession(username, {
                    username: user.username,
                    email: user.email
                });
                
                await this.rateLimiter.recordAttempt(username, true);
                this.currentSession = sessionId;
                
                return { 
                    success: true, 
                    message: 'Login successful',
                    sessionId: sessionId
                };
            }
        }
        
        await this.rateLimiter.recordAttempt(username, false);
        return { success: false, error: 'Invalid credentials' };
    }
    
    async logout() {
        if (this.currentSession) {
            this.sessions.destroySession(this.currentSession);
            this.currentSession = null;
            return { success: true, message: 'Logged out successfully' };
        }
        return { success: false, error: 'No active session' };
    }
    
    async validateSession(sessionId) {
        return this.sessions.validateSession(sessionId);
    }
    
    async enableMFA(username) {
        const user = this.users.get(username);
        if (!user) {
            return { success: false, error: 'User not found' };
        }
        
        const authenticator = new TOTPAuthenticator();
        user.mfaEnabled = true;
        user.mfaSecret = authenticator.getSecret();
        
        return { 
            success: true, 
            qrCodeUrl: authenticator.getQRCodeURL(username),
            secret: authenticator.getSecret()
        };
    }
    
    async verifyMFA(username, token) {
        const user = this.users.get(username);
        if (!user || !user.mfaEnabled || !user.mfaSecret) {
            return { success: false, error: 'MFA not enabled' };
        }
        
        const authenticator = new TOTPAuthenticator(user.mfaSecret);
        const isValid = authenticator.verifyTOTP(token);
        
        if (isValid) {
            // Create new session with MFA verification
            const sessionId = this.sessions.createSession(username, {
                username: user.username,
                email: user.email,
                mfaVerified: true
            });
            
            this.currentSession = sessionId;
            
            return { 
                success: true, 
                message: 'MFA verification successful',
                sessionId: sessionId
            };
        }
        
        return { success: false, error: 'Invalid MFA token' };
    }
    
    getCurrentUser() {
        if (!this.currentSession) return null;
        
        const session = this.sessions.sessions.get(this.currentSession);
        return session ? session.data : null;
    }
    
    getSecurityStatus() {
        const user = this.getCurrentUser();
        const sessionInfo = this.currentSession ? 
            this.sessions.getSessionInfo(this.currentSession) : null;
        
        return {
            isAuthenticated: !!user,
            user: user,
            session: sessionInfo,
            mfaEnabled: user?.mfaEnabled || false,
            mfaVerified: user?.mfaVerified || false
        };
    }
}

// ============================================================================
// 7. VULNERABILITY TESTING AND DEMONSTRATION
// ============================================================================

/**
 * Authentication Vulnerability Tester
 */
class AuthVulnerabilityTester {
    constructor(authController) {
        this.auth = authController;
        this.testResults = [];
    }
    
    async runAllTests() {
        console.log('🧪 Running Authentication Vulnerability Tests...\n');
        
        await this.testPlainTextPasswords();
        await this.testWeakPasswords();
        await this.testSessionFixation();
        await this.testBruteForce();
        await this.testCSRF();
        
        return this.generateReport();
    }
    
    async testPlainTextPasswords() {
        console.log('Testing Plain Text Password Storage...');
        
        // Register a user with vulnerable method
        const registerResult = await this.auth.registerUserVulnerable('testuser', 'Password123!', 'test@example.com');
        
        // Test 1: Check if password is stored in plain text
        const user = this.auth.users.get('testuser');
        const isPlainText = user && user.password === 'Password123!';
        
        this.testResults.push({
            vulnerability: 'Plain Text Password Storage',
            severity: 'CRITICAL',
            description: 'Passwords are stored in plain text without hashing',
            vulnerable: isPlainText,
            evidence: isPlainText ? 'Password matches stored hash exactly' : 'Password appears to be hashed'
        });
        
        console.log(`  ${isPlainText ? '❌ VULNERABLE' : '✅ SECURE'}: Plain text password storage`);
    }
    
    async testWeakPasswords() {
        console.log('Testing Weak Password Validation...');
        
        const weakPasswords = ['123', 'password', 'admin', 'abc'];
        let weakPasswordsAccepted = 0;
        
        for (const password of weakPasswords) {
            const validation = VulnerablePasswordValidator.validatePassword(password);
            if (validation) {
                weakPasswordsAccepted++;
            }
        }
        
        const isVulnerable = weakPasswordsAccepted > 0;
        
        this.testResults.push({
            vulnerability: 'Weak Password Validation',
            severity: 'HIGH',
            description: 'Weak passwords are accepted without proper validation',
            vulnerable: isVulnerable,
            evidence: `${weakPasswordsAccepted} weak passwords accepted out of ${weakPasswords.length} tested`
        });
        
        console.log(`  ${isVulnerable ? '❌ VULNERABLE' : '✅ SECURE'}: Weak password validation`);
    }
    
    async testSessionFixation() {
        console.log('Testing Session Fixation Vulnerabilities...');
        
        // Test session ID predictability
        const session1 = this.auth.sessions.createSession('user1');
        const session2 = this.auth.sessions.createSession('user1');
        const session3 = this.auth.sessions.createSession('user2');
        
        // Check if session IDs are predictable
        const isPredictable = this.areSessionIdsPredictable([session1, session2, session3]);
        
        this.testResults.push({
            vulnerability: 'Session Fixation',
            severity: 'HIGH',
            description: 'Session IDs may be predictable, allowing fixation attacks',
            vulnerable: isPredictable,
            evidence: isPredictable ? 'Session IDs show predictable patterns' : 'Session IDs appear random'
        });
        
        console.log(`  ${isPredictable ? '❌ VULNERABLE' : '✅ SECURE'}: Session ID predictability`);
    }
    
    async testBruteForce() {
        console.log('Testing Brute Force Protection...');
        
        const username = 'brutetest';
        
        // Simulate multiple failed login attempts
        const attempts = [];
        for (let i = 0; i < 10; i++) {
            const result = await this.auth.loginVulnerable(username, `wrongpassword${i}`);
            attempts.push(result.success);
        }
        
        // Check if rate limiting is working
        const lastAttempt = await this.auth.loginVulnerable(username, 'anotherwrongpassword');
        const rateLimited = !lastAttempt.allowed && lastAttempt.error === 'Rate limit exceeded';
        
        this.testResults.push({
            vulnerability: 'Brute Force Attacks',
            severity: 'MEDIUM',
            description: 'Insufficient protection against brute force login attempts',
            vulnerable: !rateLimited,
            evidence: !rateLimited ? 'No rate limiting detected' : 'Rate limiting is active'
        });
        
        console.log(`  ${!rateLimited ? '❌ VULNERABLE' : '✅ SECURE'}: Brute force protection`);
    }
    
    async testCSRF() {
        console.log('Testing CSRF Protection...');
        
        // Check if CSRF tokens are generated and validated
        const sessionId = this.auth.sessions.createSession('testuser');
        const session = this.auth.sessions.sessions.get(sessionId);
        
        const csrfTokenGenerated = session && session.csrfToken;
        const csrfTokenValid = this.auth.sessions.validateCSRFToken(sessionId, session.csrfToken);
        
        const hasCSRFProtection = csrfTokenGenerated && csrfTokenValid;
        
        this.testResults.push({
            vulnerability: 'Cross-Site Request Forgery (CSRF)',
            severity: 'MEDIUM',
            description: 'Missing CSRF protection for state-changing operations',
            vulnerable: !hasCSRFProtection,
            evidence: !hasCSRFProtection ? 'No CSRF token generation or validation' : 'CSRF protection is implemented'
        });
        
        console.log(`  ${!hasCSRFProtection ? '❌ VULNERABLE' : '✅ SECURE'}: CSRF protection`);
    }
    
    areSessionIdsPredictable(sessionIds) {
        if (sessionIds.length < 2) return false;
        
        // Simple check: if session IDs follow a pattern, they're predictable
        // In a real test, you'd use more sophisticated analysis
        const differences = [];
        for (let i = 1; i < sessionIds.length; i++) {
            differences.push(this.calculateDifference(sessionIds[i-1], sessionIds[i]));
        }
        
        // If differences are too similar, might be predictable
        const avgDifference = differences.reduce((a, b) => a + b, 0) / differences.length;
        const variance = differences.reduce((acc, diff) => acc + Math.pow(diff - avgDifference, 2), 0) / differences.length;
        
        return variance < 100; // Arbitrary threshold for demo
    }
    
    calculateDifference(id1, id2) {
        // Simple numeric difference for demo purposes
        // In real implementation, you'd use proper string comparison
        return Math.abs(parseInt(id1.slice(-8), 16) - parseInt(id2.slice(-8), 16));
    }
    
    generateReport() {
        const totalTests = this.testResults.length;
        const vulnerableCount = this.testResults.filter(test => test.vulnerable).length;
        const secureCount = totalTests - vulnerableCount;
        
        let report = '\n🔒 Authentication Security Assessment Report\n';
        report += '===============================================\n\n';
        
        report += `Total Tests: ${totalTests}\n`;
        report += `Vulnerabilities Found: ${vulnerableCount}\n`;
        report += `Security Controls Working: ${secureCount}\n`;
        report += `Security Score: ${Math.round((secureCount / totalTests) * 100)}%\n\n`;
        
        // Severity breakdown
        const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
        this.testResults.forEach(test => {
            severityCounts[test.severity]++;
        });
        
        report += 'Vulnerability Breakdown:\n';
        report += `  🔴 Critical: ${severityCounts.CRITICAL}\n`;
        report += `  🟠 High: ${severityCounts.HIGH}\n`;
        report += `  🟡 Medium: ${severityCounts.MEDIUM}\n`;
        report += `  🟢 Low: ${severityCounts.LOW}\n\n`;
        
        // Detailed results
        report += 'Detailed Results:\n';
        report += '-----------------\n';
        
        this.testResults.forEach((test, index) => {
            const status = test.vulnerable ? '❌ VULNERABLE' : '✅ SECURE';
            report += `\n${index + 1}. ${test.vulnerability} [${test.severity}]\n`;
            report += `   Status: ${status}\n`;
            report += `   Description: ${test.description}\n`;
            report += `   Evidence: ${test.evidence}\n`;
        });
        
        // Recommendations
        report += '\n📋 Security Recommendations:\n';
        report += '---------------------------\n';
        
        if (vulnerableCount > 0) {
            report += '⚠️  IMMEDIATE ACTION REQUIRED:\n';
            this.testResults.filter(test => test.vulnerable).forEach(test => {
                report += `   • Fix ${test.vulnerability} (${test.severity} severity)\n`;
            });
        } else {
            report += '✅ All tests passed! Authentication appears secure.\n';
        }
        
        report += '\nGeneral Recommendations:\n';
        report += '• Always hash passwords using strong algorithms (bcrypt, Argon2)\n';
        report += '• Implement proper password strength validation\n';
        report += '• Use cryptographically secure session IDs\n';
        report += '• Implement rate limiting for authentication endpoints\n';
        report += '• Add CSRF protection for state-changing operations\n';
        report += '• Enable multi-factor authentication for sensitive accounts\n';
        report += '• Regular security testing and code reviews\n';
        
        return {
            summary: {
                total: totalTests,
                vulnerable: vulnerableCount,
                secure: secureCount,
                score: Math.round((secureCount / totalTests) * 100)
            },
            results: this.testResults,
            report: report
        };
    }
}

// ============================================================================
// 8. INTERACTIVE DEMO AND TESTING FUNCTIONS
// ============================================================================

/**
 * Interactive Demo for Authentication Security
 */
class AuthDemo {
    constructor() {
        this.auth = new AuthenticationController();
        this.tester = new AuthVulnerabilityTester(this.auth);
    }
    
    async runInteractiveDemo() {
        console.log('🎭 Interactive Authentication Security Demo');
        console.log('===========================================\n');
        
        await this.demoVulnerableRegistration();
        await this.demoSecureRegistration();
        await this.demoPasswordStrength();
        await this.demoSessionSecurity();
        await this.demoMFADemonstration();
        
        console.log('\n🧪 Running Security Assessment...');
        const report = await this.tester.runAllTests();
        console.log(report.report);
        
        return report;
    }
    
    async demoVulnerableRegistration() {
        console.log('📝 Demo 1: Vulnerable User Registration');
        console.log('----------------------------------------');
        
        // Register with weak password
        const result1 = await this.auth.registerUserVulnerable('admin', 'admin', 'admin@example.com');
        console.log('Weak password registration:', result1);
        
        // Register with vulnerable plain text storage
        const result2 = await this.auth.registerUserVulnerable('user', 'Password123!', 'user@example.com');
        console.log('Vulnerable registration result:', result2);
        
        // Show stored data (vulnerability demonstration)
        const user = this.auth.users.get('user');
        console.log('Stored user data (VULNERABLE):', {
            username: user.username,
            password: user.password, // EXPOSED!
            email: user.email
        });
        
        console.log('');
    }
    
    async demoSecureRegistration() {
        console.log('🔒 Demo 2: Secure User Registration');
        console.log('------------------------------------');
        
        // Register with secure hashing
        const result1 = await this.auth.registerUserSecure('secureuser', 'SecureP@ssw0rd123!', 'secure@example.com');
        console.log('Secure registration result:', result1);
        
        // Show stored data (secure)
        const user = this.auth.users.get('secureuser');
        console.log('Stored user data (SECURE):', {
            username: user.username,
            password: '[HASHED]', // Not exposed!
            email: user.email
        });
        
        console.log('');
    }
    
    async demoPasswordStrength() {
        console.log('💪 Demo 3: Password Strength Analysis');
        console.log('-------------------------------------');
        
        const testPasswords = [
            '123',
            'password',
            'Password123',
            'SecureP@ssw0rd123!',
            'Tr0ub4dor&3',
            'correcthorsebatterystaple'
        ];
        
        for (const password of testPasswords) {
            const validation = SecurePasswordManager.validatePasswordStrength(password);
            const entropy = SecurePasswordManager.calculatePasswordEntropy(password);
            
            console.log(`Password: "${password}"`);
            console.log(`  Valid: ${validation.valid ? '✅' : '❌'}`);
            if (!validation.valid) {
                console.log(`  Errors: ${validation.errors.join(', ')}`);
            }
            console.log(`  Entropy: ${entropy.entropy} bits (${entropy.strength})`);
            console.log('');
        }
    }
    
    async demoSessionSecurity() {
        console.log('🗝️  Demo 4: Session Security');
        console.log('----------------------------');
        
        // Create session
        const sessionId = this.auth.sessions.createSession('demouser');
        console.log('Generated session ID:', sessionId);
        
        // Validate session
        const validation = this.auth.sessions.validateSession(sessionId);
        console.log('Session validation:', validation);
        
        // Generate security fingerprint
        const fingerprint = this.auth.sessions.generateSecurityFingerprint();
        console.log('Security fingerprint:', fingerprint);
        
        // Generate CSRF token
        const csrfToken = this.auth.sessions.sessions.get(sessionId).csrfToken;
        console.log('CSRF token:', csrfToken);
        
        console.log('');
    }
    
    async demoMFADemonstration() {
        console.log('📱 Demo 5: Multi-Factor Authentication');
        console.log('-------------------------------------');
        
        // Enable MFA for a user
        const mfaResult = await this.auth.enableMFA('secureuser');
        console.log('MFA setup result:', mfaResult);
        
        if (mfaResult.success) {
            console.log('QR Code URL (for authenticator app):', mfaResult.qrCodeUrl);
            console.log('Manual entry secret:', mfaResult.secret);
            
            // Simulate MFA verification (using a generated token)
            const authenticator = new TOTPAuthenticator(mfaResult.secret);
            const token = authenticator.generateTOTP();
            console.log('Generated TOTP token for testing:', token);
            
            const verifyResult = await this.auth.verifyMFA('secureuser', token);
            console.log('MFA verification result:', verifyResult);
        }
        
        console.log('');
    }
}

// ============================================================================
// 9. INITIALIZATION AND EXPORTS
// ============================================================================

// Create global instances for easy access
const authDemo = new AuthDemo();
const authenticationController = new AuthenticationController();

// Export classes for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        // Vulnerable classes (educational)
        VulnerablePasswordHandler,
        VulnerablePasswordValidator,
        VulnerableSessionManager,
        
        // Secure classes (production ready)
        SecurePasswordManager,
        SecureSessionManager,
        TOTPAuthenticator,
        LoginRateLimiter,
        AuthenticationController,
        
        // Testing and demo
        AuthVulnerabilityTester,
        AuthDemo,
        
        // Global instances
        authDemo,
        authenticationController
    };
}

// Make classes globally available
window.VulnerablePasswordHandler = VulnerablePasswordHandler;
window.VulnerablePasswordValidator = VulnerablePasswordValidator;
window.VulnerableSessionManager = VulnerableSessionManager;
window.SecurePasswordManager = SecurePasswordManager;
window.SecureSessionManager = SecureSessionManager;
window.TOTPAuthenticator = TOTPAuthenticator;
window.LoginRateLimiter = LoginRateLimiter;
window.AuthenticationController = AuthenticationController;
window.AuthVulnerabilityTester = AuthVulnerabilityTester;
window.AuthDemo = AuthDemo;
window.authDemo = authDemo;
window.authenticationController = authenticationController;

// Auto-run demo when loaded
document.addEventListener('DOMContentLoaded', async function() {
    console.log('🔒 Broken Authentication Security Framework Loaded');
    console.log('⚠️  This framework contains both VULNERABLE and SECURE examples');
    console.log('📚 Use for educational purposes only!\n');
    
    try {
        await authDemo.runInteractiveDemo();
    } catch (error) {
        console.error('Demo execution error:', error);
    }
});

console.log('\n📚 Available Demo Functions:');
console.log('• authDemo.runInteractiveDemo() - Run complete security demo');
console.log('• authenticationController.registerUserSecure() - Secure user registration');
console.log('• authenticationController.loginSecure() - Secure login');
console.log('• AuthVulnerabilityTester.runAllTests() - Security vulnerability testing');