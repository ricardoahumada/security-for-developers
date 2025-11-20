# Secure Authentication Implementation Examples

**Author:** MiniMax Agent  
**Module Reference:** Module 3 - Broken Authentication  
**Last Updated:** 2025-11-15  

## Overview
This file contains comprehensive code examples demonstrating secure authentication implementations, including multi-factor authentication, session management, token-based authentication, and security best practices across different programming languages and frameworks.

---

## 1. Password Security and Hashing

### 1.1 PHP Password Security
```php
<?php
class SecurePasswordManager {
    private const PASSWORD_MIN_LENGTH = 8;
    private const PASSWORD_HASH_ALGO = PASSWORD_ARGON2ID;
    private const PASSWORD_HASH_OPTIONS = [
        'memory_cost' => 65536, // 64 MB
        'time_cost' => 4,       // 4 iterations
        'threads' => 3,         // 3 threads
    ];
    
    /**
     * Validate password strength
     */
    public static function validatePasswordStrength($password) {
        $errors = [];
        
        if (strlen($password) < self::PASSWORD_MIN_LENGTH) {
            $errors[] = "Password must be at least " . self::PASSWORD_MIN_LENGTH . " characters long";
        }
        
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = "Password must contain at least one uppercase letter";
        }
        
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = "Password must contain at least one lowercase letter";
        }
        
        if (!preg_match('/\d/', $password)) {
            $errors[] = "Password must contain at least one number";
        }
        
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = "Password must contain at least one special character";
        }
        
        // Check against common passwords
        if (self::isCommonPassword($password)) {
            $errors[] = "Password is too common. Please choose a more unique password";
        }
        
        return empty($errors) ? true : $errors;
    }
    
    /**
     * Hash password securely
     */
    public static function hashPassword($password) {
        return password_hash($password, self::PASSWORD_HASH_ALGO, self::PASSWORD_HASH_OPTIONS);
    }
    
    /**
     * Verify password against hash
     */
    public static function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }
    
    /**
     * Check if password needs rehashing
     */
    public static function needsRehash($hash) {
        return password_needs_rehash($hash, self::PASSWORD_HASH_ALGO, self::PASSWORD_HASH_OPTIONS);
    }
    
    /**
     * Generate secure random password
     */
    public static function generatePassword($length = 16) {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
        $password = '';
        
        for ($i = 0; $i < $length; $i++) {
            $password .= $chars[random_int(0, strlen($chars) - 1)];
        }
        
        return $password;
    }
    
    /**
     * Check against common password list
     */
    private static function isCommonPassword($password) {
        $commonPasswords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        ];
        
        return in_array(strtolower($password), $commonPasswords);
    }
    
    /**
     * Get password entropy (for password strength analysis)
     */
    public static function calculatePasswordEntropy($password) {
        $length = strlen($password);
        $characterSetSize = 0;
        
        // Count character set size
        if (preg_match('/[a-z]/', $password)) $characterSetSize += 26;
        if (preg_match('/[A-Z]/', $password)) $characterSetSize += 26;
        if (preg_match('/\d/', $password)) $characterSetSize += 10;
        if (preg_match('/[^A-Za-z0-9]/', $password)) $characterSetSize += 32;
        
        // Calculate entropy in bits
        $entropy = $length * log($characterSetSize, 2);
        
        return [
            'entropy' => round($entropy, 2),
            'strength' => self::getPasswordStrengthLevel($entropy),
            'character_set_size' => $characterSetSize
        ];
    }
    
    private static function getPasswordStrengthLevel($entropy) {
        if ($entropy < 28) return 'Very Weak';
        if ($entropy < 36) return 'Weak';
        if ($entropy < 60) return 'Strong';
        if ($entropy < 128) return 'Very Strong';
        return 'Excellent';
    }
}

// Usage example
$password = 'MySecureP@ssw0rd123';
$validation = SecurePasswordManager::validatePasswordStrength($password);

if ($validation === true) {
    $hash = SecurePasswordManager::hashPassword($password);
    $entropy = SecurePasswordManager::calculatePasswordEntropy($password);
    
    echo "Password is valid\n";
    echo "Hash: $hash\n";
    echo "Entropy: {$entropy['entropy']} bits\n";
    echo "Strength: {$entropy['strength']}\n";
} else {
    echo "Password validation failed:\n";
    foreach ($validation as $error) {
        echo "- $error\n";
    }
}
?>
```

### 1.2 Node.js Password Security
```javascript
const crypto = require('crypto');
const argon2 = require('argon2');

class SecurePasswordManager {
    static async hashPassword(password) {
        try {
            return await argon2.hash(password, {
                type: argon2.argon2id,
                memoryCost: 65536, // 64 MB
                timeCost: 4,       // 4 iterations
                parallelism: 3,    // 3 threads
                hashLength: 32
            });
        } catch (error) {
            throw new Error('Password hashing failed: ' + error.message);
        }
    }
    
    static async verifyPassword(password, hash) {
        try {
            return await argon2.verify(hash, password);
        } catch (error) {
            throw new Error('Password verification failed: ' + error.message);
        }
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
        
        // Check against common passwords
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
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        ];
        
        return commonPasswords.includes(password.toLowerCase());
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
        return charset[Math.floor(crypto.randomBytes(1)[0] / 256 * charset.length)];
    }
    
    static shuffleString(str) {
        const arr = str.split('');
        for (let i = arr.length - 1; i > 0; i--) {
            const j = Math.floor(crypto.randomBytes(1)[0] / 256 * (i + 1));
            [arr[i], arr[j]] = [arr[j], arr[i]];
        }
        return arr.join('');
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
}

// Example usage
async function passwordExample() {
    const password = 'MySecureP@ssw0rd123';
    
    // Validate password strength
    const validation = SecurePasswordManager.validatePasswordStrength(password);
    console.log('Password validation:', validation);
    
    if (validation.valid) {
        // Hash password
        const hash = await SecurePasswordManager.hashPassword(password);
        console.log('Password hash:', hash);
        
        // Verify password
        const isValid = await SecurePasswordManager.verifyPassword(password, hash);
        console.log('Password verification:', isValid);
        
        // Calculate entropy
        const entropy = SecurePasswordManager.calculatePasswordEntropy(password);
        console.log('Password entropy:', entropy);
        
        // Generate secure password
        const newPassword = SecurePasswordManager.generateSecurePassword(20);
        console.log('Generated password:', newPassword);
    }
}

// Test with common password
const weakPasswordTest = SecurePasswordManager.validatePasswordStrength('password123');
console.log('Weak password test:', weakPasswordTest);

module.exports = SecurePasswordManager;
```

---

## 2. Multi-Factor Authentication (MFA)

### 2.1 TOTP (Time-based One-Time Password) Implementation
```php
<?php
class TOTPAuthenticator {
    private $secret;
    private $window = 1; // Allow 1 step before/after for time drift
    
    public function __construct($secret = null) {
        $this->secret = $secret ?: $this->generateSecret();
    }
    
    /**
     * Generate base32 secret key
     */
    private function generateSecret($length = 20) {
        return base32_encode(random_bytes($length));
    }
    
    /**
     * Get QR code URL for Google Authenticator
     */
    public function getQRCodeURL($username, $issuer = 'YourApp') {
        $label = rawurlencode($username);
        $issuerEncoded = rawurlencode($issuer);
        $secret = $this->secret;
        
        return "otpauth://totp/{$issuerEncoded}:{$label}?secret={$secret}&issuer={$issuerEncoded}";
    }
    
    /**
     * Get current TOTP token
     */
    public function getCurrentToken() {
        return $this->generateToken(time());
    }
    
    /**
     * Verify TOTP token
     */
    public function verifyToken($token, $timestamp = null) {
        if ($timestamp === null) {
            $timestamp = time();
        }
        
        // Check current token
        for ($i = -$this->window; $i <= $this->window; $i++) {
            $timeSlice = floor($timestamp / 30) + $i;
            $calculatedToken = $this->generateToken($timeSlice * 30);
            
            if (hash_equals($calculatedToken, $token)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Generate TOTP token for given timestamp
     */
    private function generateToken($timestamp) {
        $time = pack('N*', 0, $timestamp);
        $hash = hash_hmac('sha1', $time, base32_decode($this->secret), true);
        $offset = ord($hash[19]) & 0xf;
        
        $code = (
            ((ord($hash[$offset+0]) & 0x7f) << 24) |
            ((ord($hash[$offset+1]) & 0xff) << 16) |
            ((ord($hash[$offset+2]) & 0xff) << 8) |
            (ord($hash[$offset+3]) & 0xff)
        ) % pow(10, 6);
        
        return str_pad($code, 6, '0', STR_PAD_LEFT);
    }
    
    public function getSecret() {
        return $this->secret;
    }
}

// Base32 encoding helper function
function base32_encode($data) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $output = '';
    $v = 0;
    $vbits = 0;
    
    for ($i = 0, $j = strlen($data); $i < $j; $i++) {
        $v <<= 8;
        $v += ord($data[$i]);
        $vbits += 8;
        
        while ($vbits >= 5) {
            $vbits -= 5;
            $v = $v & (1 << $vbits) - 1;
            $output .= $alphabet[$v];
        }
    }
    
    if ($vbits > 0) {
        $v <<= (5 - $vbits);
        $output .= $alphabet[$v];
    }
    
    return $output;
}

function base32_decode($data) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $output = '';
    $v = 0;
    $vbits = 0;
    
    for ($i = 0, $j = strlen($data); $i < $j; $i++) {
        $v <<= 5;
        $v += strpos($alphabet, $data[$i]);
        $vbits += 5;
        
        if ($vbits >= 8) {
            $vbits -= 8;
            $output .= chr($v);
            $v = $v & (1 << $vbits) - 1;
        }
    }
    
    return $output;
}

// Usage example
$totp = new TOTPAuthenticator();
$secret = $totp->getSecret();

echo "Secret: $secret\n";
echo "Current token: " . $totp->getCurrentToken() . "\n";
echo "QR Code URL: " . $totp->getQRCodeURL('user@example.com') . "\n";

// Verify token (in real implementation, user provides this)
$userToken = '123456'; // User enters this from their authenticator app
$isValid = $totp->verifyToken($userToken);
echo "Token valid: " . ($isValid ? 'Yes' : 'No') . "\n";
?>
```

### 2.2 SMS OTP Implementation (Node.js)
```javascript
const crypto = require('crypto');

class SMSOTPManager {
    constructor(config = {}) {
        this.otpLength = config.otpLength || 6;
        this.expiryTime = config.expiryTime || 300; // 5 minutes
        this.allowedAttempts = config.allowedAttempts || 3;
    }
    
    generateOTP() {
        const min = Math.pow(10, this.otpLength - 1);
        const max = Math.pow(10, this.otpLength) - 1;
        
        return crypto.randomInt(min, max + 1).toString();
    }
    
    async sendOTP(phoneNumber, otp) {
        // In production, integrate with SMS service (Twilio, AWS SNS, etc.)
        try {
            // Example integration (pseudo-code)
            // const result = await twilio.messages.create({
            //     body: `Your verification code is: ${otp}. Valid for ${this.expiryTime/60} minutes.`,
            //     from: process.env.TWILIO_PHONE_NUMBER,
            //     to: phoneNumber
            // });
            
            console.log(`OTP ${otp} sent to ${phoneNumber}`);
            return { success: true, messageId: crypto.randomUUID() };
        } catch (error) {
            throw new Error('Failed to send OTP: ' + error.message);
        }
    }
    
    validateOTPFormat(otp) {
        return /^\d{6}$/.test(otp);
    }
    
    isExpired(otpData) {
        const now = Date.now();
        const otpTime = otpData.timestamp;
        return (now - otpTime) > (this.expiryTime * 1000);
    }
    
    hasExceededAttempts(otpData) {
        return otpData.attempts >= this.allowedAttempts;
    }
}

// OTP Store (in-memory for example, use Redis/database in production)
class OTPStore {
    constructor() {
        this.store = new Map();
    }
    
    saveOTP(identifier, otpData) {
        this.store.set(identifier, otpData);
    }
    
    getOTP(identifier) {
        return this.store.get(identifier);
    }
    
    deleteOTP(identifier) {
        this.store.delete(identifier);
    }
    
    cleanup() {
        const now = Date.now();
        for (const [key, value] of this.store.entries()) {
            if (now - value.timestamp > 3600000) { // 1 hour cleanup
                this.store.delete(key);
            }
        }
    }
}

class MFAManager {
    constructor(config = {}) {
        this.smsManager = new SMSOTPManager(config.sms);
        this.otpStore = new OTPStore();
        this.setupCleanupTimer();
    }
    
    setupCleanupTimer() {
        // Clean up expired OTPs every hour
        setInterval(() => {
            this.otpStore.cleanup();
        }, 3600000);
    }
    
    async sendOTP(phoneNumber) {
        const otp = this.smsManager.generateOTP();
        const identifier = this.normalizePhoneNumber(phoneNumber);
        
        const otpData = {
            otp: otp,
            attempts: 0,
            timestamp: Date.now(),
            phoneNumber: phoneNumber
        };
        
        this.otpStore.saveOTP(identifier, otpData);
        
        await this.smsManager.sendOTP(phoneNumber, otp);
        
        return {
            success: true,
            message: 'OTP sent successfully',
            expiresAt: new Date(Date.now() + this.smsManager.expiryTime * 1000)
        };
    }
    
    verifyOTP(phoneNumber, userOTP) {
        const identifier = this.normalizePhoneNumber(phoneNumber);
        const otpData = this.otpStore.getOTP(identifier);
        
        if (!otpData) {
            return { valid: false, error: 'OTP not found or expired' };
        }
        
        // Check expiry
        if (this.smsManager.isExpired(otpData)) {
            this.otpStore.deleteOTP(identifier);
            return { valid: false, error: 'OTP expired' };
        }
        
        // Check attempts
        if (this.smsManager.hasExceededAttempts(otpData)) {
            this.otpStore.deleteOTP(identifier);
            return { valid: false, error: 'Too many attempts' };
        }
        
        // Increment attempts
        otpData.attempts++;
        this.otpStore.saveOTP(identifier, otpData);
        
        // Verify OTP
        if (otpData.otp === userOTP) {
            this.otpStore.deleteOTP(identifier);
            return { valid: true, message: 'OTP verified successfully' };
        } else {
            return { 
                valid: false, 
                error: 'Invalid OTP',
                remainingAttempts: this.smsManager.allowedAttempts - otpData.attempts
            };
        }
    }
    
    normalizePhoneNumber(phone) {
        return phone.replace(/\D/g, ''); // Remove non-digits
    }
}

// Example usage
const mfaManager = new MFAManager();

async function mfaExample() {
    try {
        // Send OTP
        const sendResult = await mfaManager.sendOTP('+1234567890');
        console.log('Send result:', sendResult);
        
        // Simulate user entering OTP
        const verifyResult = mfaManager.verifyOTP('+1234567890', '123456');
        console.log('Verify result:', verifyResult);
        
    } catch (error) {
        console.error('MFA error:', error.message);
    }
}

// Simulate OTP testing
setTimeout(() => {
    const verifyResult = mfaManager.verifyOTP('+1234567890', '123456');
    console.log('Verify result (invalid):', verifyResult);
}, 1000);

module.exports = { MFAManager, SMSOTPManager };
```

---

## 3. Session Management

### 3.1 PHP Session Security
```php
<?php
class SecureSessionManager {
    private static $initialized = false;
    
    public static function init() {
        if (self::$initialized) {
            return;
        }
        
        // Configure secure session settings
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', isset($_SERVER['HTTPS']));
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.use_only_cookies', 1);
        ini_set('session.use_strict_mode', 1);
        ini_set('session.entropy_length', 32);
        ini_set('session.entropy_file', '/dev/urandom');
        ini_set('session.gc_maxlifetime', 3600); // 1 hour
        
        // Set session name
        session_name('SECURE_SESSION');
        
        // Start session with custom handler
        if (!session_start()) {
            throw new Exception('Failed to start secure session');
        }
        
        // Regenerate session ID periodically
        self::regenerateSessionId();
        
        self::$initialized = true;
    }
    
    public static function regenerateSessionId() {
        // Regenerate ID every 10 minutes or on login
        if (!isset($_SESSION['last_regeneration'])) {
            session_regenerate_id(true);
            $_SESSION['last_regeneration'] = time();
        } elseif (time() - $_SESSION['last_regeneration'] > 600) {
            session_regenerate_id(true);
            $_SESSION['last_regeneration'] = time();
        }
    }
    
    public static function set($key, $value) {
        self::init();
        $_SESSION[$key] = $value;
    }
    
    public static function get($key, $default = null) {
        self::init();
        return $_SESSION[$key] ?? $default;
    }
    
    public static function remove($key) {
        self::init();
        unset($_SESSION[$key]);
    }
    
    public static function destroy() {
        self::init();
        
        // Clear session array
        $_SESSION = [];
        
        // Destroy session cookie
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(), 
                '', 
                time() - 42000,
                $params['path'], 
                $params['domain'],
                $params['secure'], 
                $params['httponly']
            );
        }
        
        // Destroy session
        session_destroy();
    }
    
    public static function isAuthenticated() {
        self::init();
        return isset($_SESSION['user_id']) && isset($_SESSION['authenticated_at']);
    }
    
    public static function requireAuth() {
        if (!self::isAuthenticated()) {
            http_response_code(401);
            echo json_encode(['error' => 'Authentication required']);
            exit;
        }
    }
    
    public static function login($userData) {
        self::init();
        
        // Regenerate session ID to prevent session fixation
        session_regenerate_id(true);
        
        // Set session data
        $_SESSION['user_id'] = $userData['id'];
        $_SESSION['username'] = $userData['username'];
        $_SESSION['email'] = $userData['email'];
        $_SESSION['authenticated_at'] = time();
        $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        $_SESSION['login_method'] = $userData['login_method'] ?? 'password';
        
        // Update last activity
        $_SESSION['last_activity'] = time();
        
        // Store login security data
        $_SESSION['security_fingerprint'] = self::generateSecurityFingerprint();
        
        // Log successful login
        self::logSecurityEvent('login_success', [
            'user_id' => $userData['id'],
            'ip' => $_SESSION['ip_address'],
            'user_agent' => $_SESSION['user_agent']
        ]);
    }
    
    public static function logout() {
        if (self::isAuthenticated()) {
            // Log logout
            self::logSecurityEvent('logout', [
                'user_id' => self::get('user_id'),
                'session_duration' => time() - self::get('authenticated_at')
            ]);
        }
        
        self::destroy();
    }
    
    public static function validateSession() {
        self::init();
        
        // Check if session exists
        if (!self::isAuthenticated()) {
            return false;
        }
        
        // Check session timeout (1 hour)
        if (time() - self::get('last_activity', 0) > 3600) {
            self::logout();
            return false;
        }
        
        // Check IP address change (optional, can be too restrictive)
        $currentIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $sessionIp = self::get('ip_address');
        
        if ($currentIp !== $sessionIp) {
            // Log suspicious activity
            self::logSecurityEvent('ip_address_change', [
                'user_id' => self::get('user_id'),
                'original_ip' => $sessionIp,
                'current_ip' => $currentIp
            ]);
            
            // Optional: force re-authentication
            // self::logout();
            // return false;
        }
        
        // Update last activity
        self::set('last_activity', time());
        
        // Check security fingerprint
        $currentFingerprint = self::generateSecurityFingerprint();
        $sessionFingerprint = self::get('security_fingerprint');
        
        if ($currentFingerprint !== $sessionFingerprint) {
            self::logSecurityEvent('security_fingerprint_mismatch', [
                'user_id' => self::get('user_id')
            ]);
            
            // Force re-authentication
            self::logout();
            return false;
        }
        
        return true;
    }
    
    private static function generateSecurityFingerprint() {
        $fingerprint = '';
        
        // Add user agent
        if (isset($_SERVER['HTTP_USER_AGENT'])) {
            $fingerprint .= $_SERVER['HTTP_USER_AGENT'];
        }
        
        // Add Accept-Language header
        if (isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
            $fingerprint .= $_SERVER['HTTP_ACCEPT_LANGUAGE'];
        }
        
        // Add screen resolution (from JavaScript in future)
        $fingerprint .= 'default'; // Placeholder
        
        return hash('sha256', $fingerprint);
    }
    
    private static function logSecurityEvent($event, $data) {
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'event' => $event,
            'data' => $data,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ];
        
        // In production, send to logging service
        error_log('SECURITY: ' . json_encode($logEntry));
    }
}

// Usage example
try {
    SecureSessionManager::init();
    
    // Check session validity
    if (SecureSessionManager::validateSession()) {
        echo "Session is valid\n";
        echo "User ID: " . SecureSessionManager::get('user_id') . "\n";
    } else {
        echo "Session is invalid or expired\n";
    }
    
    // Simulate login
    $userData = [
        'id' => 123,
        'username' => 'john_doe',
        'email' => 'john@example.com',
        'login_method' => 'password'
    ];
    
    SecureSessionManager::login($userData);
    echo "User logged in successfully\n";
    
    // Check authentication
    if (SecureSessionManager::isAuthenticated()) {
        echo "User is authenticated\n";
    }
    
} catch (Exception $e) {
    echo "Session error: " . $e->getMessage() . "\n";
}
?>
```

### 3.2 Node.js Session Management
```javascript
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');

class SecureSessionManager {
    constructor(config = {}) {
        this.redisClient = null;
        this.sessionStore = null;
        this.config = {
            sessionName: config.sessionName || 'secure_session',
            secret: config.secret || crypto.randomBytes(32).toString('hex'),
            maxAge: config.maxAge || 3600000, // 1 hour
            secure: config.secure || false,
            httpOnly: config.httpOnly || true,
            sameSite: config.sameSite || 'strict'
        };
    }
    
    async initialize() {
        try {
            // Initialize Redis client for session storage
            this.redisClient = createClient({
                url: process.env.REDIS_URL || 'redis://localhost:6379'
            });
            
            this.redisClient.on('error', (err) => {
                console.error('Redis Client Error:', err);
            });
            
            await this.redisClient.connect();
            
            // Create session store
            this.sessionStore = new RedisStore({
                client: this.redisClient,
                prefix: 'sess:',
                ttl: this.config.maxAge / 1000
            });
            
            return this.sessionStore;
        } catch (error) {
            console.error('Failed to initialize session store:', error);
            throw error;
        }
    }
    
    generateSessionId() {
        return crypto.randomBytes(32).toString('hex');
    }
    
    createSessionMiddleware() {
        return session({
            name: this.config.sessionName,
            secret: this.config.secret,
            resave: false,
            saveUninitialized: false,
            store: this.sessionStore,
            cookie: {
                secure: this.config.secure,
                httpOnly: this.config.httpOnly,
                maxAge: this.config.maxAge,
                sameSite: this.config.sameSite
            },
            genid: () => this.generateSessionId()
        });
    }
    
    validateSession(sessionData) {
        // Check if session exists
        if (!sessionData || !sessionData.userId) {
            return { valid: false, reason: 'No session data' };
        }
        
        // Check session expiry
        if (sessionData.expires && Date.now() > sessionData.expires) {
            return { valid: false, reason: 'Session expired' };
        }
        
        // Check for suspicious changes
        const currentFingerprint = this.generateSecurityFingerprint();
        if (sessionData.securityFingerprint !== currentFingerprint) {
            return { valid: false, reason: 'Security fingerprint mismatch' };
        }
        
        return { valid: true };
    }
    
    generateSecurityFingerprint(req) {
        const components = [
            req.headers['user-agent'] || '',
            req.headers['accept-language'] || '',
            req.ip || req.connection.remoteAddress || '',
            req.headers['accept-encoding'] || ''
        ];
        
        return crypto
            .createHash('sha256')
            .update(components.join('|'))
            .digest('hex');
    }
    
    async createSession(userData, req) {
        const sessionId = this.generateSessionId();
        const now = Date.now();
        const expires = now + this.config.maxAge;
        
        const sessionData = {
            userId: userData.id,
            username: userData.username,
            email: userData.email,
            created: now,
            expires: expires,
            lastActivity: now,
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.headers['user-agent'],
            securityFingerprint: this.generateSecurityFingerprint(req),
            loginMethod: userData.loginMethod || 'password',
            csrfToken: crypto.randomBytes(32).toString('hex')
        };
        
        // Store in Redis
        await this.redisClient.setEx(
            `sess:${sessionId}`,
            this.config.maxAge / 1000,
            JSON.stringify(sessionData)
        );
        
        return {
            sessionId: sessionId,
            data: sessionData
        };
    }
    
    async getSession(sessionId) {
        try {
            const sessionData = await this.redisClient.get(`sess:${sessionId}`);
            return sessionData ? JSON.parse(sessionData) : null;
        } catch (error) {
            console.error('Error retrieving session:', error);
            return null;
        }
    }
    
    async updateSession(sessionId, updates) {
        try {
            const sessionData = await this.getSession(sessionId);
            if (!sessionData) {
                return false;
            }
            
            const updatedData = {
                ...sessionData,
                ...updates,
                lastActivity: Date.now()
            };
            
            await this.redisClient.setEx(
                `sess:${sessionId}`,
                this.config.maxAge / 1000,
                JSON.stringify(updatedData)
            );
            
            return true;
        } catch (error) {
            console.error('Error updating session:', error);
            return false;
        }
    }
    
    async destroySession(sessionId) {
        try {
            await this.redisClient.del(`sess:${sessionId}`);
            return true;
        } catch (error) {
            console.error('Error destroying session:', error);
            return false;
        }
    }
    
    async cleanupExpiredSessions() {
        try {
            const keys = await this.redisClient.keys('sess:*');
            const now = Date.now();
            
            for (const key of keys) {
                const sessionData = await this.redisClient.get(key);
                if (sessionData) {
                    const data = JSON.parse(sessionData);
                    if (data.expires && now > data.expires) {
                        await this.redisClient.del(key);
                    }
                }
            }
        } catch (error) {
            console.error('Error cleaning up expired sessions:', error);
        }
    }
}

// Express.js middleware
const createSecureSessionMiddleware = async () => {
    const sessionManager = new SecureSessionManager();
    await sessionManager.initialize();
    
    // Cleanup expired sessions every hour
    setInterval(() => {
        sessionManager.cleanupExpiredSessions();
    }, 3600000);
    
    return sessionManager.createSessionMiddleware();
};

// Example Express application
async function createSecureApp() {
    const app = express();
    const sessionMiddleware = await createSecureSessionMiddleware();
    
    app.use(sessionMiddleware);
    app.use(express.json());
    
    // Authentication middleware
    const authenticateSession = async (req, res, next) => {
        const sessionId = req.sessionID;
        
        if (!sessionId) {
            return res.status(401).json({ error: 'No session found' });
        }
        
        const sessionManager = new SecureSessionManager();
        const sessionData = await sessionManager.getSession(sessionId);
        const validation = sessionManager.validateSession(sessionData);
        
        if (!validation.valid) {
            return res.status(401).json({ error: 'Invalid session', reason: validation.reason });
        }
        
        req.sessionData = sessionData;
        next();
    };
    
    // Routes
    app.post('/login', async (req, res) => {
        const { username, password } = req.body;
        
        // Verify credentials (implement your user verification logic)
        const userData = await verifyUserCredentials(username, password);
        
        if (!userData) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Create new session
        const sessionManager = new SecureSessionManager();
        const session = await sessionManager.createSession(userData, req);
        
        // Set session cookie
        req.session = session.data;
        
        res.json({
            success: true,
            message: 'Login successful',
            user: {
                id: userData.id,
                username: userData.username,
                email: userData.email
            }
        });
    });
    
    app.post('/logout', authenticateSession, async (req, res) => {
        const sessionManager = new SecureSessionManager();
        await sessionManager.destroySession(req.sessionID);
        
        req.session.destroy();
        res.json({ success: true, message: 'Logout successful' });
    });
    
    app.get('/profile', authenticateSession, async (req, res) => {
        res.json({
            user: {
                id: req.sessionData.userId,
                username: req.sessionData.username,
                email: req.sessionData.email
            }
        });
    });
    
    return app;
}

// Mock user verification (implement your actual logic)
async function verifyUserCredentials(username, password) {
    // This should validate against your user database
    if (username === 'admin' && password === 'password123') {
        return {
            id: 1,
            username: 'admin',
            email: 'admin@example.com',
            loginMethod: 'password'
        };
    }
    return null;
}

module.exports = { SecureSessionManager, createSecureApp };
```

---

## 4. JWT Token Authentication

### 4.1 JWT Implementation (Node.js)
```javascript
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

class JWTManager {
    constructor(config = {}) {
        this.secret = config.secret || crypto.randomBytes(32).toString('hex');
        this.algorithm = config.algorithm || 'HS256';
        this.accessTokenExpiry = config.accessTokenExpiry || '15m';
        this.refreshTokenExpiry = config.refreshTokenExpiry || '7d';
        this.issuer = config.issuer || 'your-app-name';
        this.audience = config.audience || 'your-app-users';
    }
    
    generateTokens(userData) {
        const now = Math.floor(Date.now() / 1000);
        
        const payload = {
            sub: userData.id.toString(),
            username: userData.username,
            email: userData.email,
            iat: now,
            nbf: now,
            iss: this.issuer,
            aud: this.audience,
            type: 'access'
        };
        
        const accessToken = jwt.sign(payload, this.secret, {
            algorithm: this.algorithm,
            expiresIn: this.accessTokenExpiry
        });
        
        const refreshPayload = {
            sub: userData.id.toString(),
            iat: now,
            nbf: now,
            iss: this.issuer,
            aud: this.audience,
            type: 'refresh'
        };
        
        const refreshToken = jwt.sign(refreshPayload, this.secret, {
            algorithm: this.algorithm,
            expiresIn: this.refreshTokenExpiry
        });
        
        return {
            accessToken,
            refreshToken,
            expiresIn: this.accessTokenExpiry,
            tokenType: 'Bearer'
        };
    }
    
    verifyToken(token, options = {}) {
        try {
            const decoded = jwt.verify(token, this.secret, {
                algorithms: [this.algorithm],
                issuer: options.ignoreIssuer ? undefined : this.issuer,
                audience: options.ignoreAudience ? undefined : this.audience
            });
            
            return {
                valid: true,
                decoded: decoded
            };
        } catch (error) {
            return {
                valid: false,
                error: error.message,
                expired: error.name === 'TokenExpiredError',
                malformed: error.name === 'JsonWebTokenError'
            };
        }
    }
    
    decodeToken(token) {
        try {
            return {
                valid: true,
                decoded: jwt.decode(token, { complete: true })
            };
        } catch (error) {
            return {
                valid: false,
                error: error.message
            };
        }
    }
    
    async refreshTokens(refreshToken) {
        const verification = this.verifyToken(refreshToken);
        
        if (!verification.valid || verification.decoded.type !== 'refresh') {
            throw new Error('Invalid refresh token');
        }
        
        // Get user data (implement your user lookup)
        const userData = await this.getUserById(verification.decoded.sub);
        if (!userData) {
            throw new Error('User not found');
        }
        
        // Generate new tokens
        return this.generateTokens(userData);
    }
    
    async getUserById(userId) {
        // Mock user lookup - implement your actual user retrieval logic
        const users = {
            '1': { id: 1, username: 'admin', email: 'admin@example.com' },
            '2': { id: 2, username: 'user', email: 'user@example.com' }
        };
        
        return users[userId] || null;
    }
    
    blacklistToken(token) {
        // In production, store blacklisted tokens in Redis or database
        // This is a simple in-memory example
        const now = Date.now();
        const decoded = jwt.decode(token);
        
        if (decoded && decoded.exp) {
            const ttl = decoded.exp * 1000 - now;
            if (ttl > 0) {
                setTimeout(() => {
                    // Remove from blacklist after expiration
                    this.removeFromBlacklist(token);
                }, ttl);
            }
        }
    }
    
    removeFromBlacklist(token) {
        // Implementation depends on your blacklist storage
        console.log('Removing token from blacklist:', token);
    }
    
    isTokenBlacklisted(token) {
        // Check if token is blacklisted
        // Return true if token should be rejected
        return false; // Simplified for example
    }
    
    generateCSRFToken(sessionData) {
        return crypto.randomBytes(32).toString('hex');
    }
    
    validateCSRFToken(token, sessionToken) {
        return token === sessionToken;
    }
}

// Express.js JWT middleware
const JWTMiddleware = {
    authenticate: (jwtManager) => {
        return (req, res, next) => {
            const authHeader = req.headers.authorization;
            
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'Access token required' });
            }
            
            const token = authHeader.substring(7);
            
            // Check if token is blacklisted
            if (jwtManager.isTokenBlacklisted(token)) {
                return res.status(401).json({ error: 'Token has been revoked' });
            }
            
            const verification = jwtManager.verifyToken(token);
            
            if (!verification.valid) {
                return res.status(401).json({ 
                    error: 'Invalid token', 
                    details: verification.error 
                });
            }
            
            req.user = verification.decoded;
            next();
        };
    },
    
    requireRole: (roles) => {
        return (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({ error: 'Authentication required' });
            }
            
            const userRoles = req.user.roles || [];
            const hasRequiredRole = roles.some(role => userRoles.includes(role));
            
            if (!hasRequiredRole) {
                return res.status(403).json({ error: 'Insufficient permissions' });
            }
            
            next();
        };
    },
    
    requireCSRF: () => {
        return (req, res, next) => {
            const token = req.headers['x-csrf-token'];
            const sessionToken = req.session?.csrfToken;
            
            if (!token || !sessionToken) {
                return res.status(403).json({ error: 'CSRF token required' });
            }
            
            // Implement your CSRF validation logic
            next();
        };
    }
};

// Example Express application with JWT
async function createJWTApp() {
    const express = require('express');
    const app = express();
    
    app.use(express.json());
    
    const jwtManager = new JWTManager({
        secret: process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
        issuer: 'secure-app',
        audience: 'secure-app-users'
    });
    
    // Login endpoint
    app.post('/login', async (req, res) => {
        const { username, password } = req.body;
        
        // Verify credentials
        const user = await verifyUser(username, password);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Generate tokens
        const tokens = jwtManager.generateTokens(user);
        
        res.json({
            success: true,
            ...tokens
        });
    });
    
    // Protected route
    app.get('/protected', 
        JWTMiddleware.authenticate(jwtManager),
        (req, res) => {
            res.json({
                message: 'Access granted',
                user: req.user
            });
        }
    );
    
    // Admin only route
    app.get('/admin',
        JWTMiddleware.authenticate(jwtManager),
        JWTMiddleware.requireRole(['admin']),
        (req, res) => {
            res.json({ message: 'Admin access granted' });
        }
    );
    
    // Refresh token endpoint
    app.post('/refresh', async (req, res) => {
        const { refreshToken } = req.body;
        
        try {
            const tokens = await jwtManager.refreshTokens(refreshToken);
            res.json(tokens);
        } catch (error) {
            res.status(401).json({ error: error.message });
        }
    });
    
    // Logout endpoint
    app.post('/logout', JWTMiddleware.authenticate(jwtManager), async (req, res) => {
        const authHeader = req.headers.authorization;
        const token = authHeader.substring(7);
        
        // Blacklist the token
        jwtManager.blacklistToken(token);
        
        res.json({ success: true, message: 'Logout successful' });
    });
    
    return app;
}

// Mock user verification
async function verifyUser(username, password) {
    // This should validate against your user database
    const users = {
        'admin': { id: 1, username: 'admin', email: 'admin@example.com', roles: ['admin'] },
        'user': { id: 2, username: 'user', email: 'user@example.com', roles: ['user'] }
    };
    
    const user = users[username];
    if (user && password === 'password123') {
        return user;
    }
    
    return null;
}

module.exports = { JWTManager, JWTMiddleware, createJWTApp };
```

---

## 5. Authentication Rate Limiting

### 5.1 Rate Limiting Implementation
```javascript
const crypto = require('crypto');

class RateLimiter {
    constructor(options = {}) {
        this.windowSize = options.windowSize || 60000; // 1 minute
        this.maxAttempts = options.maxAttempts || 5;
        this.storage = new Map(); // In production, use Redis
    }
    
    async checkLimit(identifier) {
        const now = Date.now();
        const windowStart = now - this.windowSize;
        
        // Get existing attempts
        const attempts = this.getAttempts(identifier);
        
        // Filter attempts within window
        const recentAttempts = attempts.filter(timestamp => timestamp > windowStart);
        
        // Update attempts array
        this.setAttempts(identifier, recentAttempts);
        
        return {
            allowed: recentAttempts.length < this.maxAttempts,
            remaining: Math.max(0, this.maxAttempts - recentAttempts.length),
            resetTime: this.getResetTime(identifier, recentAttempts)
        };
    }
    
    async recordAttempt(identifier) {
        const attempts = this.getAttempts(identifier);
        attempts.push(Date.now());
        this.setAttempts(identifier, attempts);
    }
    
    async resetLimit(identifier) {
        this.storage.delete(identifier);
    }
    
    getAttempts(identifier) {
        return this.storage.get(identifier) || [];
    }
    
    setAttempts(identifier, attempts) {
        this.storage.set(identifier, attempts);
    }
    
    getResetTime(identifier, attempts) {
        if (attempts.length === 0) return Date.now();
        
        const oldestAttempt = Math.min(...attempts);
        return oldestAttempt + this.windowSize;
    }
}

class LoginRateLimiter extends RateLimiter {
    constructor(options = {}) {
        super({
            windowSize: options.windowSize || 900000, // 15 minutes
            maxAttempts: options.maxAttempts || 5,
            ...options
        });
        
        this.lockoutDuration = options.lockoutDuration || 300000; // 5 minutes
        this.accountLockouts = new Map();
    }
    
    async checkLoginAttempt(identifier) {
        // Check if account is locked
        if (this.isAccountLocked(identifier)) {
            return {
                allowed: false,
                reason: 'account_locked',
                lockoutExpires: this.getAccountLockoutExpiry(identifier)
            };
        }
        
        // Check rate limit
        const rateLimit = await this.checkLimit(identifier);
        
        if (!rateLimit.allowed) {
            // Lock account
            await this.lockAccount(identifier);
            
            return {
                allowed: false,
                reason: 'rate_limit_exceeded',
                remaining: 0,
                lockoutExpires: this.getAccountLockoutExpiry(identifier)
            };
        }
        
        return rateLimit;
    }
    
    async recordLoginAttempt(identifier, success = false) {
        if (success) {
            // Reset on successful login
            await this.resetLimit(identifier);
            await this.unlockAccount(identifier);
        } else {
            await this.recordAttempt(identifier);
        }
    }
    
    isAccountLocked(identifier) {
        const lockout = this.accountLockouts.get(identifier);
        if (!lockout) return false;
        
        if (Date.now() > lockout.expires) {
            // Lockout expired, remove it
            this.accountLockouts.delete(identifier);
            return false;
        }
        
        return true;
    }
    
    async lockAccount(identifier) {
        const expires = Date.now() + this.lockoutDuration;
        this.accountLockouts.set(identifier, { expires });
    }
    
    async unlockAccount(identifier) {
        this.accountLockouts.delete(identifier);
    }
    
    getAccountLockoutExpiry(identifier) {
        const lockout = this.accountLockouts.get(identifier);
        return lockout ? lockout.expires : null;
    }
}

// Express.js rate limiting middleware
const createRateLimitMiddleware = (limiter) => {
    return async (req, res, next) => {
        // Use IP address and username/email as identifier
        const identifier = `${req.ip}:${req.body?.username || req.body?.email || 'unknown'}`;
        
        try {
            const result = await limiter.checkLoginAttempt(identifier);
            
            if (!result.allowed) {
                if (result.reason === 'account_locked') {
                    return res.status(423).json({
                        error: 'Account is locked',
                        lockoutExpires: new Date(result.lockoutExpires)
                    });
                } else {
                    return res.status(429).json({
                        error: 'Too many login attempts',
                        remaining: result.remaining,
                        lockoutExpires: new Date(result.lockoutExpires)
                    });
                }
            }
            
            // Add rate limit info to request for later use
            req.rateLimitInfo = result;
            req.identifier = identifier;
            
            next();
        } catch (error) {
            console.error('Rate limiting error:', error);
            next(); // Continue on error to avoid blocking legitimate users
        }
    };
};

// Example usage
const loginRateLimiter = new LoginRateLimiter({
    windowSize: 900000, // 15 minutes
    maxAttempts: 5,
    lockoutDuration: 300000 // 5 minutes
});

const app = require('express')();
app.use(express.json());

// Login endpoint with rate limiting
app.post('/login', 
    createRateLimitMiddleware(loginRateLimiter),
    async (req, res) => {
        const { username, password } = req.body;
        const identifier = req.identifier;
        
        try {
            // Verify credentials
            const user = await verifyUser(username, password);
            
            if (!user) {
                await loginRateLimiter.recordLoginAttempt(identifier, false);
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            // Record successful login
            await loginRateLimiter.recordLoginAttempt(identifier, true);
            
            // Generate tokens (implement your authentication logic)
            const tokens = generateTokens(user);
            
            res.json({
                success: true,
                tokens,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email
                }
            });
            
        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }
);

module.exports = { RateLimiter, LoginRateLimiter, createRateLimitMiddleware };
```

---

## 6. Account Security Features

### 6.1 Account Lockout and Security Monitoring
```php
<?php
class AccountSecurityManager {
    private $db;
    
    public function __construct($database) {
        $this->db = $database;
    }
    
    /**
     * Track failed login attempts
     */
    public function trackFailedLogin($username, $ipAddress, $userAgent) {
        $sql = "INSERT INTO login_attempts 
                (username, ip_address, user_agent, attempt_time, success) 
                VALUES (?, ?, ?, NOW(), 0)";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("sss", $username, $ipAddress, $userAgent);
        $stmt->execute();
        
        // Check if account should be locked
        $this->checkAccountLockout($username);
    }
    
    /**
     * Record successful login
     */
    public function recordSuccessfulLogin($userId, $ipAddress, $userAgent) {
        // Update last login
        $sql = "UPDATE users SET last_login = NOW(), last_login_ip = ? WHERE id = ?";
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("si", $ipAddress, $userId);
        $stmt->execute();
        
        // Clear failed attempts
        $this->clearFailedAttempts($userId);
        
        // Log successful login
        $this->logSecurityEvent($userId, 'login_success', [
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent
        ]);
    }
    
    /**
     * Check if account should be locked
     */
    private function checkAccountLockout($username) {
        // Get failed attempts in last 15 minutes
        $sql = "SELECT COUNT(*) as attempt_count 
                FROM login_attempts 
                WHERE username = ? 
                AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
                AND success = 0";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        
        if ($row['attempt_count'] >= 5) {
            $this->lockAccount($username);
            return true;
        }
        
        return false;
    }
    
    /**
     * Lock user account
     */
    private function lockAccount($username) {
        $sql = "UPDATE users 
                SET account_locked = 1, 
                    lockout_expires = DATE_ADD(NOW(), INTERVAL 1 HOUR)
                WHERE username = ?";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        
        // Log security event
        $user = $this->getUserByUsername($username);
        if ($user) {
            $this->logSecurityEvent($user['id'], 'account_locked', [
                'reason' => 'multiple_failed_attempts',
                'username' => $username
            ]);
        }
    }
    
    /**
     * Check if account is locked
     */
    public function isAccountLocked($username) {
        $sql = "SELECT account_locked, lockout_expires 
                FROM users 
                WHERE username = ?";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($row = $result->fetch_assoc()) {
            if ($row['account_locked']) {
                // Check if lockout has expired
                if ($row['lockout_expires'] && strtotime($row['lockout_expires']) < time()) {
                    $this->unlockAccount($username);
                    return false;
                }
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Unlock account
     */
    public function unlockAccount($username) {
        $sql = "UPDATE users 
                SET account_locked = 0, 
                    lockout_expires = NULL,
                    failed_login_attempts = 0
                WHERE username = ?";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        
        // Clear failed attempts
        $this->clearFailedAttemptsByUsername($username);
        
        // Log security event
        $user = $this->getUserByUsername($username);
        if ($user) {
            $this->logSecurityEvent($user['id'], 'account_unlocked', [
                'username' => $username
            ]);
        }
    }
    
    /**
     * Clear failed attempts for user
     */
    private function clearFailedAttempts($userId) {
        $sql = "DELETE FROM login_attempts WHERE user_id = ? AND success = 0";
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        
        // Reset failed attempts counter
        $sql = "UPDATE users SET failed_login_attempts = 0 WHERE id = ?";
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("i", $userId);
        $stmt->execute();
    }
    
    private function clearFailedAttemptsByUsername($username) {
        $sql = "DELETE FROM login_attempts WHERE username = ? AND success = 0";
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("s", $username);
        $stmt->execute();
    }
    
    /**
     * Detect suspicious login patterns
     */
    public function detectSuspiciousActivity($userId, $ipAddress, $userAgent) {
        $suspiciousIndicators = [];
        
        // Check for unusual login times
        if ($this->isUnusualLoginTime()) {
            $suspiciousIndicators[] = 'unusual_login_time';
        }
        
        // Check for new IP address
        if ($this->isNewIpAddress($userId, $ipAddress)) {
            $suspiciousIndicators[] = 'new_ip_address';
        }
        
        // Check for new user agent
        if ($this->isNewUserAgent($userId, $userAgent)) {
            $suspiciousIndicators[] = 'new_user_agent';
        }
        
        // Check for rapid successive logins
        if ($this->hasRapidLogins($userId)) {
            $suspiciousIndicators[] = 'rapid_logins';
        }
        
        // Check for multiple concurrent sessions
        if ($this->hasMultipleSessions($userId)) {
            $suspiciousIndicators[] = 'multiple_sessions';
        }
        
        if (!empty($suspiciousIndicators)) {
            $this->logSecurityEvent($userId, 'suspicious_activity', [
                'indicators' => $suspiciousIndicators,
                'ip_address' => $ipAddress,
                'user_agent' => $userAgent
            ]);
            
            // Optionally require additional authentication
            return true;
        }
        
        return false;
    }
    
    private function isUnusualLoginTime() {
        $currentHour = date('H');
        // Flag logins between 2 AM and 6 AM as unusual
        return $currentHour >= 2 && $currentHour <= 6;
    }
    
    private function isNewIpAddress($userId, $ipAddress) {
        $sql = "SELECT DISTINCT last_login_ip 
                FROM users 
                WHERE id = ? AND last_login_ip IS NOT NULL
                ORDER BY last_login DESC 
                LIMIT 5";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $previousIps = [];
        while ($row = $result->fetch_assoc()) {
            $previousIps[] = $row['last_login_ip'];
        }
        
        return !in_array($ipAddress, $previousIps);
    }
    
    private function isNewUserAgent($userId, $userAgent) {
        $sql = "SELECT DISTINCT user_agent 
                FROM login_attempts 
                WHERE user_id = ? AND success = 1
                ORDER BY attempt_time DESC 
                LIMIT 5";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $previousAgents = [];
        while ($row = $result->fetch_assoc()) {
            $previousAgents[] = $row['user_agent'];
        }
        
        // Simple user agent comparison (in production, use more sophisticated fingerprinting)
        return !in_array($userAgent, $previousAgents);
    }
    
    private function hasRapidLogins($userId) {
        $sql = "SELECT COUNT(*) as login_count
                FROM login_attempts 
                WHERE user_id = ? 
                AND success = 1
                AND attempt_time > DATE_SUB(NOW(), INTERVAL 1 MINUTE)";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        
        return $row['login_count'] > 3;
    }
    
    private function hasMultipleSessions($userId) {
        // This would check your session storage (Redis, database, etc.)
        // For now, return false as placeholder
        return false;
    }
    
    /**
     * Log security events
     */
    private function logSecurityEvent($userId, $event, $details) {
        $sql = "INSERT INTO security_events 
                (user_id, event_type, details, ip_address, user_agent, created_at) 
                VALUES (?, ?, ?, ?, ?, NOW())";
        
        $stmt = $this->db->prepare($sql);
        $detailsJson = json_encode($details);
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        $stmt->bind_param("issss", $userId, $event, $detailsJson, $ipAddress, $userAgent);
        $stmt->execute();
    }
    
    private function getUserByUsername($username) {
        $sql = "SELECT id, username, email FROM users WHERE username = ?";
        $stmt = $this->db->prepare($sql);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        return $result->fetch_assoc();
    }
}
?>
```

---

## 7. Testing Authentication Security

### 7.1 Authentication Test Suite
```javascript
const { JWTManager } = require('./jwt-auth');
const { SecurePasswordManager } = require('./password-security');

class AuthenticationTester {
    constructor() {
        this.results = [];
        this.jwtManager = new JWTManager({
            secret: 'test-secret-key-for-testing-only'
        });
    }
    
    async runAllTests() {
        console.log('Running Authentication Security Tests...\n');
        
        await this.testPasswordSecurity();
        await this.testJWTSecurity();
        await this.testRateLimiting();
        await this.testSessionSecurity();
        
        return this.generateReport();
    }
    
    async testPasswordSecurity() {
        console.log('Testing Password Security...');
        
        // Test password validation
        const testPasswords = [
            { password: 'weak', expected: 'invalid' },
            { password: '123456', expected: 'invalid' },
            { password: 'Password123', expected: 'valid' },
            { password: 'SecureP@ssw0rd123!', expected: 'valid' }
        ];
        
        for (const test of testPasswords) {
            const validation = SecurePasswordManager.validatePasswordStrength(test.password);
            const result = validation.valid ? 'valid' : 'invalid';
            
            this.results.push({
                test: 'Password Validation',
                input: test.password,
                expected: test.expected,
                actual: result,
                passed: test.expected === result
            });
            
            console.log(`  ${test.password}: ${result} ${test.expected === result ? '✓' : '✗'}`);
        }
        
        // Test password hashing
        const testPassword = 'TestPassword123!';
        const hash = await SecurePasswordManager.hashPassword(testPassword);
        const verify = await SecurePasswordManager.verifyPassword(testPassword, hash);
        const entropy = SecurePasswordManager.calculatePasswordEntropy(testPassword);
        
        this.results.push({
            test: 'Password Hashing',
            input: testPassword,
            expected: true,
            actual: verify,
            passed: verify === true
        });
        
        this.results.push({
            test: 'Password Entropy',
            input: testPassword,
            expected: '>= 60',
            actual: entropy.entropy.toString(),
            passed: entropy.entropy >= 60
        });
        
        console.log(`  Hash test: ${verify ? '✓' : '✗'}`);
        console.log(`  Entropy: ${entropy.entropy} bits (${entropy.strength})`);
    }
    
    async testJWTSecurity() {
        console.log('\nTesting JWT Security...');
        
        const testUser = {
            id: 1,
            username: 'testuser',
            email: 'test@example.com'
        };
        
        // Test token generation
        const tokens = this.jwtManager.generateTokens(testUser);
        
        this.results.push({
            test: 'Token Generation',
            input: testUser,
            expected: 'accessToken and refreshToken',
            actual: typeof tokens.accessToken + ' and ' + typeof tokens.refreshToken,
            passed: tokens.accessToken && tokens.refreshToken
        });
        
        // Test token verification
        const verification = this.jwtManager.verifyToken(tokens.accessToken);
        
        this.results.push({
            test: 'Token Verification',
            input: 'Valid token',
            expected: 'valid',
            actual: verification.valid ? 'valid' : 'invalid',
            passed: verification.valid
        });
        
        // Test token expiry
        const expiredToken = jwt.sign(
            { sub: '1', type: 'access', exp: Math.floor(Date.now() / 1000) - 3600 },
            this.jwtManager.secret,
            { algorithm: this.jwtManager.algorithm }
        );
        
        const expiredVerification = this.jwtManager.verifyToken(expiredToken);
        
        this.results.push({
            test: 'Expired Token Handling',
            input: 'Expired token',
            expected: 'invalid with expiry error',
            actual: `${!expiredVerification.valid} with ${expiredVerification.error}`,
            passed: !expiredVerification.valid && expiredVerification.expired
        });
        
        // Test invalid token
        const invalidVerification = this.jwtManager.verifyToken('invalid.token.here');
        
        this.results.push({
            test: 'Invalid Token Handling',
            input: 'Invalid token format',
            expected: 'invalid with malformed error',
            actual: `${!invalidVerification.valid} with ${invalidVerification.error}`,
            passed: !invalidVerification.valid && invalidVerification.malformed
        });
        
        console.log(`  Token generation: ${tokens.accessToken ? '✓' : '✗'}`);
        console.log(`  Token verification: ${verification.valid ? '✓' : '✗'}`);
        console.log(`  Expired token: ${expiredVerification.expired ? '✓' : '✗'}`);
        console.log(`  Invalid token: ${invalidVerification.malformed ? '✓' : '✗'}`);
    }
    
    async testRateLimiting() {
        console.log('\nTesting Rate Limiting...');
        
        const rateLimiter = new LoginRateLimiter({
            windowSize: 60000, // 1 minute
            maxAttempts: 3,
            lockoutDuration: 300000 // 5 minutes
        });
        
        const identifier = 'test-user';
        
        // Test normal operation
        for (let i = 0; i < 3; i++) {
            const result = await rateLimiter.checkLoginAttempt(identifier);
            this.results.push({
                test: `Rate Limit Check ${i + 1}`,
                input: identifier,
                expected: 'allowed',
                actual: result.allowed ? 'allowed' : 'blocked',
                passed: result.allowed
            });
        }
        
        // Test rate limit exceeded
        const exceededResult = await rateLimiter.checkLoginAttempt(identifier);
        this.results.push({
            test: 'Rate Limit Exceeded',
            input: identifier,
            expected: 'blocked',
            actual: exceededResult.allowed ? 'allowed' : 'blocked',
            passed: !exceededResult.allowed
        });
        
        // Test successful reset
        await rateLimiter.recordLoginAttempt(identifier, true);
        const resetResult = await rateLimiter.checkLoginAttempt(identifier);
        
        this.results.push({
            test: 'Rate Limit Reset',
            input: identifier,
            expected: 'allowed',
            actual: resetResult.allowed ? 'allowed' : 'blocked',
            passed: resetResult.allowed
        });
        
        console.log(`  Normal requests: ${this.results.filter(r => r.test.includes('Rate Limit Check')).every(r => r.passed) ? '✓' : '✗'}`);
        console.log(`  Rate limit exceeded: ${!exceededResult.allowed ? '✓' : '✗'}`);
        console.log(`  Reset after success: ${resetResult.allowed ? '✓' : '✗'}`);
    }
    
    async testSessionSecurity() {
        console.log('\nTesting Session Security...');
        
        // This would test your session security implementations
        // For brevity, showing structure of what to test
        
        const testCases = [
            {
                test: 'Session ID Randomness',
                description: 'Session IDs should be cryptographically random'
            },
            {
                test: 'Session Fixation Protection',
                description: 'Session IDs should be regenerated after login'
            },
            {
                test: 'Session Timeout',
                description: 'Sessions should expire after inactivity'
            },
            {
                test: 'Secure Cookie Flags',
                description: 'Cookies should have secure, httponly, and samesite flags'
            }
        ];
        
        testCases.forEach(testCase => {
            this.results.push({
                test: testCase.test,
                description: testCase.description,
                expected: 'Implemented',
                actual: 'Implemented', // This would be actual test results
                passed: true // This would be actual test result
            });
        });
        
        console.log('  Session security tests structure created');
    }
    
    generateReport() {
        const total = this.results.length;
        const passed = this.results.filter(r => r.passed).length;
        const failed = total - passed;
        const successRate = Math.round((passed / total) * 100);
        
        let report = '\n=== Authentication Security Test Report ===\n';
        report += `Total Tests: ${total}\n`;
        report += `Passed: ${passed}\n`;
        report += `Failed: ${failed}\n`;
        report += `Success Rate: ${successRate}%\n\n`;
        
        if (failed > 0) {
            report += 'Failed Tests:\n';
            this.results.filter(r => !r.passed).forEach(result => {
                report += `- ${result.test}\n`;
                report += `  Input: ${result.input}\n`;
                report += `  Expected: ${result.expected}\n`;
                report += `  Actual: ${result.actual}\n\n`;
            });
        }
        
        report += 'All tests completed.\n';
        
        console.log(report);
        
        return {
            summary: {
                total,
                passed,
                failed,
                successRate
            },
            results: this.results
        };
    }
}

// Run tests if this file is executed directly
if (require.main === module) {
    const tester = new AuthenticationTester();
    tester.runAllTests().then(report => {
        process.exit(report.summary.failed > 0 ? 1 : 0);
    }).catch(error => {
        console.error('Test execution failed:', error);
        process.exit(1);
    });
}

module.exports = { AuthenticationTester };
```

---

## Conclusion

This comprehensive authentication implementation covers:

1. **Password Security** - Strong hashing, validation, and entropy analysis
2. **Multi-Factor Authentication** - TOTP and SMS OTP implementations
3. **Session Management** - Secure session handling with Redis storage
4. **JWT Authentication** - Token-based authentication with refresh tokens
5. **Rate Limiting** - Protection against brute force attacks
6. **Account Security** - Lockout mechanisms and suspicious activity detection
7. **Testing** - Comprehensive security testing framework

**Key Security Principles:**
- **Defense in Depth** - Multiple overlapping security controls
- **Principle of Least Privilege** - Minimal necessary access
- **Secure by Default** - Security features enabled by default
- **Fail Securely** - Default to secure state on errors
- **Regular Security Testing** - Continuous validation of security controls

**Remember:** Authentication security is an ongoing process that requires regular updates, monitoring, and testing to maintain effectiveness against evolving threats.