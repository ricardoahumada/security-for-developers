// SQL Injection Prevention - JavaScript Implementation for playcode.io
// Purpose: Demonstrate SQL injection attacks and prevention techniques

console.log("=== SQL Injection Prevention Demo (JavaScript) ===\n");

// ============================================================================
// 1. VULNERABLE CODE EXAMPLES
// ============================================================================

console.log("🔴 VULNERABLE CODE EXAMPLES:");
console.log("==========================================");

// Mock database simulation (in real apps, this would be a real database)
class MockDatabase {
    constructor() {
        this.users = [
            { id: 1, username: 'admin', password: 'admin123', email: 'admin@example.com', role: 'admin' },
            { id: 2, username: 'john_doe', password: 'password123', email: 'john@example.com', role: 'user' },
            { id: 3, username: 'jane_smith', password: 'secure456', email: 'jane@example.com', role: 'user' }
        ];
        this.logs = [];
    }

    // VULNERABLE: Direct string concatenation
    vulnerableQuery(query) {
        console.log("🔴 Executing vulnerable query:", query);
        this.logs.push({ type: 'vulnerable', query, timestamp: new Date() });
        
        // Simulate SQL execution
        if (query.includes("' OR '1'='1")) {
            console.log("⚠️  SQL INJECTION DETECTED! Returning ALL users!");
            return this.users; // Returns all users - authentication bypass!
        }
        
        if (query.includes("DROP TABLE")) {
            console.log("💀 DESTRUCTIVE SQL INJECTION DETECTED!");
            throw new Error("SQL injection attack blocked!");
        }
        
        return this.findUserByQuery(query);
    }

    findUserByQuery(query) {
        // Very basic parsing - just for demonstration
        const match = query.match(/username\s*=\s*['"](.*?)['"]/);
        if (match) {
            const username = match[1];
            return this.users.filter(user => user.username === username);
        }
        return [];
    }

    // SECURE: Parameterized query simulation
    secureQuery(username, password) {
        console.log("✅ Executing secure query with parameters");
        console.log("📝 Username:", username, "Password:", password);
        this.logs.push({ type: 'secure', query: 'parameterized', username, password, timestamp: new Date() });
        
        const user = this.users.find(u => u.username === username && u.password === password);
        return user ? [user] : [];
    }

    getLogs() {
        return this.logs;
    }
}

// Demo vulnerable login function
function vulnerableLogin(db, username, password) {
    // VULNERABLE: Direct string concatenation
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    console.log("🔴 VULNERABLE LOGIN ATTEMPT:");
    console.log("Generated Query:", query);
    
    try {
        const result = db.vulnerableQuery(query);
        console.log("Result:", result.length, "users found");
        return result;
    } catch (error) {
        console.log("❌ Attack blocked:", error.message);
        return [];
    }
}

console.log("\n1.1 Testing Vulnerable Login with Normal Input:");
const db1 = new MockDatabase();
const normalUser = vulnerableLogin(db1, "john_doe", "password123");
console.log("✅ Normal login successful:", normalUser.length > 0);

console.log("\n1.2 Testing Vulnerable Login with SQL Injection:");
const injectionUser = vulnerableLogin(db1, "admin' OR '1'='1", "anything");
console.log("🚨 SQL INJECTION SUCCESSFUL! Attackers got:", injectionUser.length, "users");
console.log("Exposed data:", injectionUser.map(u => ({ username: u.username, role: u.role })));

// ============================================================================
// 2. SECURE IMPLEMENTATIONS
// ============================================================================

console.log("\n\n🟢 SECURE IMPLEMENTATIONS:");
console.log("==========================================");

class SecureUserRepository {
    constructor() {
        this.users = [
            { id: 1, username: 'admin', password_hash: 'hashed_admin123', email: 'admin@example.com', role: 'admin' },
            { id: 2, username: 'john_doe', password_hash: 'hashed_password123', email: 'john@example.com', role: 'user' },
            { id: 3, username: 'jane_smith', password_hash: 'hashed_secure456', email: 'jane@example.com', role: 'user' }
        ];
    }

    // SECURE: Using parameterized queries (conceptual simulation)
    async findUserByUsernameSecure(username) {
        console.log("✅ SECURE: Using parameterized query");
        
        // Simulate prepared statement
        const sql = "SELECT id, username, password_hash, email, role FROM users WHERE username = ?";
        console.log("📝 SQL with placeholder:", sql);
        console.log("📝 Parameter:", username);
        
        // Parameter sanitization check
        if (this.containsDangerousCharacters(username)) {
            throw new Error("Input contains dangerous characters");
        }
        
        const user = this.users.find(u => u.username === username);
        console.log("🔍 Search result:", user ? "User found" : "User not found");
        return user;
    }

    // Input validation with dangerous character detection
    containsDangerousCharacters(input) {
        const dangerousPatterns = [
            /'/g,           // Single quote
            /"/g,           // Double quote  
            /;/g,           // Semicolon
            /--/g,          // SQL comments
            /\/\*/g,        // Block comments start
            /\*\//g,        // Block comments end
            /union/gi,      // UNION keyword
            /select/gi,     // SELECT keyword
            /drop/gi,       // DROP keyword
            /delete/gi,     // DELETE keyword
            /insert/gi,     // INSERT keyword
            /update/gi,     // UPDATE keyword
            /exec/gi,       // EXEC keyword
            /xp_/gi,        // Extended procedures
            /sp_/gi         // Stored procedures
        ];

        return dangerousPatterns.some(pattern => pattern.test(input));
    }

    // SECURE: Authentication with input validation
    async authenticateUserSecure(username, password) {
        console.log("\n🛡️  SECURE AUTHENTICATION:");
        
        try {
            // Step 1: Input validation
            if (!this.validateUsername(username)) {
                throw new Error("Invalid username format");
            }
            
            if (!this.validatePassword(password)) {
                throw new Error("Invalid password format");
            }
            
            // Step 2: Parameterized query
            const user = await this.findUserByUsernameSecure(username);
            if (!user) {
                console.log("❌ Authentication failed: User not found");
                return null;
            }
            
            // Step 3: Password verification (in real app, use bcrypt)
            const passwordMatch = this.verifyPassword(password, user.password_hash);
            if (!passwordMatch) {
                console.log("❌ Authentication failed: Invalid password");
                return null;
            }
            
            console.log("✅ Authentication successful!");
            return {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            };
            
        } catch (error) {
            console.log("❌ Authentication error:", error.message);
            return null;
        }
    }

    // Input validation methods
    validateUsername(username) {
        if (!username || username.length < 3 || username.length > 20) {
            console.log("❌ Username validation failed: Length must be 3-20 characters");
            return false;
        }
        
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            console.log("❌ Username validation failed: Only letters, numbers, and underscores allowed");
            return false;
        }
        
        if (this.containsDangerousCharacters(username)) {
            console.log("❌ Username validation failed: Contains dangerous characters");
            return false;
        }
        
        console.log("✅ Username validation passed");
        return true;
    }

    validatePassword(password) {
        if (!password || password.length < 8) {
            console.log("❌ Password validation failed: Must be at least 8 characters");
            return false;
        }
        
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasNumber = /\d/.test(password);
        const hasSpecial = /[^A-Za-z0-9]/.test(password);
        
        if (!hasUpper || !hasLower || !hasNumber || !hasSpecial) {
            console.log("❌ Password validation failed: Must contain uppercase, lowercase, number, and special character");
            return false;
        }
        
        console.log("✅ Password validation passed");
        return true;
    }

    // Simulated password verification
    verifyPassword(password, hash) {
        // In real implementation, use bcrypt.compare()
        const simulatedHash = 'hashed_' + password;
        return hash === simulatedHash;
    }
}

// Test secure authentication
async function testSecureAuthentication() {
    const secureRepo = new SecureUserRepository();
    
    console.log("\n2.1 Testing Secure Authentication with Valid Input:");
    const validAuth = await secureRepo.authenticateUserSecure("john_doe", "password123");
    console.log("Result:", validAuth ? "✅ Success" : "❌ Failed");
    
    console.log("\n2.2 Testing Secure Authentication with SQL Injection:");
    const injectionAuth = await secureRepo.authenticateUserSecure("admin' OR '1'='1", "anything");
    console.log("Result:", injectionAuth ? "❌ Security breach!" : "✅ Attack prevented");
    
    console.log("\n2.3 Testing Input Validation:");
    const invalidUser = await secureRepo.authenticateUserSecure("admin'; DROP TABLE users;--", "password");
    console.log("Result:", invalidUser ? "❌ Security breach!" : "✅ Attack prevented");
}

// ============================================================================
// 3. INPUT VALIDATION CLASS
// ============================================================================

class InputValidator {
    constructor() {
        this.errors = [];
    }

    validateUsername(username) {
        this.errors = [];
        console.log("🔍 Validating username:", username);
        
        // Length validation
        if (!username || username.length < 3 || username.length > 20) {
            this.errors.push("Username must be between 3-20 characters");
            return false;
        }
        
        // Character validation
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            this.errors.push("Username can only contain letters, numbers, and underscores");
            return false;
        }
        
        // SQL injection character filtering
        const dangerousChars = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_'];
        for (const char of dangerousChars) {
            if (username.toLowerCase().includes(char)) {
                this.errors.push(`Username contains forbidden character: ${char}`);
                return false;
            }
        }
        
        console.log("✅ Username validation passed");
        return true;
    }

    validateEmail(email) {
        this.errors = [];
        console.log("🔍 Validating email:", email);
        
        if (!email || !email.includes('@')) {
            this.errors.push("Invalid email format");
            return false;
        }
        
        // Additional validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            this.errors.push("Invalid email format");
            return false;
        }
        
        console.log("✅ Email validation passed");
        return true;
    }

    validatePassword(password) {
        this.errors = [];
        console.log("🔍 Validating password");
        
        if (!password || password.length < 8) {
            this.errors.push("Password must be at least 8 characters");
            return false;
        }
        
        const checks = [
            { test: /[A-Z]/, message: "at least one uppercase letter" },
            { test: /[a-z]/, message: "at least one lowercase letter" },
            { test: /\d/, message: "at least one number" },
            { test: /[^A-Za-z0-9]/, message: "at least one special character" }
        ];
        
        for (const check of checks) {
            if (!check.test.test(password)) {
                this.errors.push(`Password must contain ${check.message}`);
                return false;
            }
        }
        
        console.log("✅ Password validation passed");
        return true;
    }

    getErrors() {
        return this.errors;
    }
}

// ============================================================================
// 4. SQL INJECTION TEST SUITE
// ============================================================================

class SQLInjectionTester {
    constructor() {
        this.testCases = [
            {
                name: "Basic SQL Injection",
                input: "admin' OR '1'='1",
                expected: "blocked"
            },
            {
                name: "Union-based SQL Injection",
                input: "' UNION SELECT password FROM users--",
                expected: "blocked"
            },
            {
                name: "Comment-based Injection",
                input: "admin'; DROP TABLE users;--",
                expected: "blocked"
            },
            {
                name: "Time-based Blind SQL Injection",
                input: "admin'; WAITFOR DELAY '00:00:05'--",
                expected: "blocked"
            },
            {
                name: "Normal Username",
                input: "john_doe",
                expected: "allowed"
            }
        ];
    }

    runTests(validationFunction) {
        console.log("\n\n🧪 SQL INJECTION TEST SUITE:");
        console.log("==========================================");
        
        const results = [];
        
        this.testCases.forEach((testCase, index) => {
            console.log(`\nTest ${index + 1}: ${testCase.name}`);
            console.log("Input:", testCase.input);
            
            try {
                const result = validationFunction(testCase.input);
                const passed = (result === testCase.expected);
                
                console.log(`Expected: ${testCase.expected}`);
                console.log(`Actual: ${result}`);
                console.log(`Status: ${passed ? '✅ PASS' : '❌ FAIL'}`);
                
                results.push({
                    testName: testCase.name,
                    input: testCase.input,
                    expected: testCase.expected,
                    actual: result,
                    passed: passed
                });
            } catch (error) {
                console.log(`Expected: ${testCase.expected}`);
                console.log(`Actual: error`);
                console.log(`Status: ❌ FAIL - ${error.message}`);
                
                results.push({
                    testName: testCase.name,
                    input: testCase.input,
                    expected: testCase.expected,
                    actual: 'error',
                    passed: false,
                    error: error.message
                });
            }
        });
        
        return this.generateReport(results);
    }

    generateReport(results) {
        const total = results.length;
        const passed = results.filter(r => r.passed).length;
        const failed = total - passed;
        
        console.log("\n\n📊 TEST RESULTS SUMMARY:");
        console.log("==========================");
        console.log(`Total Tests: ${total}`);
        console.log(`Passed: ${passed}`);
        console.log(`Failed: ${failed}`);
        console.log(`Success Rate: ${Math.round((passed / total) * 100)}%`);
        
        return { total, passed, failed, results };
    }
}

// ============================================================================
// 5. DEMO EXECUTION
// ============================================================================

async function runCompleteDemo() {
    try {
        // Test vulnerable vs secure implementations
        await testSecureAuthentication();
        
        // Test input validation
        console.log("\n\n3. INPUT VALIDATION EXAMPLES:");
        console.log("==========================================");
        
        const validator = new InputValidator();
        
        console.log("\n3.1 Valid Username Test:");
        const validUsername = validator.validateUsername("john_doe_123");
        console.log("Result:", validUsername ? "✅ Passed" : "❌ Failed");
        if (validator.getErrors().length > 0) {
            console.log("Errors:", validator.getErrors());
        }
        
        console.log("\n3.2 Invalid Username (SQL Injection) Test:");
        const invalidUsername = validator.validateUsername("admin'; DROP TABLE users;--");
        console.log("Result:", invalidUsername ? "❌ Security breach!" : "✅ Blocked");
        if (validator.getErrors().length > 0) {
            console.log("Errors:", validator.getErrors());
        }
        
        // Run comprehensive test suite
        const tester = new SQLInjectionTester();
        const usernameValidator = (input) => {
            const val = new InputValidator();
            return val.validateUsername(input) ? "allowed" : "blocked";
        };
        
        tester.runTests(usernameValidator);
        
        console.log("\n\n🎯 KEY TAKEAWAYS:");
        console.log("==================");
        console.log("1. ✅ Always use parameterized queries");
        console.log("2. ✅ Implement input validation");
        console.log("3. ✅ Use ORM frameworks when possible");
        console.log("4. ✅ Never trust user input");
        console.log("5. ✅ Implement defense in depth");
        console.log("6. ✅ Test for SQL injection vulnerabilities");
        console.log("\n🚫 NEVER use string concatenation for SQL queries!");
        
    } catch (error) {
        console.error("Demo error:", error);
    }
}

// Run the complete demo
runCompleteDemo();