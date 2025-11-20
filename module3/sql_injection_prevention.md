# SQL Injection Prevention Code Examples

**Author:** MiniMax Agent  
**Module Reference:** Module 3 - Injection Attacks  
**Last Updated:** 2025-11-15  

## Overview
This file contains practical code examples demonstrating SQL injection prevention techniques across different programming languages and frameworks.

---

## 1. Vulnerable Code Examples

### 1.1 Basic Vulnerable SQL Query (PHP)
```php
<?php
// VULNERABLE CODE - NEVER USE IN PRODUCTION
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($connection, $query);

// Attack Vector: admin' OR '1'='1' --
?>
```

### 1.2 JavaScript Vulnerable Query
```javascript
// VULNERABLE CODE
function getUser(username) {
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    return db.query(query);
}

// Attack Vector: ' OR 1=1 --
```

### 1.3 Python Vulnerable Query
```python
# VULNERABLE CODE
def get_user_by_id(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

# Attack Vector: 1; DROP TABLE users; --
```

---

## 2. Secure Parameterized Queries

### 2.1 PHP with Prepared Statements
```php
<?php
// SECURE IMPLEMENTATION
function authenticateUser($username, $password) {
    global $connection;
    
    // Use prepared statement
    $stmt = $connection->prepare("SELECT id, username, password_hash FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        
        // Verify password with bcrypt
        if (password_verify($password, $user['password_hash'])) {
            return $user;
        }
    }
    
    return null;
}

// Advanced example with multiple parameters
function updateUserProfile($userId, $email, $phone) {
    global $connection;
    
    $stmt = $connection->prepare("UPDATE users SET email = ?, phone = ?, updated_at = NOW() WHERE id = ?");
    $stmt->bind_param("ssi", $email, $phone, $userId);
    
    if ($stmt->execute()) {
        return ['success' => true, 'affected_rows' => $stmt->affected_rows];
    } else {
        return ['success' => false, 'error' => $stmt->error];
    }
}
?>
```

### 2.2 Node.js with Parameterized Queries
```javascript
// SECURE IMPLEMENTATION
const mysql = require('mysql2/promise');

class SecureDatabase {
    constructor(config) {
        this.pool = mysql.createPool(config);
    }

    async getUserByUsername(username) {
        const [rows] = await this.pool.execute(
            'SELECT id, username, email, created_at FROM users WHERE username = ?',
            [username]
        );
        return rows.length > 0 ? rows[0] : null;
    }

    async createUser(userData) {
        const { username, email, password_hash } = userData;
        
        const [result] = await this.pool.execute(
            'INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, NOW())',
            [username, email, password_hash]
        );
        
        return result.insertId;
    }

    async searchProducts(searchTerm, category, minPrice, maxPrice, limit = 20) {
        let query = 'SELECT * FROM products WHERE 1=1';
        const params = [];

        if (searchTerm) {
            query += ' AND (name LIKE ? OR description LIKE ?)';
            params.push(`%${searchTerm}%`, `%${searchTerm}%`);
        }

        if (category) {
            query += ' AND category = ?';
            params.push(category);
        }

        if (minPrice !== undefined) {
            query += ' AND price >= ?';
            params.push(minPrice);
        }

        if (maxPrice !== undefined) {
            query += ' AND price <= ?';
            params.push(maxPrice);
        }

        query += ' LIMIT ?';
        params.push(limit);

        const [rows] = await this.pool.execute(query, params);
        return rows;
    }
}
```

### 2.3 Python with SQLAlchemy ORM
```python
# SECURE IMPLEMENTATION using SQLAlchemy
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, text
from datetime import datetime

class SecureUserRepository:
    def __init__(self, database_url):
        self.engine = create_engine(database_url)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

    def get_user_by_email(self, email):
        """Secure email-based user lookup"""
        query = text("""
            SELECT id, username, email, created_at, last_login 
            FROM users 
            WHERE email = :email AND is_active = :is_active
        """)
        
        result = self.session.execute(query, {
            'email': email,
            'is_active': True
        })
        
        return result.fetchone()

    def create_product(self, product_data):
        """Secure product creation with validation"""
        from models import Product  # Import your model
        
        product = Product(
            name=product_data['name'],
            description=product_data['description'],
            price=product_data['price'],
            category_id=product_data['category_id'],
            created_at=datetime.utcnow()
        )
        
        self.session.add(product)
        self.session.commit()
        
        return product.id

    def search_users_advanced(self, filters):
        """Advanced search with dynamic filtering"""
        base_query = text("""
            SELECT u.id, u.username, u.email, p.name as profile_name
            FROM users u
            LEFT JOIN profiles p ON u.id = p.user_id
            WHERE u.is_active = :is_active
        """)
        
        params = {'is_active': True}
        
        if filters.get('username'):
            base_query = text(str(base_query) + " AND u.username LIKE :username")
            params['username'] = f"%{filters['username']}%"
        
        if filters.get('email_domain'):
            base_query = text(str(base_query) + " AND u.email LIKE :email_domain")
            params['email_domain'] = f"%@{filters['email_domain']}"
        
        if filters.get('created_after'):
            base_query = text(str(base_query) + " AND u.created_at >= :created_after")
            params['created_after'] = filters['created_after']
        
        result = self.session.execute(base_query, params)
        return result.fetchall()
```

### 2.4 Java with JDBC PreparedStatement
```java
// SECURE IMPLEMENTATION using JDBC
import java.sql.*;

public class SecureUserDAO {
    private Connection connection;
    
    public SecureUserDAO(String url, String username, String password) 
            throws SQLException {
        this.connection = DriverManager.getConnection(url, username, password);
    }
    
    public User getUserById(int userId) throws SQLException {
        String query = "SELECT id, username, email, created_at FROM users WHERE id = ? AND is_active = ?";
        
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setInt(1, userId);
            stmt.setBoolean(2, true);
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return new User(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getString("email"),
                        rs.getTimestamp("created_at")
                    );
                }
            }
        }
        return null;
    }
    
    public List<Product> searchProducts(String searchTerm, String category, 
                                      Double minPrice, Double maxPrice) 
            throws SQLException {
        StringBuilder query = new StringBuilder(
            "SELECT * FROM products WHERE is_active = true"
        );
        List<Object> params = new ArrayList<>();
        
        if (searchTerm != null && !searchTerm.trim().isEmpty()) {
            query.append(" AND (name LIKE ? OR description LIKE ?)");
            params.add("%" + searchTerm + "%");
            params.add("%" + searchTerm + "%");
        }
        
        if (category != null) {
            query.append(" AND category = ?");
            params.add(category);
        }
        
        if (minPrice != null) {
            query.append(" AND price >= ?");
            params.add(minPrice);
        }
        
        if (maxPrice != null) {
            query.append(" AND price <= ?");
            params.add(maxPrice);
        }
        
        try (PreparedStatement stmt = connection.prepareStatement(query.toString())) {
            // Set parameters
            for (int i = 0; i < params.size(); i++) {
                stmt.setObject(i + 1, params.get(i));
            }
            
            List<Product> products = new ArrayList<>();
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    products.add(new Product(
                        rs.getInt("id"),
                        rs.getString("name"),
                        rs.getString("description"),
                        rs.getDouble("price")
                    ));
                }
            }
            return products;
        }
    }
}
```

---

## 3. ORM Framework Security

### 3.1 Django ORM Security
```python
# SECURE IMPLEMENTATION using Django ORM
from django.db.models import Q
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

class SecureUserService:
    @staticmethod
    def search_users(search_term, is_active=None):
        """Secure user search using Django ORM"""
        queryset = User.objects.all()
        
        # Django ORM automatically prevents SQL injection
        if search_term:
            queryset = queryset.filter(
                Q(username__icontains=search_term) |
                Q(email__icontains=search_term) |
                Q(first_name__icontains=search_term) |
                Q(last_name__icontains=search_term)
            )
        
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active)
        
        return queryset
    
    @staticmethod
    def create_user(user_data):
        """Secure user creation with validation"""
        from django.contrib.auth.models import User
        
        # Django's User model provides built-in security
        user = User.objects.create_user(
            username=user_data['username'],
            email=user_data['email'],
            password=user_data['password'],
            first_name=user_data.get('first_name', ''),
            last_name=user_data.get('last_name', '')
        )
        
        return user

# Example with raw SQL (when necessary)
from django.db import connection
from django.db import transaction

@transaction.atomic
def bulk_update_product_prices(updates):
    """
    Secure bulk update using parameterized query
    """
    with connection.cursor() as cursor:
        for product_id, new_price in updates.items():
            cursor.execute(
                "UPDATE products SET price = %s, updated_at = NOW() WHERE id = %s",
                [new_price, product_id]
            )
```

### 3.2 Entity Framework Core (C#)
```csharp
// SECURE IMPLEMENTATION using Entity Framework Core
using Microsoft.EntityFrameworkCore;
using System.Linq;

public class ApplicationDbContext : DbContext
{
    public DbSet<User> Users { get; set; }
    public DbSet<Product> Products { get; set; }
    
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.UseSqlServer(connectionString);
    }
}

public class SecureUserService
{
    private readonly ApplicationDbContext _context;
    
    public SecureUserService(ApplicationDbContext context)
    {
        _context = context;
    }
    
    public async Task<User> GetUserByEmailAsync(string email)
    {
        // Entity Framework prevents SQL injection automatically
        return await _context.Users
            .FirstOrDefaultAsync(u => u.Email == email && u.IsActive);
    }
    
    public async Task<IEnumerable<Product>> SearchProductsAsync(
        string searchTerm, string category, decimal? minPrice, decimal? maxPrice)
    {
        var query = _context.Products.Where(p => p.IsActive);
        
        if (!string.IsNullOrEmpty(searchTerm))
        {
            query = query.Where(p => p.Name.Contains(searchTerm) || 
                                   p.Description.Contains(searchTerm));
        }
        
        if (!string.IsNullOrEmpty(category))
        {
            query = query.Where(p => p.Category.Name == category);
        }
        
        if (minPrice.HasValue)
        {
            query = query.Where(p => p.Price >= minPrice.Value);
        }
        
        if (maxPrice.HasValue)
        {
            query = query.Where(p => p.Price <= maxPrice.Value);
        }
        
        return await query.ToListAsync();
    }
}
```

---

## 4. Input Validation Techniques

### 4.1 Input Validation Class
```php
<?php
class SecureInputValidator {
    private $errors = [];
    
    public function validateUsername($username) {
        // Length validation
        if (strlen($username) < 3 || strlen($username) > 20) {
            $this->errors[] = "Username must be between 3-20 characters";
            return false;
        }
        
        // Character validation
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            $this->errors[] = "Username can only contain letters, numbers, and underscores";
            return false;
        }
        
        // SQL injection character filtering (additional protection)
        $dangerous_chars = ['\'', '"', ';', '--', '/*', '*/', 'xp_', 'sp_'];
        foreach ($dangerous_chars as $char) {
            if (stripos($username, $char) !== false) {
                $this->errors[] = "Username contains forbidden characters";
                return false;
            }
        }
        
        return true;
    }
    
    public function validateEmail($email) {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->errors[] = "Invalid email format";
            return false;
        }
        
        // Additional email validation
        $email = strtolower(trim($email));
        $parts = explode('@', $email);
        
        if (count($parts) !== 2) {
            $this->errors[] = "Invalid email format";
            return false;
        }
        
        // Domain validation
        $domain = $parts[1];
        if (!$this->isValidDomain($domain)) {
            $this->errors[] = "Invalid email domain";
            return false;
        }
        
        return true;
    }
    
    public function validatePassword($password) {
        if (strlen($password) < 8) {
            $this->errors[] = "Password must be at least 8 characters";
            return false;
        }
        
        if (!preg_match('/[A-Z]/', $password)) {
            $this->errors[] = "Password must contain at least one uppercase letter";
            return false;
        }
        
        if (!preg_match('/[a-z]/', $password)) {
            $this->errors[] = "Password must contain at least one lowercase letter";
            return false;
        }
        
        if (!preg_match('/\d/', $password)) {
            $this->errors[] = "Password must contain at least one number";
            return false;
        }
        
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            $this->errors[] = "Password must contain at least one special character";
            return false;
        }
        
        return true;
    }
    
    private function isValidDomain($domain) {
        // Basic domain validation
        if (strlen($domain) > 253) {
            return false;
        }
        
        if (!preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/', $domain)) {
            return false;
        }
        
        // Check for valid TLD
        $tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil'];
        $domain_parts = explode('.', $domain);
        $tld = end($domain_parts);
        
        return in_array(strtolower($tld), $tlds);
    }
    
    public function getErrors() {
        return $this->errors;
    }
}
?>
```

---

## 5. Advanced Security Techniques

### 5.1 Stored Procedure Example
```sql
-- Create secure stored procedure
DELIMITER //

CREATE PROCEDURE GetUserProfile(IN user_id INT, IN requesting_user_id INT)
BEGIN
    -- Validate that user can only access their own profile unless admin
    DECLARE user_is_admin BOOLEAN DEFAULT FALSE;
    
    -- Check if requesting user is admin
    SELECT is_admin INTO user_is_admin 
    FROM users 
    WHERE id = requesting_user_id;
    
    -- Return profile data
    SELECT u.id, u.username, u.email, p.first_name, p.last_name, p.bio
    FROM users u
    JOIN profiles p ON u.id = p.user_id
    WHERE u.id = user_id 
    AND (u.id = requesting_user_id OR user_is_admin = TRUE)
    AND u.is_active = TRUE;
    
END //

DELIMITER ;

-- Call stored procedure (in PHP)
$stmt = $connection->prepare("CALL GetUserProfile(?, ?)");
$stmt->bind_param("ii", $userId, $requestingUserId);
$stmt->execute();
```

### 5.2 Database Function Security
```sql
-- Create secure function for user authentication
DELIMITER //

CREATE FUNCTION AuthenticateUser(p_username VARCHAR(50), p_password_hash VARCHAR(255))
RETURNS INT
READS SQL DATA
DETERMINISTIC
BEGIN
    DECLARE user_id INT DEFAULT NULL;
    
    -- Get user ID if credentials match
    SELECT id INTO user_id
    FROM users
    WHERE username = p_username
    AND password_hash = p_password_hash
    AND is_active = TRUE
    AND failed_attempts < 3
    AND (last_failed_attempt IS NULL OR last_failed_attempt < DATE_SUB(NOW(), INTERVAL 15 MINUTE));
    
    -- Log successful authentication
    IF user_id IS NOT NULL THEN
        UPDATE users 
        SET last_login = NOW(), failed_attempts = 0 
        WHERE id = user_id;
    END IF;
    
    RETURN user_id;
END //

DELIMITER ;
```

---

## 6. Error Handling and Logging

### 6.1 Secure Error Handling
```php
<?php
class SecureDatabaseOperations {
    private $connection;
    private $logger;
    
    public function __construct($connection, $logger) {
        $this->connection = $connection;
        $this->logger = $logger;
    }
    
    public function executeSecureQuery($query, $params = []) {
        try {
            if (empty($params)) {
                // Simple query without parameters - only for static queries
                $this->validateStaticQuery($query);
                $result = mysqli_query($this->connection, $query);
            } else {
                // Parameterized query
                $stmt = $this->connection->prepare($query);
                if (!$stmt) {
                    throw new DatabaseException("Failed to prepare statement");
                }
                
                // Bind parameters dynamically
                $types = str_repeat('s', count($params)); // Default to string type
                $stmt->bind_param($types, ...$params);
                
                if (!$stmt->execute()) {
                    throw new DatabaseException("Failed to execute statement: " . $stmt->error);
                }
                
                $result = $stmt->get_result();
                $stmt->close();
            }
            
            return $result;
            
        } catch (Exception $e) {
            // Log error without exposing sensitive information
            $this->logger->error('Database operation failed', [
                'error' => $e->getMessage(),
                'query_type' => $this->analyzeQueryType($query),
                'timestamp' => date('Y-m-d H:i:s')
            ]);
            
            // Return generic error to client
            throw new DatabaseException('Database operation failed. Please try again later.');
        }
    }
    
    private function validateStaticQuery($query) {
        // Only allow specific read-only queries for static execution
        $allowed_patterns = [
            '/^SELECT\s+\*\s+FROM\s+users\s+WHERE\s+id\s*=\s*\d+\s*$/i',
            '/^SELECT\s+\*\s+FROM\s+products\s+WHERE\s+id\s*=\s*\d+\s*$/i'
        ];
        
        foreach ($allowed_patterns as $pattern) {
            if (preg_match($pattern, $query)) {
                return true;
            }
        }
        
        throw new DatabaseException("Direct query execution not allowed");
    }
    
    private function analyzeQueryType($query) {
        $query_type = strtoupper(substr(trim($query), 0, 6));
        return $query_type;
    }
}

class DatabaseException extends Exception {}
?>
```

---

## 7. Performance Optimization

### 7.1 Connection Pooling and Reuse
```php
<?php
class DatabasePool {
    private static $instance = null;
    private $connections = [];
    private $maxConnections = 10;
    private $connectionConfig;
    
    private function __construct($config) {
        $this->connectionConfig = $config;
    }
    
    public static function getInstance($config = null) {
        if (self::$instance === null) {
            self::$instance = new self($config);
        }
        return self::$instance;
    }
    
    public function getConnection() {
        // Reuse existing connection if available
        foreach ($this->connections as $conn) {
            if ($this->isConnectionHealthy($conn)) {
                return $conn;
            }
        }
        
        // Create new connection if under limit
        if (count($this->connections) < $this->maxConnections) {
            $connection = $this->createNewConnection();
            $this->connections[] = $connection;
            return $connection;
        }
        
        // Wait for available connection or throw error
        throw new Exception("Database connection pool exhausted");
    }
    
    private function createNewConnection() {
        $connection = new mysqli(
            $this->connectionConfig['host'],
            $this->connectionConfig['username'],
            $this->connectionConfig['password'],
            $this->connectionConfig['database'],
            $this->connectionConfig['port']
        );
        
        if ($connection->connect_error) {
            throw new Exception("Connection failed: " . $connection->connect_error);
        }
        
        return $connection;
    }
    
    private function isConnectionHealthy($connection) {
        return $connection && $connection->ping();
    }
    
    public function executeQuery($query, $params = []) {
        $connection = $this->getConnection();
        $stmt = $connection->prepare($query);
        
        if ($params) {
            $types = str_repeat('s', count($params));
            $stmt->bind_param($types, ...$params);
        }
        
        $stmt->execute();
        return $stmt->get_result();
    }
}
?>
```

---

## 8. Testing and Validation

### 8.1 SQL Injection Test Suite
```php
<?php
class SQLInjectionTester {
    private $testCases = [
        [
            'name' => 'Basic SQL Injection',
            'input' => "admin' OR '1'='1",
            'expected_behavior' => 'blocked'
        ],
        [
            'name' => 'Union-based SQL Injection',
            'input' => "' UNION SELECT password FROM users--",
            'expected_behavior' => 'blocked'
        ],
        [
            'name' => 'Comment-based Injection',
            'input' => "admin'; DROP TABLE users;--",
            'expected_behavior' => 'blocked'
        ],
        [
            'name' => 'Time-based Blind SQL Injection',
            'input' => "admin'; WAITFOR DELAY '00:00:05'--",
            'expected_behavior' => 'blocked'
        ],
        [
            'name' => 'Normal Username',
            'input' => 'john_doe',
            'expected_behavior' => 'allowed'
        ]
    ];
    
    public function runTests($validationFunction) {
        $results = [];
        
        foreach ($this->testCases as $test) {
            $result = $this->runSingleTest($test, $validationFunction);
            $results[] = $result;
        }
        
        return $this->generateTestReport($results);
    }
    
    private function runSingleTest($testCase, $validationFunction) {
        try {
            $result = $validationFunction($testCase['input']);
            $passed = ($result === $testCase['expected_behavior']);
            
            return [
                'test_name' => $testCase['name'],
                'input' => $testCase['input'],
                'expected' => $testCase['expected_behavior'],
                'actual' => $result,
                'passed' => $passed
            ];
        } catch (Exception $e) {
            return [
                'test_name' => $testCase['name'],
                'input' => $testCase['input'],
                'expected' => $testCase['expected_behavior'],
                'actual' => 'error',
                'passed' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    private function generateTestReport($results) {
        $total = count($results);
        $passed = count(array_filter($results, fn($r) => $r['passed']));
        $failed = $total - $passed;
        
        $report = "SQL Injection Test Results\n";
        $report .= "===========================\n";
        $report .= "Total Tests: {$total}\n";
        $report .= "Passed: {$passed}\n";
        $report .= "Failed: {$failed}\n";
        $report .= "Success Rate: " . round(($passed / $total) * 100, 2) . "%\n\n";
        
        foreach ($results as $result) {
            $status = $result['passed'] ? 'PASS' : 'FAIL';
            $report .= "[{$status}] {$result['test_name']}\n";
            $report .= "  Input: {$result['input']}\n";
            $report .= "  Expected: {$result['expected']}\n";
            $report .= "  Actual: {$result['actual']}\n";
            if (isset($result['error'])) {
                $report .= "  Error: {$result['error']}\n";
            }
            $report .= "\n";
        }
        
        return $report;
    }
}
?>
```

---

## Conclusion

These code examples demonstrate comprehensive SQL injection prevention techniques:

1. **Always use parameterized queries** - This is the most effective protection
2. **Implement input validation** - Multiple layers of validation provide defense in depth
3. **Use ORM frameworks** - They provide built-in security features
4. **Validate static queries** - If you must use raw SQL, validate it carefully
5. **Implement proper error handling** - Don't expose database information to users
6. **Use connection pooling** - Improves performance and resource management
7. **Test thoroughly** - Include SQL injection testing in your security testing process

**Remember:** No single technique provides complete protection. Use a defense-in-depth approach with multiple security controls.