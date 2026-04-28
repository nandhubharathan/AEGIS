# Security Assessment Report: JUICE_SHOP

| | |
|---|---|
| **Target URL**      | http://127.0.0.1:3000 |
| **Scan Date**       | 2026-03-31 06:39 |
| **Total Findings**  | 66 |
| **Critical / High** | 33 |
| **Framework**       | OWASP Top 10 (2021) |

---

## Executive Summary

| # | Severity | Tool | Finding |
|---|----------|------|---------|
| 1 | 🔴 CRITICAL | OWASP A01 | Admin/restricted path reachable without auth: /administratio |
| 2 | 🔴 CRITICAL | OWASP A01 | Admin/restricted path reachable without auth: /admin |
| 3 | 🔴 CRITICAL | OWASP A01 | Admin/restricted path reachable without auth: /metrics |
| 4 | 🔴 CRITICAL | OWASP A01 | Admin/restricted path reachable without auth: /#/administrat |
| 5 | 🔴 CRITICAL | OWASP A01 | Sensitive path accessible without auth: /backup |
| 6 | 🔴 CRITICAL | OWASP A01 | Sensitive path accessible without auth: /backup.zip |
| 7 | 🔴 CRITICAL | OWASP A01 | Sensitive path accessible without auth: /backup.sql |
| 8 | 🔴 CRITICAL | OWASP A01 | Sensitive path accessible without auth: /dump.sql |
| 9 | 🔴 CRITICAL | OWASP A01 | Sensitive path accessible without auth: /.git/HEAD |
| 10 | 🔴 CRITICAL | OWASP A01 | Sensitive path accessible without auth: /.env |
| 11 | 🔴 CRITICAL | OWASP A01 | Sensitive path accessible without auth: /actuator/env |
| 12 | 🔴 CRITICAL | OWASP A07 | JWT 'none' algorithm accepted at /rest/user/whoami |
| 13 | 🟠 HIGH | Nikto | Wildcard CORS origin — any site can read responses |
| 14 | 🟠 HIGH | SQLMap | SQLi in q (GET http://127.0.0.1:3000/rest) |
| 15 | 🟠 HIGH | OWASP A02 | Application served over plain HTTP (no TLS) |
| 16 | 🟠 HIGH | OWASP A05 | CORS wildcard — any origin can read responses |
| 17 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /config.php |
| 18 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /web.config |
| 19 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /server-status |
| 20 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /phpinfo.php |
| 21 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /info.php |
| 22 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /swagger-ui.html |
| 23 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /swagger-ui/ |
| 24 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /openapi.json |
| 25 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /graphql |
| 26 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /graphiql |
| 27 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /actuator |
| 28 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /console |
| 29 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /h2-console |
| 30 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /manager/html |
| 31 | 🟠 HIGH | OWASP A07 | Sensitive endpoint accessible without auth: /rest/memories |
| 32 | 🟠 HIGH | OWASP A07 | Sensitive endpoint accessible without auth: /rest/products/1 |
| 33 | 🟠 HIGH | OWASP A07 | Sensitive endpoint accessible without auth: /api/Feedbacks |
| 34 | 🟡 MEDIUM | Nikto | Clickjacking protection header missing |
| 35 | 🟡 MEDIUM | Nikto | FTP directory listing exposed |
| 36 | 🟡 MEDIUM | OWASP A05 | HSTS missing |
| 37 | 🟡 MEDIUM | OWASP A05 | CSP missing — XSS risk increased |
| 38 | 🔵 LOW | Nikto | ETag header may leak inode information |
| 39 | 🔵 LOW | Nikto | MIME-sniffing protection header missing |
| 40 | 🔵 LOW | OWASP A05 | Referrer-Policy missing |
| 41 | 🔵 LOW | OWASP A05 | Permissions-Policy missing |
| 42 | ⚪ INFO | Nikto | Server: No banner retrieved |
| 43 | ⚪ INFO | Nikto | Uncommon header 'feature-policy' found, with contents: payme |
| 44 | ⚪ INFO | Nikto | Uncommon header 'x-recruiting' found, with contents: /#/jobs |
| 45 | ⚪ INFO | Nikto | No CGI Directories found (use '-C all' to force check all po |
| 46 | ⚪ INFO | Nikto | "robots.txt" contains 1 entry which should be manually viewe |
| 47 | ⚪ INFO | Nikto | lines |
| 48 | ⚪ INFO | Nikto | /crossdomain.xml contains 0 line which should be manually vi |
| 49 | ⚪ INFO | Nikto | Uncommon header 'access-control-allow-methods' found, with c |
| 50 | ⚪ INFO | Nikto | 0 items checked: 1 error(s) and 11 item(s) reported on remot |
| 51 | ⚪ INFO | Nikto | End Time:           2026-03-31 06:37:07 (GMT5.5) (13 seconds |
| 52 | ⚪ INFO | Nikto | 1 host(s) tested |
| 53 | ⚪ INFO | Nuclei | Owasp Juice Shop Detect |
| 54 | ⚪ INFO | Nuclei | Swagger Api |
| 55 | ⚪ INFO | Nuclei | Addeventlistener Detect |
| 56 | ⚪ INFO | Nuclei | Http Missing Security Headers:Content Security Policy |
| 57 | ⚪ INFO | Nuclei | Http Missing Security Headers:Permissions Policy |
| 58 | ⚪ INFO | Nuclei | Http Missing Security Headers:X Permitted Cross Domain Polic |
| 59 | ⚪ INFO | Nuclei | Http Missing Security Headers:Clear Site Data |
| 60 | ⚪ INFO | Nuclei | Http Missing Security Headers:Cross Origin Embedder Policy |
| 61 | ⚪ INFO | Nuclei | Http Missing Security Headers:Cross Origin Opener Policy |
| 62 | ⚪ INFO | Nuclei | Http Missing Security Headers:Missing Content Type |
| 63 | ⚪ INFO | Nuclei | Http Missing Security Headers:Strict Transport Security |
| 64 | ⚪ INFO | Nuclei | Http Missing Security Headers:Referrer Policy |
| 65 | ⚪ INFO | Nuclei | Http Missing Security Headers:Cross Origin Resource Policy |
| 66 | ⚪ INFO | Nuclei | Owasp Juice Shop Detect |

---

## 1. Infrastructure Scan (Nikto)

**Summary:** 🟠 HIGH: 1 | 🟡 MEDIUM: 2 | 🔵 LOW: 2 | ⚪ INFO: 11

### Finding N-01 — 🟠 HIGH
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | Wildcard CORS origin — any site can read responses |
| **Remediation** | Restrict CORS to known trusted origins only. |

> Raw: `Uncommon header 'access-control-allow-origin' found, with contents: *`

### Finding N-02 — 🟡 MEDIUM
| Field | Detail |
|-------|--------|
| **Severity**    | 🟡 MEDIUM |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | Clickjacking protection header missing |
| **Remediation** | Add `X-Frame-Options: DENY` or `SAMEORIGIN` to all responses. |

> Raw: `Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN`

### Finding N-03 — 🟡 MEDIUM
| Field | Detail |
|-------|--------|
| **Severity**    | 🟡 MEDIUM |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | FTP directory listing exposed |
| **Remediation** | Disable directory listing; restrict /ftp access. |

> Raw: `File/dir '/ftp/' in robots.txt returned a non-forbidden or redirect HTTP code (200)`

### Finding N-04 — 🔵 LOW
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | ETag header may leak inode information |
| **Remediation** | Configure web server to use content-hash ETags. |

> Raw: `Server leaks inodes via ETags, header found with file /, fields: 0xW/124fa 0x19d41606f87`

### Finding N-05 — 🔵 LOW
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | MIME-sniffing protection header missing |
| **Remediation** | Add `X-Content-Type-Options: nosniff` to all responses. |

> Raw: `Uncommon header 'x-content-type-options' found, with contents: nosniff`

### Finding N-06 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | Server: No banner retrieved |
| **Remediation** | Review this finding manually. |

> Raw: `Server: No banner retrieved`

### Finding N-07 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | Uncommon header 'feature-policy' found, with contents: payment 'self' |
| **Remediation** | Review this finding manually. |

> Raw: `Uncommon header 'feature-policy' found, with contents: payment 'self'`

### Finding N-08 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | Uncommon header 'x-recruiting' found, with contents: /#/jobs |
| **Remediation** | Review this finding manually. |

> Raw: `Uncommon header 'x-recruiting' found, with contents: /#/jobs`

### Finding N-09 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | No CGI Directories found (use '-C all' to force check all possible dirs) |
| **Remediation** | Review this finding manually. |

> Raw: `No CGI Directories found (use '-C all' to force check all possible dirs)`

### Finding N-10 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | "robots.txt" contains 1 entry which should be manually viewed. |
| **Remediation** | Review this finding manually. |

> Raw: `"robots.txt" contains 1 entry which should be manually viewed.`

### Finding N-11 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | lines |
| **Remediation** | Review this finding manually. |

> Raw: `lines`

### Finding N-12 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `/crossdomain.xml contains 0 line which should be manually viewed for improper domains or wildcards.` |
| **Description** | /crossdomain.xml contains 0 line which should be manually viewed for improper domains or wildcards. |
| **Remediation** | Review this finding manually. |

> Raw: `/crossdomain.xml contains 0 line which should be manually viewed for improper domains or wildcards.`

### Finding N-13 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | Uncommon header 'access-control-allow-methods' found, with contents: GET,HEAD,PUT,PATCH,POST,DELETE |
| **Remediation** | Review this finding manually. |

> Raw: `Uncommon header 'access-control-allow-methods' found, with contents: GET,HEAD,PUT,PATCH,POST,DELETE`

### Finding N-14 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | 0 items checked: 1 error(s) and 11 item(s) reported on remote host |
| **Remediation** | Review this finding manually. |

> Raw: `0 items checked: 1 error(s) and 11 item(s) reported on remote host`

### Finding N-15 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | End Time:           2026-03-31 06:37:07 (GMT5.5) (13 seconds) |
| **Remediation** | Review this finding manually. |

> Raw: `End Time:           2026-03-31 06:37:07 (GMT5.5) (13 seconds)`

### Finding N-16 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | 1 host(s) tested |
| **Remediation** | Review this finding manually. |

> Raw: `1 host(s) tested`

<details><summary>Full raw Nikto output</summary>

```
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          127.0.0.1
+ Target Hostname:    localhost
+ Target Port:        3000
+ Start Time:         2026-03-31 06:36:54 (GMT5.5)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ Server leaks inodes via ETags, header found with file /, fields: 0xW/124fa 0x19d41606f87 
+ Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN
+ Uncommon header 'feature-policy' found, with contents: payment 'self'
+ Uncommon header 'access-control-allow-origin' found, with contents: *
+ Uncommon header 'x-content-type-options' found, with contents: nosniff
+ Uncommon header 'x-recruiting' found, with contents: /#/jobs
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ File/dir '/ftp/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 1 entry which should be manually viewed.
+ lines
+ /crossdomain.xml contains 0 line which should be manually viewed for improper domains or wildcards.
+ Uncommon header 'access-control-allow-methods' found, with contents: GET,HEAD,PUT,PATCH,POST,DELETE
+ 0 items checked: 1 error(s) and 11 item(s) reported on remote host
+ End Time:           2026-03-31 06:37:07 (GMT5.5) (13 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```
</details>

---

## 2. Vulnerability Scan (Nuclei)

**Summary:** ⚪ INFO: 14

### Finding V-01 — ⚪ INFO: Owasp Juice Shop Detect
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `owasp-juice-shop-detect` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[owasp-juice-shop-detect] [http] [info] http://127.0.0.1:3000`

### Finding V-02 — ⚪ INFO: Swagger Api
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `swagger-api` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000/api-docs/swagger.json` |
| **Matcher**     | `paths="/api-docs/swagger.json"` |

> Raw: `[swagger-api] [http] [info] http://127.0.0.1:3000/api-docs/swagger.json [paths="/api-docs/swagger.json"]`

### Finding V-03 — ⚪ INFO: Addeventlistener Detect
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `addeventlistener-detect` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[addeventlistener-detect] [http] [info] http://127.0.0.1:3000`

### Finding V-04 — ⚪ INFO: Http Missing Security Headers:Content Security Policy
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:content-security-policy` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[http-missing-security-headers:content-security-policy] [http] [info] http://127.0.0.1:3000`

### Finding V-05 — ⚪ INFO: Http Missing Security Headers:Permissions Policy
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:permissions-policy` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[http-missing-security-headers:permissions-policy] [http] [info] http://127.0.0.1:3000`

### Finding V-06 — ⚪ INFO: Http Missing Security Headers:X Permitted Cross Domain Policies
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:x-permitted-cross-domain-policies` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://127.0.0.1:3000`

### Finding V-07 — ⚪ INFO: Http Missing Security Headers:Clear Site Data
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:clear-site-data` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[http-missing-security-headers:clear-site-data] [http] [info] http://127.0.0.1:3000`

### Finding V-08 — ⚪ INFO: Http Missing Security Headers:Cross Origin Embedder Policy
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:cross-origin-embedder-policy` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://127.0.0.1:3000`

### Finding V-09 — ⚪ INFO: Http Missing Security Headers:Cross Origin Opener Policy
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:cross-origin-opener-policy` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://127.0.0.1:3000`

### Finding V-10 — ⚪ INFO: Http Missing Security Headers:Missing Content Type
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:missing-content-type` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[http-missing-security-headers:missing-content-type] [http] [info] http://127.0.0.1:3000`

### Finding V-11 — ⚪ INFO: Http Missing Security Headers:Strict Transport Security
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:strict-transport-security` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[http-missing-security-headers:strict-transport-security] [http] [info] http://127.0.0.1:3000`

### Finding V-12 — ⚪ INFO: Http Missing Security Headers:Referrer Policy
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:referrer-policy` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[http-missing-security-headers:referrer-policy] [http] [info] http://127.0.0.1:3000`

### Finding V-13 — ⚪ INFO: Http Missing Security Headers:Cross Origin Resource Policy
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:cross-origin-resource-policy` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://127.0.0.1:3000`

### Finding V-14 — ⚪ INFO: Owasp Juice Shop Detect
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `owasp-juice-shop-detect` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[owasp-juice-shop-detect] [http] [info] http://127.0.0.1:3000`

<details><summary>Full raw Nuclei output</summary>

```
[[92mowasp-juice-shop-detect[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000
[[92mswagger-api[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000/api-docs/swagger.json [[93mpaths[0m=[93m"/api-docs/swagger.json"[0m]
[[92maddeventlistener-detect[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000
[[92mhttp-missing-security-headers[0m:[1;92mcontent-security-policy[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000
[[92mhttp-missing-security-headers[0m:[1;92mpermissions-policy[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000
[[92mhttp-missing-security-headers[0m:[1;92mx-permitted-cross-domain-policies[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000
[[92mhttp-missing-security-headers[0m:[1;92mclear-site-data[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000
[[92mhttp-missing-security-headers[0m:[1;92mcross-origin-embedder-policy[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000
[[92mhttp-missing-security-headers[0m:[1;92mcross-origin-opener-policy[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000
[[92mhttp-missing-security-headers[0m:[1;92mmissing-content-type[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000
[[92mhttp-missing-security-headers[0m:[1;92mstrict-transport-security[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000
[[92mhttp-missing-security-headers[0m:[1;92mreferrer-policy[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000
[[92mhttp-missing-security-headers[0m:[1;92mcross-origin-resource-policy[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000
[[92mowasp-juice-shop-detect[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000

```
</details>

---

## 3. Injection Analysis (SQLMap)

**Summary:** 🟠 HIGH: 1

### Finding S-01 — 🟠 HIGH: SQLi in `q`
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A03 — Injection |
| **Endpoint**    | `GET http://127.0.0.1:3000/rest/products/search` |
| **Parameter**   | `q` (GET) |
| **Type**        | boolean-based blind |
| **Technique**   | AND boolean-based blind - WHERE or HAVING clause |
| **PoC Payload** | `q=test%' AND 2242=2242 AND 'wQsn%'='wQsn` |
| **Remediation** | Use parameterised queries / prepared statements. |

<details><summary>Full raw SQLMap output</summary>

#### GET http://127.0.0.1:3000/rest/products/search
```
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.10.3#pip}
|_ -| . [,]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:38:52 /2026-03-31/

[06:38:52] [WARNING] using '/tmp/sqlmap_out' as the output directory
[06:38:52] [INFO] testing connection to the target URL
[06:38:52] [INFO] checking if the target is protected by some kind of WAF/IPS
[06:38:52] [INFO] testing if the target URL content is stable
[06:38:53] [INFO] target URL content is stable
[06:38:53] [INFO] testing if GET parameter 'q' is dynamic
[06:38:53] [INFO] GET parameter 'q' appears to be dynamic
[06:38:53] [WARNING] heuristic (basic) test shows that GET parameter 'q' might not be injectable
[06:38:53] [INFO] testing for SQL injection on GET parameter 'q'
[06:38:53] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[06:38:53] [INFO] GET parameter 'q' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[06:38:53] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'SQLite' 
it looks like the back-end DBMS is 'SQLite'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'SQLite' extending provided level (3) and risk (2) values? [Y/n] Y
[06:38:53] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[06:38:53] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query)'
[06:38:53] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[06:38:53] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[06:38:54] [INFO] testing 'Generic UNION query (random number) - 1 to 20 columns'
[06:38:54] [INFO] testing 'Generic UNION query (NULL) - 21 to 40 columns'
[06:38:54] [INFO] testing 'Generic UNION query (random number) - 21 to 40 columns'
[06:38:54] [INFO] testing 'Generic UNION query (NULL) - 41 to 60 columns'
[06:38:54] [INFO] checking if the injection point on GET parameter 'q' is a false positive
[06:38:54] [WARNING] parameter length constraining mechanism detected (e.g. Suhosin patch). Potential problems in enumeration phase can be expected
GET parameter 'q' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 166 HTTP(s) requests:
---
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=test%' AND 2242=2242 AND 'wQsn%'='wQsn
---
[06:38:54] [INFO] testing SQLite
[06:38:54] [INFO] confirming SQLite
[06:38:54] [INFO] actively fingerprinting SQLite
[06:38:54] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[06:38:54] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 139 times
[06:38:54] [INFO] fetched data logged to text files under '/tmp/sqlmap_out/127.0.0.1'

[*] ending @ 06:38:54 /2026-03-31/


```

#### POST http://127.0.0.1:3000/rest/user/login
```
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.10.3#pip}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:38:55 /2026-03-31/

[06:38:55] [WARNING] using '/tmp/sqlmap_out' as the output directory
[06:38:55] [INFO] testing connection to the target URL
[06:38:55] [CRITICAL] not authorized, try to provide right HTTP authentication type and valid credentials (401). If this is intended, try to rerun by providing a valid value for option '--ignore-code'
[06:38:55] [WARNING] HTTP error codes detected during run:
401 (Unauthorized) - 1 times

[*] ending @ 06:38:55 /2026-03-31/


```

#### GET http://127.0.0.1:3000/rest/products/reviews
```
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.10.3#pip}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:38:55 /2026-03-31/

[06:38:55] [WARNING] using '/tmp/sqlmap_out' as the output directory
[06:38:55] [INFO] testing connection to the target URL
[06:38:55] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
[06:38:55] [INFO] checking if the target is protected by some kind of WAF/IPS
[06:38:55] [WARNING] reflective value(s) found and filtering out
[06:38:55] [INFO] testing if the target URL content is stable
[06:38:55] [INFO] target URL content is stable
[06:38:55] [INFO] testing if GET parameter 'id' is dynamic
[06:38:55] [WARNING] GET parameter 'id' does not appear to be dynamic
[06:38:56] [WARNING] heuristic (basic) test shows that GET parameter 'id' might not be injectable
[06:38:56] [INFO] testing for SQL injection on GET parameter 'id'
[06:38:56] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[06:38:56] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[06:38:56] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (comment)'
[06:38:57] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[06:38:57] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (Microsoft Access comment)'
[06:38:57] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:38:58] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[06:38:58] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[06:38:58] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:38:59] [INFO] testing 'SQLite AND boolean-based blind - WHERE, HAVING, GROUP BY or HAVING clause (JSON)'
[06:38:59] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[06:39:00] [INFO] testing 'PostgreSQL boolean-based blind - Parameter replace'
[06:39:00] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace'
[06:39:00] [INFO] testing 'Oracle boolean-based blind - Parameter replace'
[06:39:00] [INFO] testing 'Informix boolean-based blind - Parameter replace'
[06:39:00] [INFO] testing 'Microsoft Access boolean-based blind - Parameter replace'
[06:39:00] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL)'
[06:39:00] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL - original value)'
[06:39:00] [INFO] testing 'Boolean-based blind - Parameter replace (CASE)'
[06:39:00] [INFO] testing 'Boolean-based blind - Parameter replace (CASE - original value)'
[06:39:00] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:39:00] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[06:39:00] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:39:00] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY, GROUP BY clause'
[06:39:00] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause'
[06:39:00] [INFO] testing 'Oracle boolean-based blind - ORDER BY, GROUP BY clause'
[06:39:00] [INFO] testing 'HAVING boolean-based blind - WHERE, GROUP BY clause'
[06:39:00] [INFO] testing 'PostgreSQL boolean-based blind - Stacked queries'
[06:39:01] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF)'
[06:39:01] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[06:39:01] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[06:39:01] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[06:39:02] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[06:39:02] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[06:39:02] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT)'
[06:39:02] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT)'
[06:39:03] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[06:39:03] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS)'
[06:39:03] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:39:03] [INFO] testing 'Firebird AND error-based - WHERE or HAVING clause'
[06:39:03] [INFO] testing 'MonetDB AND error-based - WHERE or HAVING clause'
[06:39:04] [INFO] testing 'Vertica AND error-based - WHERE or HAVING clause'
[06:39:04] [INFO] testing 'IBM DB2 AND error-based - WHERE or HAVING clause'
[06:39:04] [INFO] testing 'ClickHouse AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:39:04] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[06:39:05] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[06:39:05] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[06:39:05] [INFO] testing 'PostgreSQL error-based - Parameter replace'
[06:39:05] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace'
[06:39:05] [INFO] testing 'Oracle error-based - Parameter replace'
[06:39:05] [INFO] testing 'MySQL >= 5.6 error-based - ORDER BY, GROUP BY clause (GTID_SUBSET)'
[06:39:05] [INFO] testing 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)'
[06:39:05] [INFO] testing 'PostgreSQL error-based - ORDER BY, GROUP BY clause'
[06:39:05] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Stacking (EXEC)'
[06:39:05] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[06:39:05] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[06:39:05] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[06:39:05] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[06:39:05] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[06:39:06] [INFO] testing 'PostgreSQL stacked queries (heavy query - comment)'
[06:39:06] [INFO] testing 'PostgreSQL < 8.2 stacked queries (Glibc - comment)'
[06:39:06] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[06:39:06] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (DECLARE - comment)'
[06:39:06] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[06:39:06] [INFO] testing 'Oracle stacked queries (heavy query - comment)'
[06:39:06] [INFO] testing 'IBM DB2 stacked queries (heavy query - comment)'
[06:39:06] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[06:39:07] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[06:39:07] [INFO] testing 'Generic UNION query (random number) - 1 to 10 columns'
[06:39:07] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[06:39:08] [INFO] testing 'MySQL UNION query (random number) - 1 to 10 columns'
[06:39:08] [WARNING] GET parameter 'id' does not seem to be injectable
[06:39:08] [INFO] testing if parameter 'User-Agent' is dynamic
[06:39:08] [WARNING] parameter 'User-Agent' does not appear to be dynamic
[06:39:08] [WARNING] heuristic (basic) test shows that parameter 'User-Agent' might not be injectable
[06:39:08] [INFO] testing for SQL injection on parameter 'User-Agent'
[06:39:08] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[06:39:09] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[06:39:09] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (comment)'
[06:39:09] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[06:39:09] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (Microsoft Access comment)'
[06:39:09] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:39:09] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[06:39:09] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[06:39:10] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:39:10] [INFO] testing 'SQLite AND boolean-based blind - WHERE, HAVING, GROUP BY or HAVING clause (JSON)'
[06:39:10] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[06:39:10] [INFO] testing 'PostgreSQL boolean-based blind - Parameter replace'
[06:39:10] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace'
[06:39:10] [INFO] testing 'Oracle boolean-based blind - Parameter replace'
[06:39:10] [INFO] testing 'Informix boolean-based blind - Parameter replace'
[06:39:10] [INFO] testing 'Microsoft Access boolean-based blind - Parameter replace'
[06:39:10] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL)'
[06:39:10] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL - original value)'
[06:39:10] [INFO] testing 'Boolean-based blind - Parameter replace (CASE)'
[06:39:10] [INFO] testing 'Boolean-based blind - Parameter replace (CASE - original value)'
[06:39:10] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:39:10] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[06:39:10] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:39:10] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY, GROUP BY clause'
[06:39:10] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause'
[06:39:10] [INFO] testing 'Oracle boolean-based blind - ORDER BY, GROUP BY clause'
[06:39:10] [INFO] testing 'HAVING boolean-based blind - WHERE, GROUP BY clause'
[06:39:10] [INFO] testing 'PostgreSQL boolean-based blind - Stacked queries'
[06:39:11] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF)'
[06:39:11] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[06:39:11] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[06:39:11] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[06:39:11] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[06:39:12] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[06:39:12] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT)'
[06:39:12] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT)'
[06:39:12] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[06:39:12] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS)'
[06:39:13] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:39:13] [INFO] testing 'Firebird AND error-based - WHERE or HAVING clause'
[06:39:13] [INFO] testing 'MonetDB AND error-based - WHERE or HAVING clause'
[06:39:13] [INFO] testing 'Vertica AND error-based - WHERE or HAVING clause'
[06:39:13] [INFO] testing 'IBM DB2 AND error-based - WHERE or HAVING clause'
[06:39:13] [INFO] testing 'ClickHouse AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:39:14] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[06:39:14] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[06:39:14] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[06:39:14] [INFO] testing 'PostgreSQL error-based - Parameter replace'
[06:39:14] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace'
[06:39:14] [INFO] testing 'Oracle error-based - Parameter replace'
[06:39:14] [INFO] testing 'MySQL >= 5.6 error-based - ORDER BY, GROUP BY clause (GTID_SUBSET)'
[06:39:14] [INFO] testing 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)'
[06:39:14] [INFO] testing 'PostgreSQL error-based - ORDER BY, GROUP BY clause'
[06:39:14] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Stacking (EXEC)'
[06:39:14] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[06:39:14] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[06:39:14] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[06:39:14] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[06:39:15] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[06:39:15] [INFO] testing 'PostgreSQL stacked queries (heavy query - comment)'
[06:39:15] [INFO] testing 'PostgreSQL < 8.2 stacked queries (Glibc - comment)'
[06:39:15] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[06:39:15] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (DECLARE - comment)'
[06:39:15] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[06:39:15] [INFO] testing 'Oracle stacked queries (heavy query - comment)'
[06:39:15] [INFO] testing 'IBM DB2 stacked queries (heavy query - comment)'
[06:39:15] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[06:39:16] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[06:39:16] [INFO] testing 'Generic UNION query (random number) - 1 to 10 columns'
[06:39:16] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[06:39:17] [INFO] testing 'MySQL UNION query (random number) - 1 to 10 columns'
[06:39:17] [WARNING] parameter 'User-Agent' does not seem to be injectable
[06:39:17] [INFO] testing if parameter 'Referer' is dynamic
[06:39:17] [WARNING] parameter 'Referer' does not appear to be dynamic
[06:39:17] [WARNING] heuristic (basic) test shows that parameter 'Referer' might not be injectable
[06:39:17] [INFO] testing for SQL injection on parameter 'Referer'
[06:39:17] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[06:39:17] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[06:39:17] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (comment)'
[06:39:17] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[06:39:18] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (Microsoft Access comment)'
[06:39:18] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:39:18] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[06:39:18] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[06:39:18] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:39:19] [INFO] testing 'SQLite AND boolean-based blind - WHERE, HAVING, GROUP BY or HAVING clause (JSON)'
[06:39:19] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[06:39:19] [INFO] testing 'PostgreSQL boolean-based blind - Parameter replace'
[06:39:19] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace'
[06:39:19] [INFO] testing 'Oracle boolean-based blind - Parameter replace'
[06:39:19] [INFO] testing 'Informix boolean-based blind - Parameter replace'
[06:39:19] [INFO] testing 'Microsoft Access boolean-based blind - Parameter replace'
[06:39:19] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL)'
[06:39:19] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL - original value)'
[06:39:19] [INFO] testing 'Boolean-based blind - Parameter replace (CASE)'
[06:39:19] [INFO] testing 'Boolean-based blind - Parameter replace (CASE - original value)'
[06:39:19] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:39:19] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[06:39:19] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:39:19] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY, GROUP BY clause'
[06:39:19] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause'
[06:39:19] [INFO] testing 'Oracle boolean-based blind - ORDER BY, GROUP BY clause'
[06:39:19] [INFO] testing 'HAVING boolean-based blind - WHERE, GROUP BY clause'
[06:39:19] [INFO] testing 'PostgreSQL boolean-based blind - Stacked queries'
[06:39:19] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF)'
[06:39:19] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[06:39:20] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[06:39:20] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[06:39:20] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[06:39:20] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[06:39:20] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT)'
[06:39:20] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT)'
[06:39:21] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[06:39:21] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS)'
[06:39:21] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:39:21] [INFO] testing 'Firebird AND error-based - WHERE or HAVING clause'
[06:39:21] [INFO] testing 'MonetDB AND error-based - WHERE or HAVING clause'
[06:39:22] [INFO] testing 'Vertica AND error-based - WHERE or HAVING clause'
[06:39:22] [INFO] testing 'IBM DB2 AND error-based - WHERE or HAVING clause'
[06:39:22] [INFO] testing 'ClickHouse AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:39:22] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[06:39:22] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[06:39:22] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[06:39:22] [INFO] testing 'PostgreSQL error-based - Parameter replace'
[06:39:22] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace'
[06:39:22] [INFO] testing 'Oracle error-based - Parameter replace'
[06:39:22] [INFO] testing 'MySQL >= 5.6 error-based - ORDER BY, GROUP BY clause (GTID_SUBSET)'
[06:39:22] [INFO] testing 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)'
[06:39:22] [INFO] testing 'PostgreSQL error-based - ORDER BY, GROUP BY clause'
[06:39:22] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Stacking (EXEC)'
[06:39:23] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[06:39:23] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[06:39:23] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[06:39:23] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[06:39:23] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[06:39:23] [INFO] testing 'PostgreSQL stacked queries (heavy query - comment)'
[06:39:23] [INFO] testing 'PostgreSQL < 8.2 stacked queries (Glibc - comment)'
[06:39:23] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[06:39:23] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (DECLARE - comment)'
[06:39:24] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[06:39:24] [INFO] testing 'Oracle stacked queries (heavy query - comment)'
[06:39:24] [INFO] testing 'IBM DB2 stacked queries (heavy query - comment)'
[06:39:24] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[06:39:24] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[06:39:24] [INFO] testing 'Generic UNION query (random number) - 1 to 10 columns'
[06:39:25] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[06:39:25] [INFO] testing 'MySQL UNION query (random number) - 1 to 10 columns'
[06:39:26] [WARNING] parameter 'Referer' does not seem to be injectable
[06:39:26] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. Rerun without providing the option '--technique'. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'
[06:39:26] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 3127 times

[*] ending @ 06:39:26 /2026-03-31/


```
</details>

---

## 4. OWASP Top 10 Active Checks

**Summary:** 🔴 CRITICAL: 12 | 🟠 HIGH: 19 | 🟡 MEDIUM: 2 | 🔵 LOW: 2

### A01 — Broken Access Control
#### Finding O-01 — 🔴 CRITICAL: Admin/restricted path reachable without auth: /administration
| Field | Detail |
|-------|--------|
| **Severity**    | 🔴 CRITICAL |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/administration` |
| **Description** | The path `/administration` returned HTTP 200 with no credentials. |
| **Remediation** | Require authentication and authorisation on all admin paths. |
| **Evidence**    | `HTTP 200` |

#### Finding O-02 — 🔴 CRITICAL: Admin/restricted path reachable without auth: /admin
| Field | Detail |
|-------|--------|
| **Severity**    | 🔴 CRITICAL |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/admin` |
| **Description** | The path `/admin` returned HTTP 200 with no credentials. |
| **Remediation** | Require authentication and authorisation on all admin paths. |
| **Evidence**    | `HTTP 200` |

#### Finding O-03 — 🔴 CRITICAL: Admin/restricted path reachable without auth: /metrics
| Field | Detail |
|-------|--------|
| **Severity**    | 🔴 CRITICAL |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/metrics` |
| **Description** | The path `/metrics` returned HTTP 200 with no credentials. |
| **Remediation** | Require authentication and authorisation on all admin paths. |
| **Evidence**    | `HTTP 200` |

#### Finding O-04 — 🔴 CRITICAL: Admin/restricted path reachable without auth: /#/administration
| Field | Detail |
|-------|--------|
| **Severity**    | 🔴 CRITICAL |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/#/administration` |
| **Description** | The path `/#/administration` returned HTTP 200 with no credentials. |
| **Remediation** | Require authentication and authorisation on all admin paths. |
| **Evidence**    | `HTTP 200` |

#### Finding O-05 — 🔴 CRITICAL: Sensitive path accessible without auth: /backup
| Field | Detail |
|-------|--------|
| **Severity**    | 🔴 CRITICAL |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/backup` |
| **Description** | `/backup` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-06 — 🔴 CRITICAL: Sensitive path accessible without auth: /backup.zip
| Field | Detail |
|-------|--------|
| **Severity**    | 🔴 CRITICAL |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/backup.zip` |
| **Description** | `/backup.zip` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-07 — 🔴 CRITICAL: Sensitive path accessible without auth: /backup.sql
| Field | Detail |
|-------|--------|
| **Severity**    | 🔴 CRITICAL |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/backup.sql` |
| **Description** | `/backup.sql` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-08 — 🔴 CRITICAL: Sensitive path accessible without auth: /dump.sql
| Field | Detail |
|-------|--------|
| **Severity**    | 🔴 CRITICAL |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/dump.sql` |
| **Description** | `/dump.sql` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-09 — 🔴 CRITICAL: Sensitive path accessible without auth: /.git/HEAD
| Field | Detail |
|-------|--------|
| **Severity**    | 🔴 CRITICAL |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/.git/HEAD` |
| **Description** | `/.git/HEAD` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-10 — 🔴 CRITICAL: Sensitive path accessible without auth: /.env
| Field | Detail |
|-------|--------|
| **Severity**    | 🔴 CRITICAL |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/.env` |
| **Description** | `/.env` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-11 — 🔴 CRITICAL: Sensitive path accessible without auth: /actuator/env
| Field | Detail |
|-------|--------|
| **Severity**    | 🔴 CRITICAL |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/actuator/env` |
| **Description** | `/actuator/env` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-12 — 🟠 HIGH: Sensitive path accessible without auth: /config.php
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/config.php` |
| **Description** | `/config.php` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-13 — 🟠 HIGH: Sensitive path accessible without auth: /web.config
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/web.config` |
| **Description** | `/web.config` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-14 — 🟠 HIGH: Sensitive path accessible without auth: /server-status
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/server-status` |
| **Description** | `/server-status` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-15 — 🟠 HIGH: Sensitive path accessible without auth: /phpinfo.php
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/phpinfo.php` |
| **Description** | `/phpinfo.php` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-16 — 🟠 HIGH: Sensitive path accessible without auth: /info.php
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/info.php` |
| **Description** | `/info.php` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-17 — 🟠 HIGH: Sensitive path accessible without auth: /swagger-ui.html
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/swagger-ui.html` |
| **Description** | `/swagger-ui.html` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-18 — 🟠 HIGH: Sensitive path accessible without auth: /swagger-ui/
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/swagger-ui/` |
| **Description** | `/swagger-ui/` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-19 — 🟠 HIGH: Sensitive path accessible without auth: /openapi.json
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/openapi.json` |
| **Description** | `/openapi.json` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-20 — 🟠 HIGH: Sensitive path accessible without auth: /graphql
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/graphql` |
| **Description** | `/graphql` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-21 — 🟠 HIGH: Sensitive path accessible without auth: /graphiql
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/graphiql` |
| **Description** | `/graphiql` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-22 — 🟠 HIGH: Sensitive path accessible without auth: /actuator
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/actuator` |
| **Description** | `/actuator` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-23 — 🟠 HIGH: Sensitive path accessible without auth: /console
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/console` |
| **Description** | `/console` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-24 — 🟠 HIGH: Sensitive path accessible without auth: /h2-console
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/h2-console` |
| **Description** | `/h2-console` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

#### Finding O-25 — 🟠 HIGH: Sensitive path accessible without auth: /manager/html
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:3000/manager/html` |
| **Description** | `/manager/html` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->

<!doctype html>
<html l` |

### A02 — Cryptographic Failures
#### Finding O-26 — 🟠 HIGH: Application served over plain HTTP (no TLS)
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A02 — Cryptographic Failures |
| **Endpoint**    | `http://127.0.0.1:3000` |
| **Description** | All traffic is unencrypted. Credentials and tokens are exposed on the network. |
| **Remediation** | Deploy TLS everywhere. Redirect HTTP→HTTPS. Enable HSTS. |

### A05 — Security Misconfiguration
#### Finding O-27 — 🟠 HIGH: CORS wildcard — any origin can read responses
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A05 — Security Misconfiguration |
| **Endpoint**    | `http://127.0.0.1:3000` |
| **Description** | `Access-Control-Allow-Origin: *` allows cross-origin reads from any site. |
| **Remediation** | Restrict CORS to a known allowlist. Never use * with credentials. |
| **Evidence**    | `*` |

#### Finding O-28 — 🟡 MEDIUM: HSTS missing
| Field | Detail |
|-------|--------|
| **Severity**    | 🟡 MEDIUM |
| **OWASP**       | A05 — Security Misconfiguration |
| **Endpoint**    | `http://127.0.0.1:3000` |
| **Description** | The `strict-transport-security` security header is absent. |
| **Remediation** | Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`. |

#### Finding O-29 — 🟡 MEDIUM: CSP missing — XSS risk increased
| Field | Detail |
|-------|--------|
| **Severity**    | 🟡 MEDIUM |
| **OWASP**       | A05 — Security Misconfiguration |
| **Endpoint**    | `http://127.0.0.1:3000` |
| **Description** | The `content-security-policy` security header is absent. |
| **Remediation** | Define a restrictive Content-Security-Policy. |

#### Finding O-30 — 🔵 LOW: Referrer-Policy missing
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **OWASP**       | A05 — Security Misconfiguration |
| **Endpoint**    | `http://127.0.0.1:3000` |
| **Description** | The `referrer-policy` security header is absent. |
| **Remediation** | Set `Referrer-Policy: no-referrer` or `strict-origin`. |

#### Finding O-31 — 🔵 LOW: Permissions-Policy missing
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **OWASP**       | A05 — Security Misconfiguration |
| **Endpoint**    | `http://127.0.0.1:3000` |
| **Description** | The `permissions-policy` security header is absent. |
| **Remediation** | Restrict browser features with a Permissions-Policy header. |

### A07 — Identification & Authentication Failures
#### Finding O-32 — 🔴 CRITICAL: JWT 'none' algorithm accepted at /rest/user/whoami
| Field | Detail |
|-------|--------|
| **Severity**    | 🔴 CRITICAL |
| **OWASP**       | A07 — Identification & Authentication Failures |
| **Endpoint**    | `http://127.0.0.1:3000/rest/user/whoami` |
| **Description** | Server accepted a JWT with `alg: none` — signature verification is skipped. |
| **Remediation** | Explicitly reject `alg: none`. Whitelist permitted algorithms server-side. |
| **Evidence**    | `HTTP 200` |

#### Finding O-33 — 🟠 HIGH: Sensitive endpoint accessible without auth: /rest/memories
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A07 — Identification & Authentication Failures |
| **Endpoint**    | `http://127.0.0.1:3000/rest/memories` |
| **Description** | `/rest/memories` returned HTTP 200 (6134 bytes) with no credentials. |
| **Remediation** | Protect all sensitive endpoints with authentication middleware. |
| **Evidence**    | `{"status":"success","data":[{"UserId":13,"id":1,"caption":"😼 #zatschi #whoneedsfourlegs","imagePath":"assets/public/images/uploads/ᓚᘏᗢ-#zatschi-#whone` |

#### Finding O-34 — 🟠 HIGH: Sensitive endpoint accessible without auth: /rest/products/1/reviews
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A07 — Identification & Authentication Failures |
| **Endpoint**    | `http://127.0.0.1:3000/rest/products/1/reviews` |
| **Description** | `/rest/products/1/reviews` returned HTTP 200 (172 bytes) with no credentials. |
| **Remediation** | Protect all sensitive endpoints with authentication middleware. |
| **Evidence**    | `{"status":"success","data":[{"message":"One of my favorites!","author":"admin@juice-sh.op","product":1,"likesCount":0,"likedBy":[],"_id":"TcxLSoJKa3SJ` |

#### Finding O-35 — 🟠 HIGH: Sensitive endpoint accessible without auth: /api/Feedbacks
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A07 — Identification & Authentication Failures |
| **Endpoint**    | `http://127.0.0.1:3000/api/Feedbacks` |
| **Description** | `/api/Feedbacks` returned HTTP 200 (1734 bytes) with no credentials. |
| **Remediation** | Protect all sensitive endpoints with authentication middleware. |
| **Evidence**    | `{"status":"success","data":[{"UserId":1,"id":1,"comment":"I love this shop! Best products in town! Highly recommended! (***in@juice-sh.op)","rating":5` |

