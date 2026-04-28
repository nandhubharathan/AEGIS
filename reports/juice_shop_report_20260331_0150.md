# Security Assessment Report: JUICE_SHOP

| | |
|---|---|
| **Target URL**      | http://127.0.0.1:3000 |
| **Scan Date**       | 2026-03-31 01:50 |
| **Total Findings**  | 20 |
| **Critical / High** | 1 |

---

## Executive Summary

| # | Severity | Tool | Finding |
|---|----------|------|---------|
| 1 | 🟠 HIGH | SQLMap | SQLi in q (GET http://127.0.0.1:3000/rest/products/) |
| 2 | 🟡 MEDIUM | Nikto | Clickjacking protection header missing |
| 3 | 🟡 MEDIUM | Nikto | FTP directory listing exposed |
| 4 | 🔵 LOW | Nikto | ETag header may leak inode information |
| 5 | 🔵 LOW | Nikto | MIME-sniffing protection header missing |
| 6 | ⚪ INFO | Nikto | Server: No banner retrieved |
| 7 | ⚪ INFO | Nikto | Uncommon header 'x-recruiting' found, with contents: /#/jobs |
| 8 | ⚪ INFO | Nikto | Uncommon header 'access-control-allow-origin' found, with co |
| 9 | ⚪ INFO | Nikto | Uncommon header 'feature-policy' found, with contents: payme |
| 10 | ⚪ INFO | Nikto | No CGI Directories found (use '-C all' to force check all po |
| 11 | ⚪ INFO | Nikto | "robots.txt" contains 1 entry which should be manually viewe |
| 12 | ⚪ INFO | Nikto | lines |
| 13 | ⚪ INFO | Nikto | /crossdomain.xml contains 0 line which should be manually vi |
| 14 | ⚪ INFO | Nikto | Uncommon header 'access-control-allow-methods' found, with c |
| 15 | ⚪ INFO | Nikto | 0 items checked: 1 error(s) and 11 item(s) reported on remot |
| 16 | ⚪ INFO | Nikto | End Time:           2026-03-31 01:49:38 (GMT5.5) (13 seconds |
| 17 | ⚪ INFO | Nikto | 1 host(s) tested |
| 18 | ⚪ INFO | Nuclei | Fingerprinthub Web Fingerprints:Qm System |
| 19 | ⚪ INFO | Nuclei | Owasp Juice Shop Detect |
| 20 | ⚪ INFO | Nuclei | Owasp Juice Shop Detect |

---

## 1. Infrastructure Scan (Nikto)

**Summary:** 🟡 MEDIUM: 2 | 🔵 LOW: 2 | ⚪ INFO: 12

### Finding N-01 — 🟡 MEDIUM
| Field | Detail |
|-------|--------|
| **Severity**    | 🟡 MEDIUM |
| **Path**        | `(server-level)` |
| **Description** | Clickjacking protection header missing |
| **Remediation** | Add `X-Frame-Options: DENY` or `SAMEORIGIN` to all responses. |

> Raw: `Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN`

### Finding N-02 — 🟡 MEDIUM
| Field | Detail |
|-------|--------|
| **Severity**    | 🟡 MEDIUM |
| **Path**        | `(server-level)` |
| **Description** | FTP directory listing exposed |
| **Remediation** | Disable directory listing; restrict /ftp access. |

> Raw: `File/dir '/ftp/' in robots.txt returned a non-forbidden or redirect HTTP code (200)`

### Finding N-03 — 🔵 LOW
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **Path**        | `(server-level)` |
| **Description** | ETag header may leak inode information |
| **Remediation** | Configure web server to use content-hash ETags instead of inodes. |

> Raw: `Server leaks inodes via ETags, header found with file /, fields: 0xW/124fa 0x19d40555029`

### Finding N-04 — 🔵 LOW
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **Path**        | `(server-level)` |
| **Description** | MIME-sniffing protection header missing |
| **Remediation** | Add `X-Content-Type-Options: nosniff` to all responses. |

> Raw: `Uncommon header 'x-content-type-options' found, with contents: nosniff`

### Finding N-05 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | Server: No banner retrieved |
| **Remediation** | Review this finding manually. |

> Raw: `Server: No banner retrieved`

### Finding N-06 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | Uncommon header 'x-recruiting' found, with contents: /#/jobs |
| **Remediation** | Review this finding manually. |

> Raw: `Uncommon header 'x-recruiting' found, with contents: /#/jobs`

### Finding N-07 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | Uncommon header 'access-control-allow-origin' found, with contents: * |
| **Remediation** | Review this finding manually. |

> Raw: `Uncommon header 'access-control-allow-origin' found, with contents: *`

### Finding N-08 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | Uncommon header 'feature-policy' found, with contents: payment 'self' |
| **Remediation** | Review this finding manually. |

> Raw: `Uncommon header 'feature-policy' found, with contents: payment 'self'`

### Finding N-09 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | No CGI Directories found (use '-C all' to force check all possible dirs) |
| **Remediation** | Review this finding manually. |

> Raw: `No CGI Directories found (use '-C all' to force check all possible dirs)`

### Finding N-10 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | "robots.txt" contains 1 entry which should be manually viewed. |
| **Remediation** | Review this finding manually. |

> Raw: `"robots.txt" contains 1 entry which should be manually viewed.`

### Finding N-11 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | lines |
| **Remediation** | Review this finding manually. |

> Raw: `lines`

### Finding N-12 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `/crossdomain.xml contains 0 line which should be manually viewed for improper domains or wildcards.` |
| **Description** | /crossdomain.xml contains 0 line which should be manually viewed for improper domains or wildcards. |
| **Remediation** | Review this finding manually. |

> Raw: `/crossdomain.xml contains 0 line which should be manually viewed for improper domains or wildcards.`

### Finding N-13 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | Uncommon header 'access-control-allow-methods' found, with contents: GET,HEAD,PUT,PATCH,POST,DELETE |
| **Remediation** | Review this finding manually. |

> Raw: `Uncommon header 'access-control-allow-methods' found, with contents: GET,HEAD,PUT,PATCH,POST,DELETE`

### Finding N-14 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | 0 items checked: 1 error(s) and 11 item(s) reported on remote host |
| **Remediation** | Review this finding manually. |

> Raw: `0 items checked: 1 error(s) and 11 item(s) reported on remote host`

### Finding N-15 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | End Time:           2026-03-31 01:49:38 (GMT5.5) (13 seconds) |
| **Remediation** | Review this finding manually. |

> Raw: `End Time:           2026-03-31 01:49:38 (GMT5.5) (13 seconds)`

### Finding N-16 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
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
+ Start Time:         2026-03-31 01:49:25 (GMT5.5)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ Server leaks inodes via ETags, header found with file /, fields: 0xW/124fa 0x19d40555029 
+ Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN
+ Uncommon header 'x-content-type-options' found, with contents: nosniff
+ Uncommon header 'x-recruiting' found, with contents: /#/jobs
+ Uncommon header 'access-control-allow-origin' found, with contents: *
+ Uncommon header 'feature-policy' found, with contents: payment 'self'
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ File/dir '/ftp/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 1 entry which should be manually viewed.
+ lines
+ /crossdomain.xml contains 0 line which should be manually viewed for improper domains or wildcards.
+ Uncommon header 'access-control-allow-methods' found, with contents: GET,HEAD,PUT,PATCH,POST,DELETE
+ 0 items checked: 1 error(s) and 11 item(s) reported on remote host
+ End Time:           2026-03-31 01:49:38 (GMT5.5) (13 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```
</details>

---

## 2. Vulnerability Scan (Nuclei)

**Summary:** ⚪ INFO: 3

### Finding V-01 — ⚪ INFO: Fingerprinthub Web Fingerprints:Qm System
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `fingerprinthub-web-fingerprints:qm-system` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[fingerprinthub-web-fingerprints:qm-system] [http] [info] http://127.0.0.1:3000`

### Finding V-02 — ⚪ INFO: Owasp Juice Shop Detect
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `owasp-juice-shop-detect` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[owasp-juice-shop-detect] [http] [info] http://127.0.0.1:3000`

### Finding V-03 — ⚪ INFO: Owasp Juice Shop Detect
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `owasp-juice-shop-detect` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:3000` |

> Raw: `[owasp-juice-shop-detect] [http] [info] http://127.0.0.1:3000`

<details><summary>Full raw Nuclei output</summary>

```
[[92mfingerprinthub-web-fingerprints[0m:[1;92mqm-system[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000
[[92mowasp-juice-shop-detect[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:3000
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
| **Endpoint**    | `GET http://127.0.0.1:3000/rest/products/search` |
| **Parameter**   | `q` (GET) |
| **Type**        | boolean-based blind |
| **Technique**   | AND boolean-based blind - WHERE or HAVING clause |
| **PoC Payload** | `q=test%' AND 8668=8668 AND 'DBXu%'='DBXu` |
| **Remediation** | Use parameterised queries / prepared statements. Never interpolate user input into SQL. |

<details><summary>Full raw SQLMap output</summary>

#### GET http://127.0.0.1:3000/rest/products/search
```
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.10.3#pip}
|_ -| . ["]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:50:04 /2026-03-31/

[01:50:04] [WARNING] using '/tmp/sqlmap_out' as the output directory
[01:50:04] [INFO] testing connection to the target URL
[01:50:04] [INFO] checking if the target is protected by some kind of WAF/IPS
[01:50:04] [INFO] testing if the target URL content is stable
[01:50:05] [INFO] target URL content is stable
[01:50:05] [INFO] testing if GET parameter 'q' is dynamic
[01:50:05] [INFO] GET parameter 'q' appears to be dynamic
[01:50:05] [WARNING] heuristic (basic) test shows that GET parameter 'q' might not be injectable
[01:50:05] [INFO] testing for SQL injection on GET parameter 'q'
[01:50:05] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:50:05] [INFO] GET parameter 'q' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[01:50:05] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'SQLite' 
it looks like the back-end DBMS is 'SQLite'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'SQLite' extending provided level (3) and risk (2) values? [Y/n] Y
[01:50:05] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[01:50:05] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query)'
[01:50:05] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[01:50:05] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[01:50:06] [INFO] testing 'Generic UNION query (random number) - 1 to 20 columns'
[01:50:06] [INFO] testing 'Generic UNION query (NULL) - 21 to 40 columns'
[01:50:06] [INFO] testing 'Generic UNION query (random number) - 21 to 40 columns'
[01:50:06] [INFO] testing 'Generic UNION query (NULL) - 41 to 60 columns'
[01:50:06] [INFO] checking if the injection point on GET parameter 'q' is a false positive
[01:50:06] [WARNING] parameter length constraining mechanism detected (e.g. Suhosin patch). Potential problems in enumeration phase can be expected
GET parameter 'q' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 166 HTTP(s) requests:
---
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=test%' AND 8668=8668 AND 'DBXu%'='DBXu
---
[01:50:06] [INFO] testing SQLite
[01:50:06] [INFO] confirming SQLite
[01:50:06] [INFO] actively fingerprinting SQLite
[01:50:06] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[01:50:06] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 139 times
[01:50:06] [INFO] fetched data logged to text files under '/tmp/sqlmap_out/127.0.0.1'

[*] ending @ 01:50:06 /2026-03-31/


```

#### POST http://127.0.0.1:3000/rest/user/login
```
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.10.3#pip}
|_ -| . [.]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:50:07 /2026-03-31/

[01:50:07] [WARNING] using '/tmp/sqlmap_out' as the output directory
[01:50:07] [INFO] testing connection to the target URL
[01:50:07] [CRITICAL] not authorized, try to provide right HTTP authentication type and valid credentials (401). If this is intended, try to rerun by providing a valid value for option '--ignore-code'
[01:50:07] [WARNING] HTTP error codes detected during run:
401 (Unauthorized) - 1 times

[*] ending @ 01:50:07 /2026-03-31/


```
</details>
