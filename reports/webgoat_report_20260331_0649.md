# Security Assessment Report: WEBGOAT

| | |
|---|---|
| **Target URL**      | http://127.0.0.1:8082/WebGoat |
| **Scan Date**       | 2026-03-31 06:49 |
| **Total Findings**  | 41 |
| **Critical / High** | 8 |
| **Framework**       | OWASP Top 10 (2021) |

---

## Executive Summary

| # | Severity | Tool | Finding |
|---|----------|------|---------|
| 1 | 🔴 CRITICAL | OWASP A01 | Sensitive path accessible without auth: /actuator/env |
| 2 | 🟠 HIGH | OWASP A02 | Application served over plain HTTP (no TLS) |
| 3 | 🟠 HIGH | OWASP A01 | Admin/restricted path reachable without auth: /WebGoat/actua |
| 4 | 🟠 HIGH | OWASP A01 | Admin/restricted path reachable without auth: /WebGoat/actua |
| 5 | 🟠 HIGH | OWASP A01 | Admin/restricted path reachable without auth: /WebGoat/actua |
| 6 | 🟠 HIGH | OWASP A01 | Admin/restricted path reachable without auth: /WebGoat/serve |
| 7 | 🟠 HIGH | OWASP A01 | Sensitive path accessible without auth: /actuator |
| 8 | 🟠 HIGH | OWASP A04 | No rate limiting on login endpoint |
| 9 | 🟡 MEDIUM | Nikto | Session cookie missing security flag(s) |
| 10 | 🟡 MEDIUM | Nikto | Clickjacking protection header missing |
| 11 | 🟡 MEDIUM | OWASP A05 | Clickjacking — X-Frame-Options missing |
| 12 | 🟡 MEDIUM | OWASP A05 | HSTS missing |
| 13 | 🟡 MEDIUM | OWASP A05 | CSP missing — XSS risk increased |
| 14 | 🟡 MEDIUM | OWASP A01 | No CSRF token on login/form page |
| 15 | 🔵 LOW | Nuclei | Tomcat Stacktraces |
| 16 | 🔵 LOW | Nuclei | Tomcat Stacktraces |
| 17 | 🔵 LOW | Nuclei | Springboot Env |
| 18 | 🔵 LOW | Nuclei | Springboot Configprops |
| 19 | 🔵 LOW | OWASP A05 | MIME sniffing — X-Content-Type-Options missing |
| 20 | 🔵 LOW | OWASP A05 | Referrer-Policy missing |
| 21 | 🔵 LOW | OWASP A05 | Permissions-Policy missing |
| 22 | ⚪ INFO | Nikto | Server: No banner retrieved |
| 23 | ⚪ INFO | Nikto | Root page / redirects to: http://localhost:8082/WebGoat/logi |
| 24 | ⚪ INFO | Nikto | No CGI Directories found (use '-C all' to force check all po |
| 25 | ⚪ INFO | Nikto | 0 items checked: 0 error(s) and 2 item(s) reported on remote |
| 26 | ⚪ INFO | Nikto | End Time:           2026-03-31 06:47:02 (GMT5.5) (0 seconds) |
| 27 | ⚪ INFO | Nikto | 1 host(s) tested |
| 28 | ⚪ INFO | Nuclei | Http Missing Security Headers:Referrer Policy |
| 29 | ⚪ INFO | Nuclei | Http Missing Security Headers:Clear Site Data |
| 30 | ⚪ INFO | Nuclei | Http Missing Security Headers:Cross Origin Embedder Policy |
| 31 | ⚪ INFO | Nuclei | Http Missing Security Headers:Cross Origin Opener Policy |
| 32 | ⚪ INFO | Nuclei | Http Missing Security Headers:Strict Transport Security |
| 33 | ⚪ INFO | Nuclei | Http Missing Security Headers:Content Security Policy |
| 34 | ⚪ INFO | Nuclei | Http Missing Security Headers:Cross Origin Resource Policy |
| 35 | ⚪ INFO | Nuclei | Http Missing Security Headers:Missing Content Type |
| 36 | ⚪ INFO | Nuclei | Http Missing Security Headers:Permissions Policy |
| 37 | ⚪ INFO | Nuclei | Http Missing Security Headers:X Frame Options |
| 38 | ⚪ INFO | Nuclei | Http Missing Security Headers:X Content Type Options |
| 39 | ⚪ INFO | Nuclei | Http Missing Security Headers:X Permitted Cross Domain Polic |
| 40 | ⚪ INFO | Nuclei | Missing Cookie Samesite Strict |
| 41 | ⚪ INFO | Nuclei | Springboot Health |

---

## 1. Infrastructure Scan (Nikto)

**Summary:** 🟡 MEDIUM: 2 | ⚪ INFO: 6

### Finding N-01 — 🟡 MEDIUM
| Field | Detail |
|-------|--------|
| **Severity**    | 🟡 MEDIUM |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | Session cookie missing security flag(s) |
| **Remediation** | Set HttpOnly and Secure flags on all session cookies. |

> Raw: `Cookie JSESSIONID created without the httponly flag`

### Finding N-02 — 🟡 MEDIUM
| Field | Detail |
|-------|--------|
| **Severity**    | 🟡 MEDIUM |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | Clickjacking protection header missing |
| **Remediation** | Add `X-Frame-Options: DENY` or `SAMEORIGIN` to all responses. |

> Raw: `The anti-clickjacking X-Frame-Options header is not present.`

### Finding N-03 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | Server: No banner retrieved |
| **Remediation** | Review this finding manually. |

> Raw: `Server: No banner retrieved`

### Finding N-04 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | Root page / redirects to: http://localhost:8082/WebGoat/login |
| **Remediation** | Review this finding manually. |

> Raw: `Root page / redirects to: http://localhost:8082/WebGoat/login`

### Finding N-05 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | No CGI Directories found (use '-C all' to force check all possible dirs) |
| **Remediation** | Review this finding manually. |

> Raw: `No CGI Directories found (use '-C all' to force check all possible dirs)`

### Finding N-06 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | 0 items checked: 0 error(s) and 2 item(s) reported on remote host |
| **Remediation** | Review this finding manually. |

> Raw: `0 items checked: 0 error(s) and 2 item(s) reported on remote host`

### Finding N-07 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **OWASP**       | A05 |
| **Path**        | `(server-level)` |
| **Description** | End Time:           2026-03-31 06:47:02 (GMT5.5) (0 seconds) |
| **Remediation** | Review this finding manually. |

> Raw: `End Time:           2026-03-31 06:47:02 (GMT5.5) (0 seconds)`

### Finding N-08 — ⚪ INFO
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
+ Target Port:        8082
+ Start Time:         2026-03-31 06:47:02 (GMT5.5)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ Cookie JSESSIONID created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ Root page / redirects to: http://localhost:8082/WebGoat/login
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 0 items checked: 0 error(s) and 2 item(s) reported on remote host
+ End Time:           2026-03-31 06:47:02 (GMT5.5) (0 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```
</details>

---

## 2. Vulnerability Scan (Nuclei)

**Summary:** 🔵 LOW: 4 | ⚪ INFO: 14

### Finding V-01 — 🔵 LOW: Tomcat Stacktraces
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **Template**    | `tomcat-stacktraces` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/?f=\[` |

> Raw: `[tomcat-stacktraces] [http] [low] http://127.0.0.1:8082/WebGoat/?f=\[`

### Finding V-02 — 🔵 LOW: Tomcat Stacktraces
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **Template**    | `tomcat-stacktraces` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/?f=\[` |

> Raw: `[tomcat-stacktraces] [http] [low] http://127.0.0.1:8082/WebGoat/?f=\[`

### Finding V-03 — 🔵 LOW: Springboot Env
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **Template**    | `springboot-env` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/actuator/env` |

> Raw: `[springboot-env] [http] [low] http://127.0.0.1:8082/WebGoat/actuator/env`

### Finding V-04 — 🔵 LOW: Springboot Configprops
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **Template**    | `springboot-configprops` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/actuator/configprops` |

> Raw: `[springboot-configprops] [http] [low] http://127.0.0.1:8082/WebGoat/actuator/configprops`

### Finding V-05 — ⚪ INFO: Http Missing Security Headers:Referrer Policy
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:referrer-policy` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[http-missing-security-headers:referrer-policy] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-06 — ⚪ INFO: Http Missing Security Headers:Clear Site Data
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:clear-site-data` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[http-missing-security-headers:clear-site-data] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-07 — ⚪ INFO: Http Missing Security Headers:Cross Origin Embedder Policy
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:cross-origin-embedder-policy` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-08 — ⚪ INFO: Http Missing Security Headers:Cross Origin Opener Policy
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:cross-origin-opener-policy` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-09 — ⚪ INFO: Http Missing Security Headers:Strict Transport Security
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:strict-transport-security` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[http-missing-security-headers:strict-transport-security] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-10 — ⚪ INFO: Http Missing Security Headers:Content Security Policy
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:content-security-policy` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[http-missing-security-headers:content-security-policy] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-11 — ⚪ INFO: Http Missing Security Headers:Cross Origin Resource Policy
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:cross-origin-resource-policy` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-12 — ⚪ INFO: Http Missing Security Headers:Missing Content Type
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:missing-content-type` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[http-missing-security-headers:missing-content-type] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-13 — ⚪ INFO: Http Missing Security Headers:Permissions Policy
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:permissions-policy` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[http-missing-security-headers:permissions-policy] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-14 — ⚪ INFO: Http Missing Security Headers:X Frame Options
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:x-frame-options` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[http-missing-security-headers:x-frame-options] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-15 — ⚪ INFO: Http Missing Security Headers:X Content Type Options
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:x-content-type-options` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[http-missing-security-headers:x-content-type-options] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-16 — ⚪ INFO: Http Missing Security Headers:X Permitted Cross Domain Policies
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `http-missing-security-headers:x-permitted-cross-domain-policies` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-17 — ⚪ INFO: Missing Cookie Samesite Strict
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `missing-cookie-samesite-strict` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/` |
| **Matcher**     | `"JSESSIONID=A114D2BD8EAFC32D6161F78AA609BE73; Path=/WebGoat; HttpOnly"` |

> Raw: `[missing-cookie-samesite-strict] [http] [info] http://127.0.0.1:8082/WebGoat/ ["JSESSIONID=A114D2BD8EAFC32D6161F78AA609BE73; Path=/WebGoat; HttpOnly"]`

### Finding V-18 — ⚪ INFO: Springboot Health
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `springboot-health` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/actuator/health` |

> Raw: `[springboot-health] [http] [info] http://127.0.0.1:8082/WebGoat/actuator/health`

<details><summary>Full raw Nuclei output</summary>

```
[[92mtomcat-stacktraces[0m] [[94mhttp[0m] [[32mlow[0m] http://127.0.0.1:8082/WebGoat/?f=\[
[[92mhttp-missing-security-headers[0m:[1;92mreferrer-policy[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mhttp-missing-security-headers[0m:[1;92mclear-site-data[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mhttp-missing-security-headers[0m:[1;92mcross-origin-embedder-policy[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mhttp-missing-security-headers[0m:[1;92mcross-origin-opener-policy[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mhttp-missing-security-headers[0m:[1;92mstrict-transport-security[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mhttp-missing-security-headers[0m:[1;92mcontent-security-policy[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mhttp-missing-security-headers[0m:[1;92mcross-origin-resource-policy[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mhttp-missing-security-headers[0m:[1;92mmissing-content-type[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mhttp-missing-security-headers[0m:[1;92mpermissions-policy[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mhttp-missing-security-headers[0m:[1;92mx-frame-options[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mhttp-missing-security-headers[0m:[1;92mx-content-type-options[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mhttp-missing-security-headers[0m:[1;92mx-permitted-cross-domain-policies[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mmissing-cookie-samesite-strict[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/ [[96m"JSESSIONID=A114D2BD8EAFC32D6161F78AA609BE73; Path=/WebGoat; HttpOnly"[0m]
[[92mtomcat-stacktraces[0m] [[94mhttp[0m] [[32mlow[0m] http://127.0.0.1:8082/WebGoat/?f=\[
[[92mspringboot-env[0m] [[94mhttp[0m] [[32mlow[0m] http://127.0.0.1:8082/WebGoat/actuator/env
[[92mspringboot-health[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/actuator/health
[[92mspringboot-configprops[0m] [[94mhttp[0m] [[32mlow[0m] http://127.0.0.1:8082/WebGoat/actuator/configprops

```
</details>

---

## 3. Injection Analysis (SQLMap)

_No SQL injection vulnerabilities detected by SQLMap._
<details><summary>Full raw SQLMap output</summary>

#### POST http://127.0.0.1:8082/WebGoat/SqlInjection/attack5a
```
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.10.3#pip}
|_ -| . [.]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:48:52 /2026-03-31/

[06:48:52] [WARNING] using '/tmp/sqlmap_out' as the output directory
[06:48:52] [INFO] testing connection to the target URL
got a 302 redirect to 'http://127.0.0.1:8082/WebGoat/login'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
[06:48:52] [INFO] testing if the target URL content is stable
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[06:48:52] [WARNING] POST parameter 'account' does not appear to be dynamic
[06:48:52] [WARNING] heuristic (basic) test shows that POST parameter 'account' might not be injectable
[06:48:52] [INFO] testing for SQL injection on POST parameter 'account'
[06:48:52] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[06:48:53] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[06:48:53] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (comment)'
[06:48:53] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[06:48:53] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (Microsoft Access comment)'
[06:48:53] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:48:54] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[06:48:54] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[06:48:54] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:48:55] [INFO] testing 'SQLite AND boolean-based blind - WHERE, HAVING, GROUP BY or HAVING clause (JSON)'
[06:48:55] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[06:48:55] [INFO] testing 'PostgreSQL boolean-based blind - Parameter replace'
[06:48:55] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace'
[06:48:55] [INFO] testing 'Oracle boolean-based blind - Parameter replace'
[06:48:55] [INFO] testing 'Informix boolean-based blind - Parameter replace'
[06:48:55] [INFO] testing 'Microsoft Access boolean-based blind - Parameter replace'
[06:48:55] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL)'
[06:48:55] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL - original value)'
[06:48:55] [INFO] testing 'Boolean-based blind - Parameter replace (CASE)'
[06:48:55] [INFO] testing 'Boolean-based blind - Parameter replace (CASE - original value)'
[06:48:55] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:48:55] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[06:48:55] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:48:55] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY, GROUP BY clause'
[06:48:55] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause'
[06:48:55] [INFO] testing 'Oracle boolean-based blind - ORDER BY, GROUP BY clause'
[06:48:55] [INFO] testing 'HAVING boolean-based blind - WHERE, GROUP BY clause'
[06:48:55] [INFO] testing 'PostgreSQL boolean-based blind - Stacked queries'
[06:48:56] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF)'
[06:48:56] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[06:48:56] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[06:48:56] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[06:48:56] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[06:48:57] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[06:48:57] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT)'
[06:48:57] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT)'
[06:48:57] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[06:48:58] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS)'
[06:48:58] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:48:58] [INFO] testing 'Firebird AND error-based - WHERE or HAVING clause'
[06:48:58] [INFO] testing 'MonetDB AND error-based - WHERE or HAVING clause'
[06:48:59] [INFO] testing 'Vertica AND error-based - WHERE or HAVING clause'
[06:48:59] [INFO] testing 'IBM DB2 AND error-based - WHERE or HAVING clause'
[06:48:59] [INFO] testing 'ClickHouse AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:48:59] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[06:49:00] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[06:49:00] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[06:49:00] [INFO] testing 'PostgreSQL error-based - Parameter replace'
[06:49:00] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace'
[06:49:00] [INFO] testing 'Oracle error-based - Parameter replace'
[06:49:00] [INFO] testing 'MySQL >= 5.6 error-based - ORDER BY, GROUP BY clause (GTID_SUBSET)'
[06:49:00] [INFO] testing 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)'
[06:49:00] [INFO] testing 'PostgreSQL error-based - ORDER BY, GROUP BY clause'
[06:49:00] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Stacking (EXEC)'
[06:49:00] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[06:49:00] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[06:49:00] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[06:49:00] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[06:49:00] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[06:49:01] [INFO] testing 'PostgreSQL stacked queries (heavy query - comment)'
[06:49:01] [INFO] testing 'PostgreSQL < 8.2 stacked queries (Glibc - comment)'
[06:49:01] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[06:49:01] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (DECLARE - comment)'
[06:49:01] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[06:49:01] [INFO] testing 'Oracle stacked queries (heavy query - comment)'
[06:49:01] [INFO] testing 'IBM DB2 stacked queries (heavy query - comment)'
[06:49:01] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[06:49:02] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[06:49:02] [INFO] testing 'Generic UNION query (random number) - 1 to 10 columns'
[06:49:02] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[06:49:03] [INFO] testing 'MySQL UNION query (random number) - 1 to 10 columns'
[06:49:03] [WARNING] POST parameter 'account' does not seem to be injectable
[06:49:03] [WARNING] POST parameter 'operator' does not appear to be dynamic
[06:49:03] [WARNING] heuristic (basic) test shows that POST parameter 'operator' might not be injectable
[06:49:03] [INFO] testing for SQL injection on POST parameter 'operator'
[06:49:03] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[06:49:04] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[06:49:04] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (comment)'
[06:49:04] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[06:49:04] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (Microsoft Access comment)'
[06:49:04] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:49:04] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[06:49:05] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[06:49:05] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:49:05] [INFO] testing 'SQLite AND boolean-based blind - WHERE, HAVING, GROUP BY or HAVING clause (JSON)'
[06:49:05] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[06:49:05] [INFO] testing 'PostgreSQL boolean-based blind - Parameter replace'
[06:49:05] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace'
[06:49:05] [INFO] testing 'Oracle boolean-based blind - Parameter replace'
[06:49:05] [INFO] testing 'Informix boolean-based blind - Parameter replace'
[06:49:05] [INFO] testing 'Microsoft Access boolean-based blind - Parameter replace'
[06:49:05] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL)'
[06:49:05] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL - original value)'
[06:49:05] [INFO] testing 'Boolean-based blind - Parameter replace (CASE)'
[06:49:05] [INFO] testing 'Boolean-based blind - Parameter replace (CASE - original value)'
[06:49:05] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:05] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[06:49:05] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:05] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:06] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause'
[06:49:06] [INFO] testing 'Oracle boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:06] [INFO] testing 'HAVING boolean-based blind - WHERE, GROUP BY clause'
[06:49:06] [INFO] testing 'PostgreSQL boolean-based blind - Stacked queries'
[06:49:06] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF)'
[06:49:06] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[06:49:06] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[06:49:06] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[06:49:07] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[06:49:07] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[06:49:07] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT)'
[06:49:07] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT)'
[06:49:08] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[06:49:08] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS)'
[06:49:08] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:49:08] [INFO] testing 'Firebird AND error-based - WHERE or HAVING clause'
[06:49:08] [INFO] testing 'MonetDB AND error-based - WHERE or HAVING clause'
[06:49:09] [INFO] testing 'Vertica AND error-based - WHERE or HAVING clause'
[06:49:09] [INFO] testing 'IBM DB2 AND error-based - WHERE or HAVING clause'
[06:49:09] [INFO] testing 'ClickHouse AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:49:09] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[06:49:10] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[06:49:10] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[06:49:10] [INFO] testing 'PostgreSQL error-based - Parameter replace'
[06:49:10] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace'
[06:49:10] [INFO] testing 'Oracle error-based - Parameter replace'
[06:49:10] [INFO] testing 'MySQL >= 5.6 error-based - ORDER BY, GROUP BY clause (GTID_SUBSET)'
[06:49:10] [INFO] testing 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)'
[06:49:10] [INFO] testing 'PostgreSQL error-based - ORDER BY, GROUP BY clause'
[06:49:10] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Stacking (EXEC)'
[06:49:10] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[06:49:10] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[06:49:10] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[06:49:10] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[06:49:10] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[06:49:10] [INFO] testing 'PostgreSQL stacked queries (heavy query - comment)'
[06:49:10] [INFO] testing 'PostgreSQL < 8.2 stacked queries (Glibc - comment)'
[06:49:10] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[06:49:11] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (DECLARE - comment)'
[06:49:11] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[06:49:11] [INFO] testing 'Oracle stacked queries (heavy query - comment)'
[06:49:11] [INFO] testing 'IBM DB2 stacked queries (heavy query - comment)'
[06:49:11] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[06:49:11] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[06:49:11] [INFO] testing 'Generic UNION query (random number) - 1 to 10 columns'
[06:49:12] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[06:49:12] [INFO] testing 'MySQL UNION query (random number) - 1 to 10 columns'
[06:49:13] [WARNING] POST parameter 'operator' does not seem to be injectable
[06:49:13] [WARNING] POST parameter 'injection' does not appear to be dynamic
[06:49:13] [WARNING] heuristic (basic) test shows that POST parameter 'injection' might not be injectable
[06:49:13] [INFO] testing for SQL injection on POST parameter 'injection'
[06:49:13] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[06:49:13] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[06:49:13] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (comment)'
[06:49:13] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[06:49:13] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (Microsoft Access comment)'
[06:49:13] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:49:13] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[06:49:13] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[06:49:14] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:49:14] [INFO] testing 'SQLite AND boolean-based blind - WHERE, HAVING, GROUP BY or HAVING clause (JSON)'
[06:49:14] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[06:49:14] [INFO] testing 'PostgreSQL boolean-based blind - Parameter replace'
[06:49:14] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace'
[06:49:14] [INFO] testing 'Oracle boolean-based blind - Parameter replace'
[06:49:14] [INFO] testing 'Informix boolean-based blind - Parameter replace'
[06:49:14] [INFO] testing 'Microsoft Access boolean-based blind - Parameter replace'
[06:49:14] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL)'
[06:49:14] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL - original value)'
[06:49:14] [INFO] testing 'Boolean-based blind - Parameter replace (CASE)'
[06:49:14] [INFO] testing 'Boolean-based blind - Parameter replace (CASE - original value)'
[06:49:14] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:14] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[06:49:14] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:14] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:14] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause'
[06:49:14] [INFO] testing 'Oracle boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:14] [INFO] testing 'HAVING boolean-based blind - WHERE, GROUP BY clause'
[06:49:14] [INFO] testing 'PostgreSQL boolean-based blind - Stacked queries'
[06:49:14] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF)'
[06:49:14] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[06:49:15] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[06:49:15] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[06:49:15] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[06:49:15] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[06:49:15] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT)'
[06:49:15] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT)'
[06:49:16] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[06:49:16] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS)'
[06:49:16] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:49:16] [INFO] testing 'Firebird AND error-based - WHERE or HAVING clause'
[06:49:16] [INFO] testing 'MonetDB AND error-based - WHERE or HAVING clause'
[06:49:16] [INFO] testing 'Vertica AND error-based - WHERE or HAVING clause'
[06:49:17] [INFO] testing 'IBM DB2 AND error-based - WHERE or HAVING clause'
[06:49:17] [INFO] testing 'ClickHouse AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:49:17] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[06:49:17] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[06:49:17] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[06:49:17] [INFO] testing 'PostgreSQL error-based - Parameter replace'
[06:49:17] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace'
[06:49:17] [INFO] testing 'Oracle error-based - Parameter replace'
[06:49:17] [INFO] testing 'MySQL >= 5.6 error-based - ORDER BY, GROUP BY clause (GTID_SUBSET)'
[06:49:17] [INFO] testing 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)'
[06:49:17] [INFO] testing 'PostgreSQL error-based - ORDER BY, GROUP BY clause'
[06:49:17] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Stacking (EXEC)'
[06:49:17] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[06:49:18] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[06:49:18] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[06:49:18] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[06:49:18] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[06:49:18] [INFO] testing 'PostgreSQL stacked queries (heavy query - comment)'
[06:49:18] [INFO] testing 'PostgreSQL < 8.2 stacked queries (Glibc - comment)'
[06:49:18] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[06:49:19] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (DECLARE - comment)'
[06:49:19] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[06:49:19] [INFO] testing 'Oracle stacked queries (heavy query - comment)'
[06:49:19] [INFO] testing 'IBM DB2 stacked queries (heavy query - comment)'
[06:49:19] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[06:49:19] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[06:49:20] [INFO] testing 'Generic UNION query (random number) - 1 to 10 columns'
[06:49:20] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[06:49:20] [INFO] testing 'MySQL UNION query (random number) - 1 to 10 columns'
[06:49:21] [WARNING] POST parameter 'injection' does not seem to be injectable
[06:49:21] [INFO] ignoring Cookie parameter 'JSESSIONID'
[06:49:21] [WARNING] parameter 'User-Agent' does not appear to be dynamic
[06:49:21] [WARNING] heuristic (basic) test shows that parameter 'User-Agent' might not be injectable
[06:49:21] [INFO] testing for SQL injection on parameter 'User-Agent'
[06:49:21] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[06:49:21] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[06:49:21] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (comment)'
[06:49:21] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[06:49:21] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (Microsoft Access comment)'
[06:49:21] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:49:21] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[06:49:22] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[06:49:22] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:49:22] [INFO] testing 'SQLite AND boolean-based blind - WHERE, HAVING, GROUP BY or HAVING clause (JSON)'
[06:49:22] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[06:49:22] [INFO] testing 'PostgreSQL boolean-based blind - Parameter replace'
[06:49:22] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace'
[06:49:22] [INFO] testing 'Oracle boolean-based blind - Parameter replace'
[06:49:22] [INFO] testing 'Informix boolean-based blind - Parameter replace'
[06:49:22] [INFO] testing 'Microsoft Access boolean-based blind - Parameter replace'
[06:49:22] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL)'
[06:49:22] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL - original value)'
[06:49:22] [INFO] testing 'Boolean-based blind - Parameter replace (CASE)'
[06:49:22] [INFO] testing 'Boolean-based blind - Parameter replace (CASE - original value)'
[06:49:22] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:22] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[06:49:22] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:22] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:22] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause'
[06:49:22] [INFO] testing 'Oracle boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:22] [INFO] testing 'HAVING boolean-based blind - WHERE, GROUP BY clause'
[06:49:22] [INFO] testing 'PostgreSQL boolean-based blind - Stacked queries'
[06:49:23] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF)'
[06:49:23] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[06:49:23] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[06:49:23] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[06:49:23] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[06:49:23] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[06:49:23] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT)'
[06:49:24] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT)'
[06:49:24] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[06:49:24] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS)'
[06:49:24] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:49:24] [INFO] testing 'Firebird AND error-based - WHERE or HAVING clause'
[06:49:24] [INFO] testing 'MonetDB AND error-based - WHERE or HAVING clause'
[06:49:24] [INFO] testing 'Vertica AND error-based - WHERE or HAVING clause'
[06:49:25] [INFO] testing 'IBM DB2 AND error-based - WHERE or HAVING clause'
[06:49:25] [INFO] testing 'ClickHouse AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:49:25] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[06:49:25] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[06:49:25] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[06:49:25] [INFO] testing 'PostgreSQL error-based - Parameter replace'
[06:49:25] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace'
[06:49:25] [INFO] testing 'Oracle error-based - Parameter replace'
[06:49:25] [INFO] testing 'MySQL >= 5.6 error-based - ORDER BY, GROUP BY clause (GTID_SUBSET)'
[06:49:25] [INFO] testing 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)'
[06:49:25] [INFO] testing 'PostgreSQL error-based - ORDER BY, GROUP BY clause'
[06:49:25] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Stacking (EXEC)'
[06:49:25] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[06:49:25] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[06:49:26] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[06:49:26] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[06:49:26] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[06:49:26] [INFO] testing 'PostgreSQL stacked queries (heavy query - comment)'
[06:49:26] [INFO] testing 'PostgreSQL < 8.2 stacked queries (Glibc - comment)'
[06:49:26] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[06:49:26] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (DECLARE - comment)'
[06:49:26] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[06:49:26] [INFO] testing 'Oracle stacked queries (heavy query - comment)'
[06:49:26] [INFO] testing 'IBM DB2 stacked queries (heavy query - comment)'
[06:49:27] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[06:49:27] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[06:49:27] [INFO] testing 'Generic UNION query (random number) - 1 to 10 columns'
[06:49:27] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[06:49:28] [INFO] testing 'MySQL UNION query (random number) - 1 to 10 columns'
[06:49:28] [WARNING] parameter 'User-Agent' does not seem to be injectable
[06:49:28] [WARNING] parameter 'Referer' does not appear to be dynamic
[06:49:28] [WARNING] heuristic (basic) test shows that parameter 'Referer' might not be injectable
[06:49:28] [INFO] testing for SQL injection on parameter 'Referer'
[06:49:28] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[06:49:28] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[06:49:28] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (comment)'
[06:49:28] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[06:49:28] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (Microsoft Access comment)'
[06:49:29] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:49:29] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[06:49:29] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[06:49:29] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:49:29] [INFO] testing 'SQLite AND boolean-based blind - WHERE, HAVING, GROUP BY or HAVING clause (JSON)'
[06:49:29] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[06:49:29] [INFO] testing 'PostgreSQL boolean-based blind - Parameter replace'
[06:49:29] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace'
[06:49:29] [INFO] testing 'Oracle boolean-based blind - Parameter replace'
[06:49:29] [INFO] testing 'Informix boolean-based blind - Parameter replace'
[06:49:29] [INFO] testing 'Microsoft Access boolean-based blind - Parameter replace'
[06:49:29] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL)'
[06:49:29] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL - original value)'
[06:49:29] [INFO] testing 'Boolean-based blind - Parameter replace (CASE)'
[06:49:29] [INFO] testing 'Boolean-based blind - Parameter replace (CASE - original value)'
[06:49:29] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:29] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[06:49:29] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:29] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:29] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause'
[06:49:29] [INFO] testing 'Oracle boolean-based blind - ORDER BY, GROUP BY clause'
[06:49:29] [INFO] testing 'HAVING boolean-based blind - WHERE, GROUP BY clause'
[06:49:30] [INFO] testing 'PostgreSQL boolean-based blind - Stacked queries'
[06:49:30] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF)'
[06:49:30] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[06:49:30] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[06:49:30] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[06:49:30] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[06:49:30] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[06:49:31] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT)'
[06:49:31] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT)'
[06:49:31] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[06:49:31] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS)'
[06:49:31] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[06:49:31] [INFO] testing 'Firebird AND error-based - WHERE or HAVING clause'
[06:49:32] [INFO] testing 'MonetDB AND error-based - WHERE or HAVING clause'
[06:49:32] [INFO] testing 'Vertica AND error-based - WHERE or HAVING clause'
[06:49:32] [INFO] testing 'IBM DB2 AND error-based - WHERE or HAVING clause'
[06:49:32] [INFO] testing 'ClickHouse AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[06:49:32] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[06:49:32] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[06:49:32] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[06:49:32] [INFO] testing 'PostgreSQL error-based - Parameter replace'
[06:49:32] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace'
[06:49:32] [INFO] testing 'Oracle error-based - Parameter replace'
[06:49:32] [INFO] testing 'MySQL >= 5.6 error-based - ORDER BY, GROUP BY clause (GTID_SUBSET)'
[06:49:32] [INFO] testing 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)'
[06:49:32] [INFO] testing 'PostgreSQL error-based - ORDER BY, GROUP BY clause'
[06:49:32] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Stacking (EXEC)'
[06:49:33] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[06:49:33] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[06:49:33] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[06:49:33] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[06:49:33] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[06:49:33] [INFO] testing 'PostgreSQL stacked queries (heavy query - comment)'
[06:49:33] [INFO] testing 'PostgreSQL < 8.2 stacked queries (Glibc - comment)'
[06:49:33] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[06:49:33] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (DECLARE - comment)'
[06:49:33] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[06:49:34] [INFO] testing 'Oracle stacked queries (heavy query - comment)'
[06:49:34] [INFO] testing 'IBM DB2 stacked queries (heavy query - comment)'
[06:49:34] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[06:49:34] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[06:49:34] [INFO] testing 'Generic UNION query (random number) - 1 to 10 columns'
[06:49:34] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[06:49:35] [INFO] testing 'MySQL UNION query (random number) - 1 to 10 columns'
[06:49:35] [WARNING] parameter 'Referer' does not seem to be injectable
[06:49:35] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. Rerun without providing the option '--technique'. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'

[*] ending @ 06:49:35 /2026-03-31/


```

#### POST http://127.0.0.1:8082/WebGoat/SqlInjection/attack8a
```
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.10.3#pip}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:49:35 /2026-03-31/

[06:49:35] [WARNING] using '/tmp/sqlmap_out' as the output directory
[06:49:35] [WARNING] it appears that you have provided tainted parameter values ('auth_tan=1' OR '1'='1') with most likely leftover chars/statements from manual SQL injection test(s). Please, always use only valid parameter values so sqlmap could be able to run properly
are you really sure that you want to continue (sqlmap could have problems)? [y/N] N

[*] ending @ 06:49:35 /2026-03-31/


```
</details>

---

## 4. OWASP Top 10 Active Checks

**Summary:** 🔴 CRITICAL: 1 | 🟠 HIGH: 7 | 🟡 MEDIUM: 4 | 🔵 LOW: 3

### A01 — Broken Access Control
#### Finding O-01 — 🔴 CRITICAL: Sensitive path accessible without auth: /actuator/env
| Field | Detail |
|-------|--------|
| **Severity**    | 🔴 CRITICAL |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat/actuator/env` |
| **Description** | `/actuator/env` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `{"activeProfiles":[],"defaultProfiles":["default"],"propertySources":[{"name":"commandLineArgs","properties":{"server.address":{"value":"******"}}},{"` |

#### Finding O-02 — 🟠 HIGH: Admin/restricted path reachable without auth: /WebGoat/actuator
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat/WebGoat/actuator` |
| **Description** | The path `/WebGoat/actuator` returned HTTP 302 with no credentials. |
| **Remediation** | Require authentication and authorisation on all admin paths. |
| **Evidence**    | `HTTP 302` |

#### Finding O-03 — 🟠 HIGH: Admin/restricted path reachable without auth: /WebGoat/actuator/env
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat/WebGoat/actuator/env` |
| **Description** | The path `/WebGoat/actuator/env` returned HTTP 302 with no credentials. |
| **Remediation** | Require authentication and authorisation on all admin paths. |
| **Evidence**    | `HTTP 302` |

#### Finding O-04 — 🟠 HIGH: Admin/restricted path reachable without auth: /WebGoat/actuator/health
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat/WebGoat/actuator/health` |
| **Description** | The path `/WebGoat/actuator/health` returned HTTP 302 with no credentials. |
| **Remediation** | Require authentication and authorisation on all admin paths. |
| **Evidence**    | `HTTP 302` |

#### Finding O-05 — 🟠 HIGH: Admin/restricted path reachable without auth: /WebGoat/server-info.xsp
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat/WebGoat/server-info.xsp` |
| **Description** | The path `/WebGoat/server-info.xsp` returned HTTP 302 with no credentials. |
| **Remediation** | Require authentication and authorisation on all admin paths. |
| **Evidence**    | `HTTP 302` |

#### Finding O-06 — 🟠 HIGH: Sensitive path accessible without auth: /actuator
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat/actuator` |
| **Description** | `/actuator` returned HTTP 200 without any authentication. |
| **Remediation** | Block or require authentication for all sensitive paths. |
| **Evidence**    | `{"_links":{"self":{"href":"http://127.0.0.1:8082/WebGoat/actuator","templated":false},"health":{"href":"http://127.0.0.1:8082/WebGoat/actuator/health"` |

#### Finding O-07 — 🟡 MEDIUM: No CSRF token on login/form page
| Field | Detail |
|-------|--------|
| **Severity**    | 🟡 MEDIUM |
| **OWASP**       | A01 — Broken Access Control |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat/WebGoat/login` |
| **Description** | `/WebGoat/login` does not include a detectable CSRF token. State-changing requests may be forgeable from any origin. |
| **Remediation** | Add per-session CSRF tokens to all state-changing forms and API endpoints. |

### A02 — Cryptographic Failures
#### Finding O-08 — 🟠 HIGH: Application served over plain HTTP (no TLS)
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A02 — Cryptographic Failures |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat` |
| **Description** | All traffic is unencrypted. Credentials and tokens are exposed on the network. |
| **Remediation** | Deploy TLS everywhere. Redirect HTTP→HTTPS. Enable HSTS. |

### A04 — Insecure Design
#### Finding O-09 — 🟠 HIGH: No rate limiting on login endpoint
| Field | Detail |
|-------|--------|
| **Severity**    | 🟠 HIGH |
| **OWASP**       | A04 — Insecure Design |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat/WebGoat/login` |
| **Description** | 10 consecutive failed login attempts to `/WebGoat/login` received no HTTP 429. Brute-force and credential stuffing are possible. |
| **Remediation** | Implement account lockout or exponential back-off. Add CAPTCHA for repeated failures. |
| **Evidence**    | `10/10 requests not throttled` |

### A05 — Security Misconfiguration
#### Finding O-10 — 🟡 MEDIUM: Clickjacking — X-Frame-Options missing
| Field | Detail |
|-------|--------|
| **Severity**    | 🟡 MEDIUM |
| **OWASP**       | A05 — Security Misconfiguration |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat` |
| **Description** | The `x-frame-options` security header is absent. |
| **Remediation** | Add `X-Frame-Options: DENY` or `SAMEORIGIN`. |

#### Finding O-11 — 🟡 MEDIUM: HSTS missing
| Field | Detail |
|-------|--------|
| **Severity**    | 🟡 MEDIUM |
| **OWASP**       | A05 — Security Misconfiguration |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat` |
| **Description** | The `strict-transport-security` security header is absent. |
| **Remediation** | Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`. |

#### Finding O-12 — 🟡 MEDIUM: CSP missing — XSS risk increased
| Field | Detail |
|-------|--------|
| **Severity**    | 🟡 MEDIUM |
| **OWASP**       | A05 — Security Misconfiguration |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat` |
| **Description** | The `content-security-policy` security header is absent. |
| **Remediation** | Define a restrictive Content-Security-Policy. |

#### Finding O-13 — 🔵 LOW: MIME sniffing — X-Content-Type-Options missing
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **OWASP**       | A05 — Security Misconfiguration |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat` |
| **Description** | The `x-content-type-options` security header is absent. |
| **Remediation** | Add `X-Content-Type-Options: nosniff`. |

#### Finding O-14 — 🔵 LOW: Referrer-Policy missing
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **OWASP**       | A05 — Security Misconfiguration |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat` |
| **Description** | The `referrer-policy` security header is absent. |
| **Remediation** | Set `Referrer-Policy: no-referrer` or `strict-origin`. |

#### Finding O-15 — 🔵 LOW: Permissions-Policy missing
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **OWASP**       | A05 — Security Misconfiguration |
| **Endpoint**    | `http://127.0.0.1:8082/WebGoat` |
| **Description** | The `permissions-policy` security header is absent. |
| **Remediation** | Restrict browser features with a Permissions-Policy header. |

