# Security Assessment Report: WEBGOAT

| | |
|---|---|
| **Target URL**      | http://127.0.0.1:8082/WebGoat |
| **Scan Date**       | 2026-03-31 01:53 |
| **Total Findings**  | 23 |
| **Critical / High** | 0 |

---

## Executive Summary

| # | Severity | Tool | Finding |
|---|----------|------|---------|
| 1 | 🟡 MEDIUM | Nikto | Session cookie missing security flag(s) |
| 2 | 🟡 MEDIUM | Nikto | Clickjacking protection header missing |
| 3 | 🔵 LOW | Nuclei | Tomcat Stacktraces |
| 4 | 🔵 LOW | Nuclei | Springboot Env |
| 5 | 🔵 LOW | Nuclei | Springboot Configprops |
| 6 | 🔵 LOW | Nuclei | Tomcat Stacktraces |
| 7 | ⚪ INFO | Nikto | Server: No banner retrieved |
| 8 | ⚪ INFO | Nikto | Root page / redirects to: http://localhost:8082/WebGoat/logi |
| 9 | ⚪ INFO | Nikto | No CGI Directories found (use '-C all' to force check all po |
| 10 | ⚪ INFO | Nikto | 0 items checked: 0 error(s) and 2 item(s) reported on remote |
| 11 | ⚪ INFO | Nikto | End Time:           2026-03-31 01:51:50 (GMT5.5) (0 seconds) |
| 12 | ⚪ INFO | Nikto | 1 host(s) tested |
| 13 | ⚪ INFO | Nuclei | Tomcat Detect:Version |
| 14 | ⚪ INFO | Nuclei | Springboot Actuator:Available Endpoints |
| 15 | ⚪ INFO | Nuclei | Tech Detect:Font Awesome |
| 16 | ⚪ INFO | Nuclei | Tech Detect:Animate.Css |
| 17 | ⚪ INFO | Nuclei | Tech Detect:Bootstrap |
| 18 | ⚪ INFO | Nuclei | Wordpress Plugin Detect:Bootstrap |
| 19 | ⚪ INFO | Nuclei | Springboot Health |
| 20 | ⚪ INFO | Nuclei | Springboot Actuator:Available Endpoints |
| 21 | ⚪ INFO | Nuclei | Tomcat Detect:Version |
| 22 | ⚪ INFO | Nuclei | Wordpress Plugin Detect:Bootstrap |
| 23 | ⚪ INFO | Nuclei | Dameng Detect |

---

## 1. Infrastructure Scan (Nikto)

**Summary:** 🟡 MEDIUM: 2 | ⚪ INFO: 6

### Finding N-01 — 🟡 MEDIUM
| Field | Detail |
|-------|--------|
| **Severity**    | 🟡 MEDIUM |
| **Path**        | `(server-level)` |
| **Description** | Session cookie missing security flag(s) |
| **Remediation** | Set HttpOnly and Secure flags on all session cookies. |

> Raw: `Cookie JSESSIONID created without the httponly flag`

### Finding N-02 — 🟡 MEDIUM
| Field | Detail |
|-------|--------|
| **Severity**    | 🟡 MEDIUM |
| **Path**        | `(server-level)` |
| **Description** | Clickjacking protection header missing |
| **Remediation** | Add `X-Frame-Options: DENY` or `SAMEORIGIN` to all responses. |

> Raw: `The anti-clickjacking X-Frame-Options header is not present.`

### Finding N-03 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | Server: No banner retrieved |
| **Remediation** | Review this finding manually. |

> Raw: `Server: No banner retrieved`

### Finding N-04 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | Root page / redirects to: http://localhost:8082/WebGoat/login |
| **Remediation** | Review this finding manually. |

> Raw: `Root page / redirects to: http://localhost:8082/WebGoat/login`

### Finding N-05 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | No CGI Directories found (use '-C all' to force check all possible dirs) |
| **Remediation** | Review this finding manually. |

> Raw: `No CGI Directories found (use '-C all' to force check all possible dirs)`

### Finding N-06 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | 0 items checked: 0 error(s) and 2 item(s) reported on remote host |
| **Remediation** | Review this finding manually. |

> Raw: `0 items checked: 0 error(s) and 2 item(s) reported on remote host`

### Finding N-07 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Path**        | `(server-level)` |
| **Description** | End Time:           2026-03-31 01:51:50 (GMT5.5) (0 seconds) |
| **Remediation** | Review this finding manually. |

> Raw: `End Time:           2026-03-31 01:51:50 (GMT5.5) (0 seconds)`

### Finding N-08 — ⚪ INFO
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
+ Target Port:        8082
+ Start Time:         2026-03-31 01:51:50 (GMT5.5)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ Cookie JSESSIONID created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ Root page / redirects to: http://localhost:8082/WebGoat/login
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 0 items checked: 0 error(s) and 2 item(s) reported on remote host
+ End Time:           2026-03-31 01:51:50 (GMT5.5) (0 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```
</details>

---

## 2. Vulnerability Scan (Nuclei)

**Summary:** 🔵 LOW: 4 | ⚪ INFO: 11

### Finding V-01 — 🔵 LOW: Tomcat Stacktraces
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **Template**    | `tomcat-stacktraces` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/?f=\[` |

> Raw: `[tomcat-stacktraces] [http] [low] http://127.0.0.1:8082/WebGoat/?f=\[`

### Finding V-02 — 🔵 LOW: Springboot Env
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **Template**    | `springboot-env` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/actuator/env` |

> Raw: `[springboot-env] [http] [low] http://127.0.0.1:8082/WebGoat/actuator/env`

### Finding V-03 — 🔵 LOW: Springboot Configprops
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **Template**    | `springboot-configprops` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/actuator/configprops` |

> Raw: `[springboot-configprops] [http] [low] http://127.0.0.1:8082/WebGoat/actuator/configprops`

### Finding V-04 — 🔵 LOW: Tomcat Stacktraces
| Field | Detail |
|-------|--------|
| **Severity**    | 🔵 LOW |
| **Template**    | `tomcat-stacktraces` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/?f=\[` |

> Raw: `[tomcat-stacktraces] [http] [low] http://127.0.0.1:8082/WebGoat/?f=\[`

### Finding V-05 — ⚪ INFO: Tomcat Detect:Version
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `tomcat-detect:version` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/%5C` |
| **Matcher**     | `"10.1.36"` |

> Raw: `[tomcat-detect:version] [http] [info] http://127.0.0.1:8082/WebGoat/%5C ["10.1.36"]`

### Finding V-06 — ⚪ INFO: Springboot Actuator:Available Endpoints
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `springboot-actuator:available-endpoints` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/actuator` |
| **Matcher**     | `"configprops","configprops-prefix","env","env-toMatch","health","health-path","self"` |

> Raw: `[springboot-actuator:available-endpoints] [http] [info] http://127.0.0.1:8082/WebGoat/actuator ["configprops","configprops-prefix","env","env-toMatch","health","health-path","self"]`

### Finding V-07 — ⚪ INFO: Tech Detect:Font Awesome
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `tech-detect:font-awesome` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[tech-detect:font-awesome] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-08 — ⚪ INFO: Tech Detect:Animate.Css
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `tech-detect:animate.css` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[tech-detect:animate.css] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-09 — ⚪ INFO: Tech Detect:Bootstrap
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `tech-detect:bootstrap` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[tech-detect:bootstrap] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-10 — ⚪ INFO: Wordpress Plugin Detect:Bootstrap
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `wordpress-plugin-detect:bootstrap` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[wordpress-plugin-detect:bootstrap] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-11 — ⚪ INFO: Springboot Health
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `springboot-health` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/actuator/health` |

> Raw: `[springboot-health] [http] [info] http://127.0.0.1:8082/WebGoat/actuator/health`

### Finding V-12 — ⚪ INFO: Springboot Actuator:Available Endpoints
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `springboot-actuator:available-endpoints` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/actuator` |
| **Matcher**     | `"env-toMatch","health","health-path","self","configprops","configprops-prefix","env"` |

> Raw: `[springboot-actuator:available-endpoints] [http] [info] http://127.0.0.1:8082/WebGoat/actuator ["env-toMatch","health","health-path","self","configprops","configprops-prefix","env"]`

### Finding V-13 — ⚪ INFO: Tomcat Detect:Version
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `tomcat-detect:version` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/%5C` |
| **Matcher**     | `"10.1.36"` |

> Raw: `[tomcat-detect:version] [http] [info] http://127.0.0.1:8082/WebGoat/%5C ["10.1.36"]`

### Finding V-14 — ⚪ INFO: Wordpress Plugin Detect:Bootstrap
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `wordpress-plugin-detect:bootstrap` |
| **Protocol**    | http |
| **URL**         | `http://127.0.0.1:8082/WebGoat/login` |

> Raw: `[wordpress-plugin-detect:bootstrap] [http] [info] http://127.0.0.1:8082/WebGoat/login`

### Finding V-15 — ⚪ INFO: Dameng Detect
| Field | Detail |
|-------|--------|
| **Severity**    | ⚪ INFO |
| **Template**    | `dameng-detect` |
| **Protocol**    | javascript |
| **URL**         | `` |
| **Matcher**     | `"008.1.1.490"` |

> Raw: `[dameng-detect] [javascript] [info] 127.0.0.1:8082 ["008.1.1.490"]`

<details><summary>Full raw Nuclei output</summary>

```
[[92mtomcat-stacktraces[0m] [[94mhttp[0m] [[32mlow[0m] http://127.0.0.1:8082/WebGoat/?f=\[
[[92mtomcat-detect[0m:[1;92mversion[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/%5C [[96m"10.1.36"[0m]
[[92mspringboot-actuator[0m:[1;92mavailable-endpoints[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/actuator [[96m"configprops"[0m,[96m"configprops-prefix"[0m,[96m"env"[0m,[96m"env-toMatch"[0m,[96m"health"[0m,[96m"health-path"[0m,[96m"self"[0m]
[[92mtech-detect[0m:[1;92mfont-awesome[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mtech-detect[0m:[1;92manimate.css[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mtech-detect[0m:[1;92mbootstrap[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mwordpress-plugin-detect[0m:[1;92mbootstrap[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mspringboot-env[0m] [[94mhttp[0m] [[32mlow[0m] http://127.0.0.1:8082/WebGoat/actuator/env
[[92mspringboot-health[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/actuator/health
[[92mspringboot-configprops[0m] [[94mhttp[0m] [[32mlow[0m] http://127.0.0.1:8082/WebGoat/actuator/configprops
[[92mtomcat-stacktraces[0m] [[94mhttp[0m] [[32mlow[0m] http://127.0.0.1:8082/WebGoat/?f=\[
[[92mspringboot-actuator[0m:[1;92mavailable-endpoints[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/actuator [[96m"env-toMatch"[0m,[96m"health"[0m,[96m"health-path"[0m,[96m"self"[0m,[96m"configprops"[0m,[96m"configprops-prefix"[0m,[96m"env"[0m]
[[92mtomcat-detect[0m:[1;92mversion[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/%5C [[96m"10.1.36"[0m]
[[92mwordpress-plugin-detect[0m:[1;92mbootstrap[0m] [[94mhttp[0m] [[34minfo[0m] http://127.0.0.1:8082/WebGoat/login
[[92mdameng-detect[0m] [[94mjavascript[0m] [[34minfo[0m] 127.0.0.1:8082 [[96m"008.1.1.490"[0m]

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
|_ -| . [)]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:52:48 /2026-03-31/

[01:52:48] [WARNING] using '/tmp/sqlmap_out' as the output directory
[01:52:48] [INFO] testing connection to the target URL
got a 302 redirect to 'http://127.0.0.1:8082/WebGoat/login'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
[01:52:48] [INFO] testing if the target URL content is stable
[01:52:48] [WARNING] POST parameter 'account' does not appear to be dynamic
[01:52:48] [WARNING] heuristic (basic) test shows that POST parameter 'account' might not be injectable
[01:52:48] [INFO] testing for SQL injection on POST parameter 'account'
[01:52:48] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:52:49] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[01:52:49] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (comment)'
[01:52:49] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[01:52:49] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (Microsoft Access comment)'
[01:52:49] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[01:52:50] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[01:52:50] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[01:52:50] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[01:52:50] [INFO] testing 'SQLite AND boolean-based blind - WHERE, HAVING, GROUP BY or HAVING clause (JSON)'
[01:52:51] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:52:51] [INFO] testing 'PostgreSQL boolean-based blind - Parameter replace'
[01:52:51] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace'
[01:52:51] [INFO] testing 'Oracle boolean-based blind - Parameter replace'
[01:52:51] [INFO] testing 'Informix boolean-based blind - Parameter replace'
[01:52:51] [INFO] testing 'Microsoft Access boolean-based blind - Parameter replace'
[01:52:51] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL)'
[01:52:51] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL - original value)'
[01:52:51] [INFO] testing 'Boolean-based blind - Parameter replace (CASE)'
[01:52:51] [INFO] testing 'Boolean-based blind - Parameter replace (CASE - original value)'
[01:52:51] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[01:52:51] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[01:52:51] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[01:52:51] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY, GROUP BY clause'
[01:52:51] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause'
[01:52:51] [INFO] testing 'Oracle boolean-based blind - ORDER BY, GROUP BY clause'
[01:52:51] [INFO] testing 'HAVING boolean-based blind - WHERE, GROUP BY clause'
[01:52:51] [INFO] testing 'PostgreSQL boolean-based blind - Stacked queries'
[01:52:51] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF)'
[01:52:52] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:52:52] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[01:52:52] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[01:52:52] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:52:53] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:52:53] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT)'
[01:52:53] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT)'
[01:52:53] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:52:53] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS)'
[01:52:54] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[01:52:54] [INFO] testing 'Firebird AND error-based - WHERE or HAVING clause'
[01:52:54] [INFO] testing 'MonetDB AND error-based - WHERE or HAVING clause'
[01:52:54] [INFO] testing 'Vertica AND error-based - WHERE or HAVING clause'
[01:52:54] [INFO] testing 'IBM DB2 AND error-based - WHERE or HAVING clause'
[01:52:55] [INFO] testing 'ClickHouse AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[01:52:55] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[01:52:55] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[01:52:55] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[01:52:55] [INFO] testing 'PostgreSQL error-based - Parameter replace'
[01:52:55] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace'
[01:52:55] [INFO] testing 'Oracle error-based - Parameter replace'
[01:52:55] [INFO] testing 'MySQL >= 5.6 error-based - ORDER BY, GROUP BY clause (GTID_SUBSET)'
[01:52:55] [INFO] testing 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)'
[01:52:55] [INFO] testing 'PostgreSQL error-based - ORDER BY, GROUP BY clause'
[01:52:55] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Stacking (EXEC)'
[01:52:55] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[01:52:55] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[01:52:56] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[01:52:56] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[01:52:56] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:52:56] [INFO] testing 'PostgreSQL stacked queries (heavy query - comment)'
[01:52:56] [INFO] testing 'PostgreSQL < 8.2 stacked queries (Glibc - comment)'
[01:52:56] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:52:56] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (DECLARE - comment)'
[01:52:56] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:52:56] [INFO] testing 'Oracle stacked queries (heavy query - comment)'
[01:52:56] [INFO] testing 'IBM DB2 stacked queries (heavy query - comment)'
[01:52:57] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[01:52:57] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:52:57] [INFO] testing 'Generic UNION query (random number) - 1 to 10 columns'
[01:52:57] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[01:52:58] [INFO] testing 'MySQL UNION query (random number) - 1 to 10 columns'
[01:52:58] [WARNING] POST parameter 'account' does not seem to be injectable
[01:52:58] [WARNING] POST parameter 'operator' does not appear to be dynamic
[01:52:58] [WARNING] heuristic (basic) test shows that POST parameter 'operator' might not be injectable
[01:52:58] [INFO] testing for SQL injection on POST parameter 'operator'
[01:52:58] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:52:58] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[01:52:59] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (comment)'
[01:52:59] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[01:52:59] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (Microsoft Access comment)'
[01:52:59] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[01:52:59] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[01:52:59] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[01:52:59] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[01:53:00] [INFO] testing 'SQLite AND boolean-based blind - WHERE, HAVING, GROUP BY or HAVING clause (JSON)'
[01:53:00] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:53:00] [INFO] testing 'PostgreSQL boolean-based blind - Parameter replace'
[01:53:00] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace'
[01:53:00] [INFO] testing 'Oracle boolean-based blind - Parameter replace'
[01:53:00] [INFO] testing 'Informix boolean-based blind - Parameter replace'
[01:53:00] [INFO] testing 'Microsoft Access boolean-based blind - Parameter replace'
[01:53:00] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL)'
[01:53:00] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL - original value)'
[01:53:00] [INFO] testing 'Boolean-based blind - Parameter replace (CASE)'
[01:53:00] [INFO] testing 'Boolean-based blind - Parameter replace (CASE - original value)'
[01:53:00] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:00] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[01:53:00] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:00] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:00] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause'
[01:53:00] [INFO] testing 'Oracle boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:00] [INFO] testing 'HAVING boolean-based blind - WHERE, GROUP BY clause'
[01:53:00] [INFO] testing 'PostgreSQL boolean-based blind - Stacked queries'
[01:53:00] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF)'
[01:53:00] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:53:01] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[01:53:01] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[01:53:01] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:53:01] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:53:01] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT)'
[01:53:02] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT)'
[01:53:02] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:53:02] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS)'
[01:53:02] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[01:53:02] [INFO] testing 'Firebird AND error-based - WHERE or HAVING clause'
[01:53:03] [INFO] testing 'MonetDB AND error-based - WHERE or HAVING clause'
[01:53:03] [INFO] testing 'Vertica AND error-based - WHERE or HAVING clause'
[01:53:03] [INFO] testing 'IBM DB2 AND error-based - WHERE or HAVING clause'
[01:53:03] [INFO] testing 'ClickHouse AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[01:53:03] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[01:53:04] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[01:53:04] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[01:53:04] [INFO] testing 'PostgreSQL error-based - Parameter replace'
[01:53:04] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace'
[01:53:04] [INFO] testing 'Oracle error-based - Parameter replace'
[01:53:04] [INFO] testing 'MySQL >= 5.6 error-based - ORDER BY, GROUP BY clause (GTID_SUBSET)'
[01:53:04] [INFO] testing 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)'
[01:53:04] [INFO] testing 'PostgreSQL error-based - ORDER BY, GROUP BY clause'
[01:53:04] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Stacking (EXEC)'
[01:53:04] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[01:53:04] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[01:53:04] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[01:53:04] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[01:53:04] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:53:04] [INFO] testing 'PostgreSQL stacked queries (heavy query - comment)'
[01:53:04] [INFO] testing 'PostgreSQL < 8.2 stacked queries (Glibc - comment)'
[01:53:04] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:53:04] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (DECLARE - comment)'
[01:53:05] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:53:05] [INFO] testing 'Oracle stacked queries (heavy query - comment)'
[01:53:05] [INFO] testing 'IBM DB2 stacked queries (heavy query - comment)'
[01:53:05] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[01:53:05] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:53:05] [INFO] testing 'Generic UNION query (random number) - 1 to 10 columns'
[01:53:06] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[01:53:06] [INFO] testing 'MySQL UNION query (random number) - 1 to 10 columns'
[01:53:06] [WARNING] POST parameter 'operator' does not seem to be injectable
[01:53:06] [WARNING] POST parameter 'injection' does not appear to be dynamic
[01:53:06] [WARNING] heuristic (basic) test shows that POST parameter 'injection' might not be injectable
[01:53:06] [INFO] testing for SQL injection on POST parameter 'injection'
[01:53:06] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:53:06] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[01:53:06] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (comment)'
[01:53:07] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[01:53:07] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (Microsoft Access comment)'
[01:53:07] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[01:53:07] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[01:53:07] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[01:53:07] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[01:53:07] [INFO] testing 'SQLite AND boolean-based blind - WHERE, HAVING, GROUP BY or HAVING clause (JSON)'
[01:53:07] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:53:07] [INFO] testing 'PostgreSQL boolean-based blind - Parameter replace'
[01:53:08] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace'
[01:53:08] [INFO] testing 'Oracle boolean-based blind - Parameter replace'
[01:53:08] [INFO] testing 'Informix boolean-based blind - Parameter replace'
[01:53:08] [INFO] testing 'Microsoft Access boolean-based blind - Parameter replace'
[01:53:08] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL)'
[01:53:08] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL - original value)'
[01:53:08] [INFO] testing 'Boolean-based blind - Parameter replace (CASE)'
[01:53:08] [INFO] testing 'Boolean-based blind - Parameter replace (CASE - original value)'
[01:53:08] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:08] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[01:53:08] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:08] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:08] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause'
[01:53:08] [INFO] testing 'Oracle boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:08] [INFO] testing 'HAVING boolean-based blind - WHERE, GROUP BY clause'
[01:53:08] [INFO] testing 'PostgreSQL boolean-based blind - Stacked queries'
[01:53:08] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF)'
[01:53:08] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:53:08] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[01:53:08] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[01:53:08] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:53:09] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:53:09] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT)'
[01:53:09] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT)'
[01:53:09] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:53:09] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS)'
[01:53:09] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[01:53:10] [INFO] testing 'Firebird AND error-based - WHERE or HAVING clause'
[01:53:10] [INFO] testing 'MonetDB AND error-based - WHERE or HAVING clause'
[01:53:10] [INFO] testing 'Vertica AND error-based - WHERE or HAVING clause'
[01:53:10] [INFO] testing 'IBM DB2 AND error-based - WHERE or HAVING clause'
[01:53:10] [INFO] testing 'ClickHouse AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[01:53:10] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[01:53:10] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[01:53:10] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[01:53:10] [INFO] testing 'PostgreSQL error-based - Parameter replace'
[01:53:10] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace'
[01:53:10] [INFO] testing 'Oracle error-based - Parameter replace'
[01:53:10] [INFO] testing 'MySQL >= 5.6 error-based - ORDER BY, GROUP BY clause (GTID_SUBSET)'
[01:53:10] [INFO] testing 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)'
[01:53:10] [INFO] testing 'PostgreSQL error-based - ORDER BY, GROUP BY clause'
[01:53:10] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Stacking (EXEC)'
[01:53:11] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[01:53:11] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[01:53:11] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[01:53:11] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[01:53:11] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:53:11] [INFO] testing 'PostgreSQL stacked queries (heavy query - comment)'
[01:53:11] [INFO] testing 'PostgreSQL < 8.2 stacked queries (Glibc - comment)'
[01:53:11] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:53:11] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (DECLARE - comment)'
[01:53:11] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:53:11] [INFO] testing 'Oracle stacked queries (heavy query - comment)'
[01:53:12] [INFO] testing 'IBM DB2 stacked queries (heavy query - comment)'
[01:53:12] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[01:53:12] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:53:12] [INFO] testing 'Generic UNION query (random number) - 1 to 10 columns'
[01:53:12] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[01:53:13] [INFO] testing 'MySQL UNION query (random number) - 1 to 10 columns'
[01:53:13] [WARNING] POST parameter 'injection' does not seem to be injectable
[01:53:13] [INFO] ignoring Cookie parameter 'JSESSIONID'
[01:53:13] [WARNING] parameter 'User-Agent' does not appear to be dynamic
[01:53:13] [WARNING] heuristic (basic) test shows that parameter 'User-Agent' might not be injectable
[01:53:13] [INFO] testing for SQL injection on parameter 'User-Agent'
[01:53:13] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:53:13] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[01:53:13] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (comment)'
[01:53:13] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[01:53:13] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (Microsoft Access comment)'
[01:53:13] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[01:53:13] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[01:53:14] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[01:53:14] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[01:53:14] [INFO] testing 'SQLite AND boolean-based blind - WHERE, HAVING, GROUP BY or HAVING clause (JSON)'
[01:53:14] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:53:14] [INFO] testing 'PostgreSQL boolean-based blind - Parameter replace'
[01:53:14] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace'
[01:53:14] [INFO] testing 'Oracle boolean-based blind - Parameter replace'
[01:53:14] [INFO] testing 'Informix boolean-based blind - Parameter replace'
[01:53:14] [INFO] testing 'Microsoft Access boolean-based blind - Parameter replace'
[01:53:14] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL)'
[01:53:14] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL - original value)'
[01:53:14] [INFO] testing 'Boolean-based blind - Parameter replace (CASE)'
[01:53:14] [INFO] testing 'Boolean-based blind - Parameter replace (CASE - original value)'
[01:53:14] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:14] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[01:53:14] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:14] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:14] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause'
[01:53:14] [INFO] testing 'Oracle boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:14] [INFO] testing 'HAVING boolean-based blind - WHERE, GROUP BY clause'
[01:53:14] [INFO] testing 'PostgreSQL boolean-based blind - Stacked queries'
[01:53:14] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF)'
[01:53:15] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:53:15] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[01:53:15] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[01:53:15] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:53:15] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:53:15] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT)'
[01:53:15] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT)'
[01:53:16] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:53:16] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS)'
[01:53:16] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[01:53:16] [INFO] testing 'Firebird AND error-based - WHERE or HAVING clause'
[01:53:16] [INFO] testing 'MonetDB AND error-based - WHERE or HAVING clause'
[01:53:16] [INFO] testing 'Vertica AND error-based - WHERE or HAVING clause'
[01:53:17] [INFO] testing 'IBM DB2 AND error-based - WHERE or HAVING clause'
[01:53:17] [INFO] testing 'ClickHouse AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[01:53:17] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[01:53:17] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[01:53:17] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[01:53:17] [INFO] testing 'PostgreSQL error-based - Parameter replace'
[01:53:17] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace'
[01:53:17] [INFO] testing 'Oracle error-based - Parameter replace'
[01:53:17] [INFO] testing 'MySQL >= 5.6 error-based - ORDER BY, GROUP BY clause (GTID_SUBSET)'
[01:53:17] [INFO] testing 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)'
[01:53:17] [INFO] testing 'PostgreSQL error-based - ORDER BY, GROUP BY clause'
[01:53:17] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Stacking (EXEC)'
[01:53:17] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[01:53:17] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[01:53:17] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[01:53:17] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[01:53:18] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:53:18] [INFO] testing 'PostgreSQL stacked queries (heavy query - comment)'
[01:53:18] [INFO] testing 'PostgreSQL < 8.2 stacked queries (Glibc - comment)'
[01:53:18] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:53:18] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (DECLARE - comment)'
[01:53:18] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:53:18] [INFO] testing 'Oracle stacked queries (heavy query - comment)'
[01:53:18] [INFO] testing 'IBM DB2 stacked queries (heavy query - comment)'
[01:53:18] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[01:53:18] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:53:19] [INFO] testing 'Generic UNION query (random number) - 1 to 10 columns'
[01:53:19] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[01:53:19] [INFO] testing 'MySQL UNION query (random number) - 1 to 10 columns'
[01:53:19] [WARNING] parameter 'User-Agent' does not seem to be injectable
[01:53:19] [WARNING] parameter 'Referer' does not appear to be dynamic
[01:53:19] [WARNING] heuristic (basic) test shows that parameter 'Referer' might not be injectable
[01:53:19] [INFO] testing for SQL injection on parameter 'Referer'
[01:53:19] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:53:20] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[01:53:20] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (comment)'
[01:53:20] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[01:53:20] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (Microsoft Access comment)'
[01:53:20] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[01:53:20] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[01:53:20] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[01:53:20] [INFO] testing 'Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[01:53:20] [INFO] testing 'SQLite AND boolean-based blind - WHERE, HAVING, GROUP BY or HAVING clause (JSON)'
[01:53:21] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:53:21] [INFO] testing 'PostgreSQL boolean-based blind - Parameter replace'
[01:53:21] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Parameter replace'
[01:53:21] [INFO] testing 'Oracle boolean-based blind - Parameter replace'
[01:53:21] [INFO] testing 'Informix boolean-based blind - Parameter replace'
[01:53:21] [INFO] testing 'Microsoft Access boolean-based blind - Parameter replace'
[01:53:21] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL)'
[01:53:21] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL - original value)'
[01:53:21] [INFO] testing 'Boolean-based blind - Parameter replace (CASE)'
[01:53:21] [INFO] testing 'Boolean-based blind - Parameter replace (CASE - original value)'
[01:53:21] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:21] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[01:53:21] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:21] [INFO] testing 'PostgreSQL boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:21] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause'
[01:53:21] [INFO] testing 'Oracle boolean-based blind - ORDER BY, GROUP BY clause'
[01:53:21] [INFO] testing 'HAVING boolean-based blind - WHERE, GROUP BY clause'
[01:53:21] [INFO] testing 'PostgreSQL boolean-based blind - Stacked queries'
[01:53:21] [INFO] testing 'Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF)'
[01:53:21] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[01:53:21] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[01:53:21] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[01:53:21] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[01:53:22] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[01:53:22] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT)'
[01:53:22] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT)'
[01:53:22] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[01:53:22] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS)'
[01:53:22] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN)'
[01:53:22] [INFO] testing 'Firebird AND error-based - WHERE or HAVING clause'
[01:53:23] [INFO] testing 'MonetDB AND error-based - WHERE or HAVING clause'
[01:53:23] [INFO] testing 'Vertica AND error-based - WHERE or HAVING clause'
[01:53:23] [INFO] testing 'IBM DB2 AND error-based - WHERE or HAVING clause'
[01:53:23] [INFO] testing 'ClickHouse AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause'
[01:53:23] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[01:53:23] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[01:53:23] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[01:53:23] [INFO] testing 'PostgreSQL error-based - Parameter replace'
[01:53:23] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Parameter replace'
[01:53:23] [INFO] testing 'Oracle error-based - Parameter replace'
[01:53:23] [INFO] testing 'MySQL >= 5.6 error-based - ORDER BY, GROUP BY clause (GTID_SUBSET)'
[01:53:23] [INFO] testing 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)'
[01:53:23] [INFO] testing 'PostgreSQL error-based - ORDER BY, GROUP BY clause'
[01:53:23] [INFO] testing 'Microsoft SQL Server/Sybase error-based - Stacking (EXEC)'
[01:53:24] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[01:53:24] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[01:53:24] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[01:53:24] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[01:53:24] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[01:53:24] [INFO] testing 'PostgreSQL stacked queries (heavy query - comment)'
[01:53:24] [INFO] testing 'PostgreSQL < 8.2 stacked queries (Glibc - comment)'
[01:53:24] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[01:53:24] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (DECLARE - comment)'
[01:53:24] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[01:53:25] [INFO] testing 'Oracle stacked queries (heavy query - comment)'
[01:53:25] [INFO] testing 'IBM DB2 stacked queries (heavy query - comment)'
[01:53:25] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[01:53:25] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[01:53:25] [INFO] testing 'Generic UNION query (random number) - 1 to 10 columns'
[01:53:25] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[01:53:26] [INFO] testing 'MySQL UNION query (random number) - 1 to 10 columns'
[01:53:26] [WARNING] parameter 'Referer' does not seem to be injectable
[01:53:26] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. Rerun without providing the option '--technique'. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'

[*] ending @ 01:53:26 /2026-03-31/


```
</details>
