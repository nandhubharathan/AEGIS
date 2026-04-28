# Security Assessment Report

| | |
|---|---|
| **Target URL** | http://aaaa.com |
| **Scan Mode** | STANDARD |
| **Scan Date** | 2026-03-31 15:30 |
| **Total Findings** | 2 |
| **Critical / High** | 1 |
| **Framework** | OWASP Top 10 (2021) |

---

## Executive Summary

| # | Severity | Tool | Finding |
|---|----------|------|---------|
| 1 | 🟠 HIGH | OWASP A02 | Application served over plain HTTP |
| 2 | ⚪ INFO | Nikto | 0 host(s) tested |

---

## 1. Infrastructure Scan (Nikto)

**Summary:** ⚪ INFO: 1

### N-01 — ⚪ INFO
| Field | Detail |
|-------|--------|
| **Severity** | ⚪ INFO |
| **Path** | `(server-level)` |
| **Description** | 0 host(s) tested |
| **Remediation** | Review this finding manually. |

> Raw: `0 host(s) tested`

<details><summary>Full Nikto output</summary>

```
- Nikto v2.1.5
---------------------------------------------------------------------------
+ 0 host(s) tested

```
</details>

---

## 2. Vulnerability Scan (Nuclei)

_No Nuclei findings._

<details><summary>Raw output</summary>

```

```
</details>

---

## 3. SQL Injection Analysis (SQLMap)

_No SQL injection detected by SQLMap._
<details><summary>Full SQLMap output</summary>

#### GET http://aaaa.com/search
```
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.10.3#pip}
|_ -| . [,]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:30:28 /2026-03-31/

[15:30:28] [WARNING] using '/tmp/sqlmap_out' as the output directory
[15:30:28] [CRITICAL] host 'aaaa.com' does not exist

[*] ending @ 15:30:28 /2026-03-31/


```

#### POST http://aaaa.com/login
```
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.10.3#pip}
|_ -| . [(]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:30:28 /2026-03-31/

[15:30:28] [WARNING] using '/tmp/sqlmap_out' as the output directory
[15:30:29] [CRITICAL] host 'aaaa.com' does not exist

[*] ending @ 15:30:29 /2026-03-31/


```

#### GET http://aaaa.com/api/items
```
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.10.3#pip}
|_ -| . [)]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:30:29 /2026-03-31/

[15:30:29] [WARNING] using '/tmp/sqlmap_out' as the output directory
[15:30:29] [CRITICAL] host 'aaaa.com' does not exist

[*] ending @ 15:30:29 /2026-03-31/


```
</details>

---

## 4. OWASP Top 10 + Extended Active Checks

**Summary:** 🟠 HIGH: 1

### O-01 — 🟠 HIGH: Application served over plain HTTP
| Field | Detail |
|-------|--------|
| **Severity** | 🟠 HIGH |
| **OWASP** | A02 — Cryptographic Failures |
| **Endpoint** | `http://aaaa.com` |
| **Description** | All traffic is unencrypted. Credentials and tokens are exposed to network sniffing. |
| **Remediation** | Deploy TLS everywhere. Redirect HTTP→HTTPS. Enable HSTS. |

