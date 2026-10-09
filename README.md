# vamp-waf-bypass

**VampSecure Labs · Security Research Division**

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

WAF evasion tester — 15 bypass techniques for authorized security testing.  
Pure Python, zero external dependencies.

> ⚠️ **FOR AUTHORIZED SECURITY TESTING ONLY.** Only use against systems you own or have explicit written permission to test.

### Features

- **15 bypass checks** (WAF-001–015) covering SQLi, XSS, path traversal, method override, IP spoofing, Log4Shell, rate limiting and more
- **Zero external dependencies** — uses only Python standard library (`urllib`, `re`, `json`…)
- **Pure check functions** for unit testing without network calls
- **JSON + HTML reports** for automated pipelines and human review
- **WAF fingerprinting** — detects Cloudflare, Incapsula, Sucuri, AWS WAF, Akamai, ModSecurity and more
- **Exit codes** CI-compatible: `2` = CRITICAL bypass, `1` = HIGH/MEDIUM, `0` = WAF blocking all

### Checks

| ID | Title | Severity | Category |
|----|-------|----------|----------|
| WAF-001 | WAF absent or not detected | high | Detection |
| WAF-002 | SQLi bypass — single URL encoding | critical | SQLi |
| WAF-003 | SQLi bypass — double URL encoding | critical | SQLi |
| WAF-004 | SQLi bypass — inline comments | critical | SQLi |
| WAF-005 | XSS bypass — HTML entities | critical | XSS |
| WAF-006 | XSS bypass — case variation | high | XSS |
| WAF-007 | Path traversal bypass — encoded | critical | LFI/Path Traversal |
| WAF-008 | Bypass via X-HTTP-Method-Override | medium | HTTP Method Tampering |
| WAF-009 | Bypass via IP spoofing headers | high | Access Control |
| WAF-010 | Bypass via User-Agent whitelisting | medium | Evasion |
| WAF-011 | Log4Shell / JNDI bypass | critical | RCE |
| WAF-012 | Null byte injection bypass | high | Evasion |
| WAF-013 | Bypass via parameter fragmentation | high | Evasion |
| WAF-014 | No rate limiting protection | medium | Rate Limiting |
| WAF-015 | WAF headers revealed in response | low | Information Disclosure |

### Installation

```bash
pip install vamp-waf-bypass
```

Or with Homebrew:

```bash
brew tap vampsecure-labs/labs
brew install vamp-waf-bypass
```

### Usage

```bash
# Basic scan
vamp-waf-bypass https://target.example.com

# Specify injection parameter
vamp-waf-bypass https://target.example.com --param search

# JSON report
vamp-waf-bypass https://target.example.com --json report.json

# HTML report
vamp-waf-bypass https://target.example.com --html report.html

# Filter by severity
vamp-waf-bypass https://target.example.com --severity critical high

# With case metadata
vamp-waf-bypass https://target.example.com --case CASE-2026-001 --analyst "Red Team"

# Quiet mode (exit code only, for CI)
vamp-waf-bypass https://target.example.com --quiet
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | WAF blocking all — no bypasses found |
| 1 | HIGH or MEDIUM bypasses detected |
| 2 | CRITICAL bypass confirmed |

### Sample Output

```
$ vamp-waf-bypass https://testapp.example.com --case CASE-2026-042 --analyst "Red Team VSS"

╭───────────────────────────────────────────────────────────────────╮
│  vamp-waf-bypass — WAF Evasion Tester · VampSecure Labs           │
│  Target  : https://testapp.example.com                            │
│  Case    : CASE-2026-042  · Analyst: Red Team VSS                 │
╰───────────────────────────────────────────────────────────────────╯

[+] WAF Fingerprinting...
    Detected : ModSecurity / OWASP CRS 3.3.4
    Headers  : X-Blocked-By: ModSecurity

╭─ CRITICAL — WAF-002 ────────────────────────────────────────────╮
│ SQLi bypass via URL single-encoding                               │
│ Payload : ?id=1%27%20OR%20%271%27%3D%271                         │
│ Response: HTTP 200 · Content-Type: text/html · 4.2 KB            │
│ Expected: HTTP 403 · BLOCKED                                      │
│ Evidence: Response body contains "syntax error near..."           │
╰──────────────────────────────────────────────────────────────────╯

╭─ CRITICAL — WAF-003 ────────────────────────────────────────────╮
│ SQLi bypass via double URL-encoding                               │
│ Payload : ?id=1%2527%2520OR%2520%25271%2527%253D%25271           │
│ Response: HTTP 200 · 4.1 KB                                       │
│ Evidence: Database error message present in response body         │
╰──────────────────────────────────────────────────────────────────╯

╭─ HIGH — WAF-009 ────────────────────────────────────────────────╮
│ IP spoofing via X-Forwarded-For: 10.0.0.1                        │
│ Response changed from HTTP 429 to HTTP 200                        │
│ Rate-limit bypass: WAF trusts client-supplied IP header           │
╰──────────────────────────────────────────────────────────────────╯

╭─ MEDIUM — WAF-014 ──────────────────────────────────────────────╮
│ No rate limiting on /login endpoint                               │
│ 50 requests in 3.2 s → all HTTP 200 · no throttling detected     │
╰──────────────────────────────────────────────────────────────────╯

╭─ LOW — WAF-015 ─────────────────────────────────────────────────╮
│ WAF product / version disclosed in response headers               │
│ Header: X-Powered-By: ModSecurity 2.9.7                          │
╰──────────────────────────────────────────────────────────────────╯

┌──────────┬──────────────────────────────────────────────────────┐
│ Severity │ Count                                                │
├──────────┼──────────────────────────────────────────────────────┤
│ CRITICAL │ 4                                                    │
│ HIGH     │ 3                                                    │
│ MEDIUM   │ 2                                                    │
│ LOW      │ 1                                                    │
│ PASS     │ 5                                                    │
└──────────┴──────────────────────────────────────────────────────┘
Exit code: 2 (CRITICAL bypass confirmed)
```

### Why vamp-waf-bypass vs. WAFNinja · GoTestWAF · w3af

| Feature | vamp-waf-bypass | WAFNinja | GoTestWAF | w3af |
|---------|:---------------:|:--------:|:---------:|:----:|
| Zero external dependencies (stdlib only) | ✅ | ❌ requests + sqlmap | ❌ Go runtime | ❌ large dep tree |
| WAF fingerprinting — 7 products | ✅ CF/AWS/Azure/ModSec/Nginx/F5/Incapsula | ⚠️ basic | ✅ | ⚠️ |
| Daemon / watch mode (`--watch N`) | ✅ | ❌ | ❌ | ❌ |
| CI/CD exit codes (0 / 1 / 2) | ✅ | ❌ | ✅ | ⚠️ |
| JSON + HTML dark-theme reports | ✅ | ❌ JSON only | ✅ | ⚠️ XML |
| OWASP WSTG-CONF-06 / MITRE ATT&CK T1036 aligned | ✅ | ❌ | ⚠️ partial | ⚠️ partial |
| Case + analyst metadata in report | ✅ | ❌ | ❌ | ❌ |
| Actively maintained (2024–2026) | ✅ | ❌ archived | ✅ | ⚠️ slow releases |

- **No dependencies**: `vamp-waf-bypass` uses only the Python standard library — no pip install, no virtualenv required. Drop it onto any analyst machine or CI runner and it works immediately.
- **Daemon mode**: `--watch N` re-runs the full check suite every N seconds, enabling continuous regression testing after WAF rule updates without scripting external loops.
- **Engagement metadata**: `--case` and `--analyst` fields propagate into JSON and HTML reports, satisfying chain-of-custody requirements for pentest deliverables.
- **Precision over noise**: each of the 15 checks has a dedicated pure function that can be unit-tested offline, ensuring reproducible results and avoiding false positives from network jitter.

### Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| WAF-001 | WAF absent or not detectable on target | OWASP WSTG-CONF-06 | HIGH |
| WAF-002 | SQLi bypass via single URL encoding | OWASP WSTG-INPV-05 · MITRE T1036 | CRITICAL |
| WAF-003 | SQLi bypass via double URL encoding | OWASP WSTG-INPV-05 | CRITICAL |
| WAF-004 | SQLi bypass via inline SQL comment injection | OWASP WSTG-INPV-05 | CRITICAL |
| WAF-005 | XSS bypass via HTML entity encoding | OWASP WSTG-CLNT-01 | CRITICAL |
| WAF-006 | XSS bypass via mixed-case tag variation | OWASP WSTG-CLNT-01 | HIGH |
| WAF-007 | Path traversal bypass via percent-encoded sequences | OWASP WSTG-ATHZ-01 | CRITICAL |
| WAF-008 | HTTP method override via X-HTTP-Method-Override header | OWASP WSTG-CONF-06 | MEDIUM |
| WAF-009 | Access control bypass via spoofed IP headers (X-Forwarded-For) | OWASP WSTG-IDNT-04 | HIGH |
| WAF-010 | WAF whitelist bypass via known-good User-Agent strings | MITRE T1036.005 | MEDIUM |
| WAF-011 | Log4Shell / JNDI injection payload not blocked (CVE-2021-44228) | NIST NVD · MITRE T1190 | CRITICAL |
| WAF-012 | Null byte injection evades pattern matching rules | OWASP WSTG-INPV-11 | HIGH |
| WAF-013 | Parameter fragmentation splits payload across multiple params | OWASP WSTG-INPV-01 | HIGH |
| WAF-014 | No rate limiting detected on sensitive endpoint | OWASP WSTG-CONF-06 | MEDIUM |
| WAF-015 | WAF version / product name disclosed in response headers | OWASP WSTG-INFO-08 | LOW |

### Version History

| Version | Main changes |
|---------|-------------|
| v1.1.1 | Bilingual README (EN/ES) |
| v1.1.0 | Daemon mode (`--watch N`) |
| v1.0.0 | Initial release — 15 checks, WAF fingerprinting, JSON + HTML reports |

---

© VampSecure Studios — VampSecure Labs Security Research Division  
For use in authorized audits only. Unauthorized use is illegal.

---
---

<a name="español"></a>
## 🇪🇸 Español

Herramienta de prueba de evasión WAF — 15 técnicas de bypass para pruebas de seguridad autorizadas.  
Python puro, sin dependencias externas.

> ⚠️ **SOLO PARA PRUEBAS DE SEGURIDAD AUTORIZADAS.** Usar únicamente contra sistemas de tu propiedad o para los que tengas autorización escrita explícita.

### Características

- **15 checks de bypass** (WAF-001–015) que cubren SQLi, XSS, path traversal, override de método, IP spoofing, Log4Shell, rate limiting y más
- **Sin dependencias externas** — usa únicamente la biblioteca estándar de Python (`urllib`, `re`, `json`…)
- **Funciones de check puras** para pruebas unitarias sin llamadas de red
- **Informes JSON + HTML** para pipelines automatizados y revisión humana
- **Fingerprinting WAF** — detecta Cloudflare, Incapsula, Sucuri, AWS WAF, Akamai, ModSecurity y más
- **Exit codes** compatibles con CI: `2` = bypass CRITICAL, `1` = HIGH/MEDIUM, `0` = WAF bloqueando todo

### Checks

| ID | Título | Severidad | Categoría |
|----|--------|-----------|-----------|
| WAF-001 | WAF ausente o no detectado | high | Detección |
| WAF-002 | Bypass SQLi — codificación URL simple | critical | SQLi |
| WAF-003 | Bypass SQLi — doble codificación URL | critical | SQLi |
| WAF-004 | Bypass SQLi — comentarios inline | critical | SQLi |
| WAF-005 | Bypass XSS — HTML entities | critical | XSS |
| WAF-006 | Bypass XSS — variación de mayúsculas | high | XSS |
| WAF-007 | Bypass path traversal — codificado | critical | LFI/Path Traversal |
| WAF-008 | Bypass via X-HTTP-Method-Override | medium | HTTP Method Tampering |
| WAF-009 | Bypass via IP spoofing headers | high | Control de Acceso |
| WAF-010 | Bypass via User-Agent whitelisting | medium | Evasión |
| WAF-011 | Bypass Log4Shell / JNDI | critical | RCE |
| WAF-012 | Bypass null byte injection | high | Evasión |
| WAF-013 | Bypass via fragmentación de parámetros | high | Evasión |
| WAF-014 | Sin protección contra rate limiting | medium | Rate Limiting |
| WAF-015 | Headers WAF revelados en respuesta | low | Information Disclosure |

### Instalación

```bash
pip install vamp-waf-bypass
```

O con Homebrew:

```bash
brew tap vampsecure-labs/labs
brew install vamp-waf-bypass
```

### Uso

```bash
# Escaneo básico
vamp-waf-bypass https://objetivo.example.com

# Especificar parámetro de inyección
vamp-waf-bypass https://objetivo.example.com --param search

# Informe JSON
vamp-waf-bypass https://objetivo.example.com --json informe.json

# Informe HTML
vamp-waf-bypass https://objetivo.example.com --html informe.html

# Filtrar por severidad
vamp-waf-bypass https://objetivo.example.com --severity critical high

# Con metadatos del caso
vamp-waf-bypass https://objetivo.example.com --case CASO-2026-001 --analyst "Equipo Red"

# Modo silencioso (solo exit code, para CI)
vamp-waf-bypass https://objetivo.example.com --quiet
```

### Exit codes

| Código | Significado |
|--------|-------------|
| 0 | WAF bloqueando todo — no se encontraron bypasses |
| 1 | Bypasses HIGH o MEDIUM detectados |
| 2 | Bypass CRITICAL confirmado |

### Ejemplo de salida

```
$ vamp-waf-bypass https://testapp.example.com --case CASO-2026-042 --analyst "Red Team VSS"

╭───────────────────────────────────────────────────────────────────╮
│  vamp-waf-bypass — WAF Evasion Tester · VampSecure Labs           │
│  Target  : https://testapp.example.com                            │
│  Case    : CASO-2026-042  · Analyst: Red Team VSS                 │
╰───────────────────────────────────────────────────────────────────╯

[+] WAF Fingerprinting...
    Detected : ModSecurity / OWASP CRS 3.3.4
    Headers  : X-Blocked-By: ModSecurity

╭─ CRITICAL — WAF-002 ────────────────────────────────────────────╮
│ SQLi bypass via URL single-encoding                               │
│ Payload : ?id=1%27%20OR%20%271%27%3D%271                         │
│ Response: HTTP 200 · Content-Type: text/html · 4.2 KB            │
│ Expected: HTTP 403 · BLOCKED                                      │
│ Evidence: Response body contains "syntax error near..."           │
╰──────────────────────────────────────────────────────────────────╯

╭─ CRITICAL — WAF-003 ────────────────────────────────────────────╮
│ SQLi bypass via double URL-encoding                               │
│ Payload : ?id=1%2527%2520OR%2520%25271%2527%253D%25271           │
│ Response: HTTP 200 · 4.1 KB                                       │
│ Evidence: Database error message present in response body         │
╰──────────────────────────────────────────────────────────────────╯

╭─ HIGH — WAF-009 ────────────────────────────────────────────────╮
│ IP spoofing via X-Forwarded-For: 10.0.0.1                        │
│ Response changed from HTTP 429 to HTTP 200                        │
│ Rate-limit bypass: WAF trusts client-supplied IP header           │
╰──────────────────────────────────────────────────────────────────╯

╭─ MEDIUM — WAF-014 ──────────────────────────────────────────────╮
│ No rate limiting on /login endpoint                               │
│ 50 requests in 3.2 s → all HTTP 200 · no throttling detected     │
╰──────────────────────────────────────────────────────────────────╯

╭─ LOW — WAF-015 ─────────────────────────────────────────────────╮
│ WAF product / version disclosed in response headers               │
│ Header: X-Powered-By: ModSecurity 2.9.7                          │
╰──────────────────────────────────────────────────────────────────╯

┌──────────┬──────────────────────────────────────────────────────┐
│ Severity │ Count                                                │
├──────────┼──────────────────────────────────────────────────────┤
│ CRITICAL │ 4                                                    │
│ HIGH     │ 3                                                    │
│ MEDIUM   │ 2                                                    │
│ LOW      │ 1                                                    │
│ PASS     │ 5                                                    │
└──────────┴──────────────────────────────────────────────────────┘
Exit code: 2 (CRITICAL bypass confirmed)
```

### Por qué vamp-waf-bypass vs. WAFNinja · GoTestWAF · w3af

| Característica | vamp-waf-bypass | WAFNinja | GoTestWAF | w3af |
|----------------|:---------------:|:--------:|:---------:|:----:|
| Sin dependencias externas (solo stdlib) | ✅ | ❌ requests + sqlmap | ❌ Go runtime | ❌ árbol de deps grande |
| Fingerprinting WAF — 7 productos | ✅ CF/AWS/Azure/ModSec/Nginx/F5/Incapsula | ⚠️ básico | ✅ | ⚠️ |
| Modo daemon / watch (`--watch N`) | ✅ | ❌ | ❌ | ❌ |
| Exit codes CI/CD (0 / 1 / 2) | ✅ | ❌ | ✅ | ⚠️ |
| Informes JSON + HTML dark-theme | ✅ | ❌ solo JSON | ✅ | ⚠️ XML |
| Alineado con OWASP WSTG-CONF-06 / MITRE ATT&CK T1036 | ✅ | ❌ | ⚠️ parcial | ⚠️ parcial |
| Metadatos de caso y analista en el informe | ✅ | ❌ | ❌ | ❌ |
| Mantenido activamente (2024–2026) | ✅ | ❌ archivado | ✅ | ⚠️ releases lentas |

- **Sin dependencias**: `vamp-waf-bypass` usa únicamente la biblioteca estándar de Python — sin pip install, sin virtualenv. Se puede copiar a cualquier máquina de analista o runner de CI y funciona inmediatamente.
- **Modo daemon**: `--watch N` vuelve a ejecutar el conjunto completo de checks cada N segundos, permitiendo pruebas de regresión continua tras actualizaciones de reglas WAF sin necesidad de scripts externos.
- **Metadatos del encargo**: los campos `--case` y `--analyst` se propagan a los informes JSON y HTML, cumpliendo los requisitos de cadena de custodia en entregables de pentest.
- **Precisión sobre ruido**: cada uno de los 15 checks tiene una función pura dedicada que puede probarse de forma unitaria offline, garantizando resultados reproducibles y evitando falsos positivos por jitter de red.

### Cobertura de checks

| Check ID | Descripción | Estándar | Severidad |
|----------|-------------|----------|-----------|
| WAF-001 | WAF ausente o no detectable en el objetivo | OWASP WSTG-CONF-06 | HIGH |
| WAF-002 | Bypass SQLi mediante codificación URL simple | OWASP WSTG-INPV-05 · MITRE T1036 | CRITICAL |
| WAF-003 | Bypass SQLi mediante doble codificación URL | OWASP WSTG-INPV-05 | CRITICAL |
| WAF-004 | Bypass SQLi mediante inyección de comentarios SQL inline | OWASP WSTG-INPV-05 | CRITICAL |
| WAF-005 | Bypass XSS mediante codificación de entidades HTML | OWASP WSTG-CLNT-01 | CRITICAL |
| WAF-006 | Bypass XSS mediante variación de mayúsculas en etiquetas | OWASP WSTG-CLNT-01 | HIGH |
| WAF-007 | Bypass path traversal mediante secuencias codificadas en porcentaje | OWASP WSTG-ATHZ-01 | CRITICAL |
| WAF-008 | Override de método HTTP mediante cabecera X-HTTP-Method-Override | OWASP WSTG-CONF-06 | MEDIUM |
| WAF-009 | Bypass de control de acceso mediante cabeceras IP falsificadas (X-Forwarded-For) | OWASP WSTG-IDNT-04 | HIGH |
| WAF-010 | Bypass de whitelist WAF mediante cadenas User-Agent conocidas | MITRE T1036.005 | MEDIUM |
| WAF-011 | Payload Log4Shell / JNDI no bloqueado (CVE-2021-44228) | NIST NVD · MITRE T1190 | CRITICAL |
| WAF-012 | Inyección de null byte evade reglas de coincidencia de patrones | OWASP WSTG-INPV-11 | HIGH |
| WAF-013 | Fragmentación de parámetros divide el payload entre múltiples params | OWASP WSTG-INPV-01 | HIGH |
| WAF-014 | Sin rate limiting detectado en endpoint sensible | OWASP WSTG-CONF-06 | MEDIUM |
| WAF-015 | Versión / nombre del producto WAF revelado en cabeceras de respuesta | OWASP WSTG-INFO-08 | LOW |

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.1.1 | README bilingüe (EN/ES) |
| v1.1.0 | Modo daemon (`--watch N`) |
| v1.0.0 | Versión inicial — 15 checks, fingerprinting WAF, informes JSON + HTML |

---

© VampSecure Studios — VampSecure Labs Security Research Division  
Uso exclusivo en auditorías autorizadas. El uso no autorizado es ilegal.

## License

AGPL-3.0-only — see [LICENSE](LICENSE).
