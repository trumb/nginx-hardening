# nginx-hardening

OWASP-hardened nginx security baseline that blocks **35 attack categories**. Every blocking rule was derived from **live honeypot data** — real scanners probing a real server, with ongoing updates from continuous honeypot monitoring.

## Quick Start

```bash
# Install the snippet
sudo cp security-hardening.conf /etc/nginx/snippets/

# Add to every server block
# include /etc/nginx/snippets/security-hardening.conf;

# Test and reload
sudo nginx -t && sudo systemctl reload nginx
```

## What It Blocks

| # | Category | Threat | Examples |
|---|----------|--------|----------|
| 1 | **Dotfiles** | Credential theft | `.env` (21+ variants), `.git/config`, `.DS_Store`, `.aws/credentials` |
| 2 | **Script extensions** | Remote code execution | `.php`, `.asp`, `.jsp`, `.cgi` |
| 3 | **Source maps** | Source code / API key theft | `*.js.map`, `*.json.map` (20+ variants observed) |
| 4 | **Config files** | Secret exposure | `credentials.json`, `config.env`, `config.json`, `docker-compose.yml` |
| 5 | **WordPress** | Plugin exploits, user enum | `wp-admin`, `wp-content`, `wp-json`, `xmlrpc.php`, `wlwmanifest.xml` |
| 6 | **Spring Actuator** | Env var dump (DB creds) | `actuator/env`, `manage/env`, `actuator/gateway/routes` |
| 7 | **Swagger/OpenAPI** | API enumeration | `swagger-ui.html`, `api-docs`, `swagger.json` |
| 8 | **PHP/Laravel debug** | App state dump | `_profiler`, `telescope`, `_ignition`, `_wdt` |
| 9 | **Container/K8s** | Secret theft | `v2/_catalog`, `api/v1/namespaces/default/secrets` |
| 10 | **JS dev tools** | Dev server exploit | `@vite/client`, `webpack-dev-server`, `_next/data`, `_next/server` |
| 11 | **Atlassian** | RCE (CVEs) | `login.action`, `META-INF/maven/...` |
| 12 | **MS Exchange** | ProxyShell/ProxyLogon | `/ecp/` |
| 13 | **GraphQL** | Schema enumeration | `graphql`, `api/graphql`, `api/gql` |
| 14 | **Admin panels** | Auth bypass | `phpmyadmin`, `adminer`, `solr`, `hudson`, `druid`, `jenkins` |
| 15 | **CVE probes** | Fingerprinting | `__cve_probe` patterns |
| 16 | **WP user enum** | Username harvest | `?rest_route=/wp/v2/users` |
| 17 | **Path traversal** | Arbitrary file read / RCE | `cgi-bin/.%2e/`, `..%2F`, `%%32%65`, `/etc/passwd` |
| 18 | **Phishing kits** | Hosted phishing detection | `/js/twint_ch.js`, `/js/lkk_ch.js` |
| 19 | **Backup/bin dirs** | Data theft, shell access | `/backup/`, `/bins/`, `/logs/`, `database.sql` |
| 20 | **robots/security.txt** | Info disclosure | *(optional — uncomment to hide)* |
| 21 | **HNAP/Router** | Router exploitation | `/HNAP1` (Mirai variants, D-Link/Netgear) |
| 22 | **VPN/SSL Gateways** | Credential harvest, CVE | `/+CSCOE+/` (Cisco), `/dana-na/` (Pulse Secure/Ivanti) |
| 23 | **Apache Struts** | RCE (CVE-2017-5638+) | `/struts/utils.js`, `/struts2-showcase/`, `/struts2-rest-showcase/` |
| 24 | **Log4Shell/JNDI** | RCE (CVE-2021-44228) | `${jndi:ldap://...}` in URI, Referer, and UA headers |
| 25 | **SSH Key / Cloud Creds** | Private key theft | `/id_rsa`, `/id_ed25519`, `/.aws/credentials` |
| 26 | **IoT/OEM Devices** | Default cred abuse, RCE | `/boaform/` (TP-Link), `/GponForm/` (GPON), `/sdk` (Hikvision), `/evox/` |
| 27 | **Package manager files** | Dependency confusion | `composer.json`, `yarn.lock`, `package.json`, `pom.xml`, `Gemfile` |
| 28 | **App settings files** | Credential exposure | `appsettings.json`, `settings.py`, `web.xml`, `WEB-INF/`, `.nsf` |
| 29 | **XDEBUG** | Remote debug hijack | `?XDEBUG_SESSION_START=phpstorm` |
| 30 | **Enterprise apps** | SAP/ManageEngine RCE | `/developmentserver/` (SAP CVE-2020-6287), `/PassTrixMain.cc` |
| 31 | **InfluxDB** | Data exfiltration | `/query?q=SHOW+DIAGNOSTICS` |
| 32 | **Network infra** | Industrial/SCADA discovery | `/portal/redlion`, `/cgi-bin/luci/` (OpenWrt), QNAP NAS |
| 33 | **Lotus Notes** | Legacy exploitation | `.nsf` files (Domino) |
| 34 | **Login discovery** | Credential stuffing | Framework-specific login pages (informational) |
| 35 | **Misc exploit paths** | Mixed product exploits | PHP RCE via `auto_prepend_file`, `/functionRouter`, Apache OFBiz |

## Security Headers

Automatically added to every response:

| Header | Value |
|--------|-------|
| `X-Frame-Options` | `SAMEORIGIN` |
| `X-Content-Type-Options` | `nosniff` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |

Plus: `server_tokens off` and `autoindex off`.

## Files

```
security-hardening.conf              # The main snippet — include in every server block
autoharden.py                        # Automated log analysis + rule generation (stdlib only)
config.example.json                  # Example config — copy to config.json and customize
examples/
  hardened-site.conf                  # Full example: hardened site with TLS, CSP, rate limiting
  scanner-ua-blocking.conf            # Optional: drop known scanner User-Agents (444)
```

## Auto-Hardener

`autoharden.py` is a Python script (stdlib only, no pip) that automatically analyzes nginx honeypot logs, detects new attack patterns, and generates blocking rules. It runs daily via a systemd timer.

### What It Does

1. **Parses honeypot logs** — reads `/var/log/nginx/claw-access.log` (tracks offset to only process new entries)
2. **Detects patterns** — paths returning 200 that aren't known routes, new scanner User-Agents appearing 3+ times, suspicious paths with attack markers
3. **Generates rules** — appends `location` blocks to `security-hardening.conf` and UA patterns to the site config
4. **Validates** — runs `nginx -t` before reloading; rolls back `.bak` on failure
5. **Syncs** — commits and pushes new rules to this repo

### Safety Guarantees

- **Additive only** — never removes existing rules
- **Max 10 new rules per run** — prevents runaway
- **Backup before edit** — `.bak` files created before any config change
- **`nginx -t` validation** — rollback on syntax failure
- **Whitelisted paths** — `/health`, `/favicon.ico`, `/.well-known/acme-challenge/`, all honeypot routes
- **`--dry-run` flag** — preview changes without applying

### Setup

```bash
# Install
sudo mkdir -p /opt/nginx-hardening /var/log/nginx-hardening
sudo cp autoharden.py /opt/nginx-hardening/
sudo cp config.example.json /opt/nginx-hardening/config.json
# Edit /opt/nginx-hardening/config.json with your paths and routes

# Test
sudo python3 /opt/nginx-hardening/autoharden.py --dry-run

# Enable daily timer
sudo python3 /opt/nginx-hardening/autoharden.py --enable-timer
```

### Configuration — `config.json`

| Key | Description |
|-----|-------------|
| `log_files` | Nginx log files to parse (default: `claw-access.log`) |
| `hardening_conf` | Path to `security-hardening.conf` snippet |
| `claw_site_conf` | Path to the site-specific nginx config |
| `honeypot_routes` | Known good routes (won't trigger path rules) |
| `whitelisted_paths` | Paths to never block |
| `whitelisted_ua_patterns` | UA strings to never block |
| `min_occurrences` | Minimum hits before generating a rule (default: 3) |
| `max_rules_per_run` | Cap on new rules per execution (default: 10) |

## Optional: Scanner UA Blocking

For public-facing servers, you can also block known scanner User-Agents. See `examples/scanner-ua-blocking.conf`.

This drops connections (nginx 444) from tools like: nuclei, zgrab, masscan, censys, shodan, nmap, nikto, sqlmap, dirbuster, gobuster, ffuf, wfuzz, wpscan, mrtscan, Palo Alto Cortex Xpanse, and more.

**New in v2.0.0:** Also blocks HTTP library scanners and headless browsers:

| Category | Blocked | Hit Count |
|----------|---------|-----------|
| Security scanners | l9scan, l9explore, nuclei, zgrab, censys, nmap, nikto, sqlmap... | 600+ |
| Attack surface management | Palo Alto Cortex Xpanse, BitSightBot, ModatScanner, Odin | 180+ |
| HTTP libraries (used as scanners) | python-requests, python-httpx, fasthttp, go-http-client, curl, wget, libredtail, xfa1 | 200+ |
| Headless browsers | HeadlessChrome | 6 |
| Truncated/fake UAs | Bare `Mozilla/5.0`, ancient Chrome (<80), missing KHTML | 250+ |
| Novelty UAs | `Hello, World`, `ECHOSCU`, `Explorer`, `Mozilla/1.0` | 60+ |

Also detects scanner signatures:
- Truncated Chrome UA (missing `(KHTML, like Gecko) Chrome/xxx`)
- Bare `Mozilla/5.0` with no engine details
- Partial Mozilla with no engine (e.g., `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` alone)
- Ancient Chrome versions (pre-2020)
- Empty User-Agent
- Ancient `Mozilla/0.x` and `Mozilla/1.x`

## Full Hardened Server Checklist

When deploying any nginx server:

- [ ] `include /etc/nginx/snippets/security-hardening.conf;`
- [ ] TLS 1.2+ only with ECDHE ciphers
- [ ] `Content-Security-Policy` header (app-specific)
- [ ] `client_max_body_size` set (default: `10m`)
- [ ] Method restriction (GET/POST/PUT/PATCH/DELETE/OPTIONS only)
- [ ] Rate limiting appropriate to the service
- [ ] ACME challenge location for cert renewals

## How This Was Built

1. Deployed a public-facing honeypot behind Cloudflare
2. First automated scanner arrived in **< 30 seconds**
3. Collected 180+ attack requests in the first 10 minutes
4. Cataloged every attack path, user-agent, and technique
5. Built blocking rules for each category
6. Verified every rule against the live data
7. Ongoing monitoring adds new categories as they appear

### Attacker Stats

| Period | Scanners | New Categories | Key Findings |
|--------|----------|---------------|--------------|
| First 10 min (Feb 23) | LeakIX, unknown bot, PHP bot | 19 | .env (21 variants), source maps, WP, K8s, Confluence |
| Feb 24 — Mar 8 | autoharden.py detections | +1 | config.json, api/config probes |
| **Mar 9 — Mar 23** | **Greenbone, Nmap, Censys, Palo Alto, BitSight, Odin, ModatScanner, FreePBX** | **+15** | **JNDI/Log4Shell (30 attempts from Greenbone), HNAP (66x), Hikvision SDK (64x), Struts RCE, VPN gateways, IoT exploits, SSH key theft** |

### Top New Scanners (Mar 9–23)

| Scanner | Requests | Targets |
|---------|----------|---------|
| Greenbone (Nmap UA) | 262 | JNDI/Log4Shell, path traversal (100+ /etc/passwd variants) |
| CensysInspect | 198 | General fingerprinting |
| GenomeCrawlerd (Nokia) | 137 | Web crawling/fingerprinting |
| mrtscan | 101 | Router/device discovery |
| Go-http-client | 99 | HNAP, SDK, boaform, evox, printer probes |
| Palo Alto Cortex Xpanse | 84 | Attack surface mapping |
| BitSightBot | 60 | Security rating scans |
| l9explore (LeakIX) | 59 | Dotfiles, GraphQL, Swagger, Actuator |
| libredtail-http | 49 | PHP RCE (auto_prepend_file) |

## Contributing

Found a new attack pattern? Open a PR. Include:
1. The request path or pattern
2. What it targets (framework, service, vulnerability)
3. Where you observed it (honeypot logs, security scan, etc.)

## Changelog

### v2.0.0 (2026-03-23)
- **15 new blocking categories** (21→35 total) from Mar 9–23 log analysis
- New: HNAP/router, VPN/SSL gateways, Apache Struts, Log4Shell/JNDI, SSH key theft, IoT/OEM devices, package manager files, app settings, WEB-INF, XDEBUG, enterprise apps, InfluxDB, network infrastructure, Lotus Notes, misc exploit paths
- Enhanced path traversal: `..%2F`, `%%32%65` double-encoding, `/etc/passwd`
- Consolidated redundant auto-generated rules into proper categories
- Updated scanner UA blocking: 15 new signatures (libredtail, fasthttp, python-httpx, ModatScanner, FreePBX-Scanner, GenomeCrawlerd, BitSightBot, Odin, HeadlessChrome, xfa1, and more)
- Added truncated UA variants, partial Mozilla detection, novelty UA blocking

### v1.3.0 (2026-03-02)
- Track autoharden script in repo, update README with docs

### v1.2.0 (2026-02-24)
- Auto-generated rules from honeypot log analysis

### v1.1.0 (2026-02-24)
- Add okhttp and Go-http-client to scanner UA blocklist

### v1.0.0 (2026-02-23)
- Initial release: 19 attack categories from first honeypot deployment

## License

[MIT](LICENSE) — use it however you want.
