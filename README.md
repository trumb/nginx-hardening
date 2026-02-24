# nginx-hardening

OWASP-hardened nginx security baseline that blocks 19 attack categories. Every blocking rule was derived from **live honeypot data** — real scanners probing a real server, with ongoing updates from continuous honeypot monitoring.

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
| 1 | **Dotfiles** | Credential theft | `.env`, `.git/config`, `.DS_Store`, `.vscode/sftp.json` |
| 2 | **Script extensions** | Remote code execution | `.php`, `.asp`, `.jsp`, `.cgi` |
| 3 | **Source maps** | Source code / API key theft | `*.js.map`, `*.json.map` (20+ variants observed) |
| 4 | **Config files** | Secret exposure | `credentials.json`, `config.env`, `docker-compose.yml` |
| 5 | **WordPress** | Plugin exploits, user enum | `wp-admin`, `wp-content`, `wp-json`, `xmlrpc.php` |
| 6 | **Spring Actuator** | Env var dump (DB creds) | `actuator/env`, `manage/env`, `configprops` |
| 7 | **Swagger/OpenAPI** | API enumeration | `swagger-ui.html`, `api-docs`, `swagger.json` |
| 8 | **PHP/Laravel debug** | App state dump | `_profiler`, `telescope`, `_ignition`, `_wdt` |
| 9 | **Container/K8s** | Secret theft | `v2/_catalog`, `api/v1/namespaces/default/secrets` |
| 10 | **JS dev tools** | Dev server exploit | `@vite/client`, `webpack-dev-server`, `_next/data` |
| 11 | **Atlassian** | RCE (CVEs) | `login.action`, `META-INF/maven/...` |
| 12 | **MS Exchange** | ProxyShell/ProxyLogon | `/ecp/` |
| 13 | **GraphQL** | Schema enumeration | `graphql`, `api/graphql`, `api/gql` |
| 14 | **Admin panels** | Auth bypass | `phpmyadmin`, `adminer`, `solr`, `server-status` |
| 15 | **CVE probes** | Fingerprinting | `__cve_probe` patterns |
| 16 | **WP user enum** | Username harvest | `?rest_route=/wp/v2/users` |
| 17 | **Path traversal** | Arbitrary file read / RCE | `/cgi-bin/.%2e/.%2e/bin/sh` (CVE-2021-41773) |
| 18 | **Phishing kits** | Hosted phishing detection | `/js/twint_ch.js`, `/js/lkk_ch.js` |
| 19 | **Backup/bin dirs** | Data theft, shell access | `/backup/`, `/bins/`, `/bin/`, `/dump/`, `/sql/` |

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
examples/
  hardened-site.conf                  # Full example: hardened site with TLS, CSP, rate limiting
  scanner-ua-blocking.conf            # Optional: drop known scanner User-Agents (444)
```

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

### Attacker Stats (First 10 Minutes)

| Scanner | Requests | Targets |
|---------|----------|---------|
| LeakIX (l9scan) | 20 | Dotfiles, GraphQL, Swagger, Vite, Actuator |
| Unknown (via Cloudflare) | 100+ | .env (21 variants), source maps, WP, K8s, Exchange, Confluence |
| PHP exploit bot | 1 | `/_internal/api/setup.php` |
| Fingerprint bot | 1 | HEAD / (server detection) |

## Optional: Scanner UA Blocking

For public-facing servers, you can also block known scanner User-Agents. See `examples/scanner-ua-blocking.conf`.

This drops connections (nginx 444) from tools like: nuclei, zgrab, masscan, censys, shodan, nmap, nikto, sqlmap, dirbuster, gobuster, ffuf, wfuzz, wpscan, mrtscan, Palo Alto Cortex Xpanse, and more.

Also detects scanner signatures:
- Truncated Chrome UA (missing `(KHTML, like Gecko) Chrome/xxx`)
- Bare `Mozilla/5.0` with no engine details
- Ancient Chrome versions (pre-2020)
- Empty User-Agent

## Contributing

Found a new attack pattern? Open a PR. Include:
1. The request path or pattern
2. What it targets (framework, service, vulnerability)
3. Where you observed it (honeypot logs, security scan, etc.)

## License

[MIT](LICENSE) — use it however you want.
