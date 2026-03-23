# `claude-nginx-hardening` Phase 3 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add advanced operations — canary deployment, IoC/threat intel integration, recipe system with scheduling, remote deployment via SSH, rule aging/decay, and environment profile activation.

**Architecture:** Builds on Phase 1+2 foundation. Adds 3 new Python scripts, 3 new commands, enhances existing commands, and adds the full IoC pipeline with 10 built-in threat feeds.

**Tech Stack:** Python 3.10+ (stdlib only), Bash, SSH/sshpass, existing plugin infrastructure.

---

## Task 1: Write canary-deployer.py

**Files:**
- Create: `scripts/canary-deployer.py`

Manages phased remote deployment with canary verification.

### Deployment Phases

1. **Validate locally** — Run invariant-checker.py + compatibility-checker.py
2. **Sync without reload** — Copy config to target host(s) via SSH, do NOT reload
3. **Reload canary host** — Pick first host as canary, reload nginx there
4. **Verify canary** — Run checks on canary: nginx -t pass, reload success, health endpoint responds, key deny paths return 404
5. **Fan out** — On canary success, reload remaining hosts one by one
6. **Summarize** — Per-host outcome report

### CLI

```
python3 scripts/canary-deployer.py \
  --config-file PATH \
  --hosts host1,host2,host3 \
  --ssh-user USER \
  --ssh-key PATH | --ssh-pass-env ENV_VAR \
  --remote-config-path /etc/nginx/snippets/security-hardening.conf \
  --health-endpoint /health \
  --verify-deny-paths "/.env,/wp-admin,/actuator/env" \
  [--canary-host host1] \
  [--dry-run]
```

Credentials: SSH key path or sshpass via env var name (Invariant 18 — never embed secrets).

### Output JSON

```json
{
  "phase": "complete",
  "canary_host": "host1",
  "canary_result": {
    "sync": "pass",
    "nginx_test": "pass",
    "reload": "pass",
    "health_check": "pass",
    "deny_checks": {"/.env": 404, "/wp-admin": 404}
  },
  "hosts": {
    "host1": {"status": "pass", "role": "canary"},
    "host2": {"status": "pass", "role": "follower"},
    "host3": {"status": "fail", "role": "follower", "error": "reload failed"}
  },
  "stopped_at": "host3",
  "rollback_needed": ["host3"]
}
```

On partial failure: stop fanout immediately, report which hosts need rollback.

### Safety

- `--dry-run` shows what would happen without executing
- Never stores SSH passwords — reads from env var at runtime
- Stops on first failure during fanout (no "push through errors")
- Each host gets its own nginx -t before reload
- Health check timeout: 10 seconds, 3 retries

Commit after implementation and tests.

---

## Task 2: Write deploy-planner.py (remote deploy orchestration)

**Files:**
- Create: `scripts/deploy-planner.py`

Generates deployment plan JSON for both local and remote deployments. Integrates with canary-deployer.py.

### Functions

- Parse host inventory from recipe config or CLI args
- Determine deployment order (canary first, then alphabetical)
- Generate per-host pre-flight checklist
- Estimate deployment time
- Create rollback plan for each host

### CLI

```
python3 scripts/deploy-planner.py \
  --hosts host1,host2,host3 \
  --config-file PATH \
  --remote-config-path PATH \
  [--canary-host HOST]
```

### Output

Deployment plan JSON with ordered steps, per-host commands, verification checks, and rollback procedures.

Commit.

---

## Task 3: Write rule-aging.py

**Files:**
- Create: `scripts/rule-aging.py`

Manages rule aging and decay — identifies stale rules that may no longer be needed.

### Functions

- **scan** — Scan all blocking rules in a config, cross-reference with recent logs to find rules that haven't matched anything in N days
- **report** — Generate a staleness report: rule, last seen, days since last hit, recommendation (keep/review/remove)
- **tag** — Add aging metadata comments to rules (e.g., `# last-hit: 2026-03-15, hits-30d: 42`)

### CLI

```
python3 scripts/rule-aging.py scan --config PATH --log-data PATH [--stale-days 90]
python3 scripts/rule-aging.py report --config PATH --log-data PATH
python3 scripts/rule-aging.py tag --config PATH --log-data PATH
```

Note: "remove" is recommendation only — Invariant 1 (additive-only) means the tool never deletes rules automatically. Stale rules are flagged for human review.

### Output JSON (report)

```json
{
  "total_rules": 35,
  "active_rules": 28,
  "stale_rules": 7,
  "rules": [
    {
      "category": "lotus",
      "pattern": "\\.nsf$",
      "last_hit": "2026-02-24",
      "days_since_hit": 27,
      "hits_30d": 0,
      "hits_90d": 8,
      "recommendation": "review",
      "reason": "No hits in 27 days but historically active"
    }
  ]
}
```

Commit.

---

## Task 4: Write /ioc-nginx command

**Files:**
- Create: `commands/ioc-nginx.md`

IoC response command — parse indicators, cross-reference logs, generate containment rules.

### Invocation

- `/harden-nginx ioc /path/to/rule.yar` — Parse YARA rule file
- `/harden-nginx ioc CVE-2024-XXXXX` — Look up CVE and generate rules
- `/harden-nginx ioc` — Interactive, paste or describe the IoC
- `/harden-nginx ioc --feed` — Poll configured threat feeds

### Response Modes

**Advisory** (default) — Cross-reference only, no rule generation. Shows: "This IoC has been seen N times in your logs."

**Stage** (`--stage`) — Generate candidate rules + severity assessment. Write to outputs/<run-id>/.

**Emergency Containment** (`--emergency`) — Allowed ONLY for Class A controls (containment) when:
- Source provenance is recorded
- Confidence threshold >= 0.8
- Scope is narrow (exact-location or server-block only)
- TTL is assigned (not permanent by default)
- All invariants pass
- Must NOT modify TLS, headers, routing, or location precedence

### IoC Parsing

**YARA files (.yar):**
- Extract `strings:` section
- Map string patterns to nginx-matchable paths/UAs
- Generate location blocks for path patterns
- Generate UA blocks for user-agent patterns

**CVE lookup:**
- Use NVD API to fetch CVE details
- Extract known exploit paths from description/references
- Generate blocking rules for known paths
- Assign severity from CVSS score

**Plain text lists:**
- One indicator per line (paths, UAs, IPs)
- Classify each into rule class

**STIX JSON:**
- Extract URL and HTTP-related indicators
- Map to nginx blocking rules

**Manual entry:**
- User describes the IoC in natural language
- Agent interprets and generates appropriate rules

### Log Cross-Reference

For each parsed indicator:
1. Run sanitizer.py to normalize the indicator
2. Search sanitized log data for matches
3. Report: indicator, match count, first seen, last seen, affected server blocks

### Output

Artifacts in `outputs/<run-id>/`:
- `ioc-findings.json` — Findings from IoC analysis
- `ioc-proposed-rules/` — Candidate blocking rules
- `ioc-report.md` — Human-readable summary
- Learning file in `learnings/ioc-responses/`

Commit.

---

## Task 5: Write /manage-recipes command

**Files:**
- Create: `commands/manage-recipes.md`

Full recipe lifecycle management.

### Subcommands

**create** — Interactive recipe builder:
1. Name (kebab-case)
2. Description
3. Profile (select from 6 options)
4. Steps (add one at a time: analyze-logs, audit-config, check-ioc-feeds, deploy, compact-learnings, sync-repos)
5. Parameters for each step
6. Schedule (manual, cron expression, systemd timer)
7. Deployment target (local, remote, generate-only)
8. Confirmation checkpoints
9. Max privilege level
10. Validate via schema-validator.py
11. Write to learnings/recipes/

**run <recipe-name>** — Execute a saved recipe:
1. Load recipe from learnings/recipes/
2. Show privilege summary (first execution always)
3. Execute steps in order
4. Pause at confirmation checkpoints
5. Write run results to outputs/

**list** — Show all recipes with name, description, schedule, last run.

**edit <recipe-name>** — Modify an existing recipe interactively.

**install <recipe-name>** — Install schedule:
- **local**: Generate and install crontab entry or systemd timer
- **remote**: SSH to target, install cron/systemd (credentials from env vars)
- **generate-only**: Output the crontab/systemd config for manual install

**export <recipe-name>** — Export recipe as standalone YAML for sharing.

### Scheduling

Cron format: `schedule: "0 9 * * 1"` (Monday 9am)

For local install:
```bash
# Generates and installs crontab entry
(crontab -l 2>/dev/null; echo "0 9 * * 1 cd /path/to/repo && claude /harden-nginx run weekly-scan") | crontab -
```

For remote install via SSH:
- Uses NH_SSH_HOST, NH_SSH_USER, NH_SSH_KEY or NH_SSH_PASS_ENV
- Copies recipe to remote host
- Installs crontab entry on remote

### Safety

- First execution always shows privilege summary
- Cannot suppress invariants
- Cannot embed secrets
- Write-capable recipes require confirmation unless marked non-interactive
- `auto_approve` field: only auto-accepts findings at or below specified severity

Commit.

---

## Task 6: Write threat feed integration

**Files:**
- Create: `scripts/feed-poller.py`
- Create: `skills/nginx-hardening/THREAT-FEEDS.md`

### feed-poller.py

Stdlib-only Python script that polls threat intelligence feeds and outputs normalized indicators.

**Built-in feeds (10):**

| Feed | URL | Format | Auth |
|------|-----|--------|------|
| AlienVault OTX | `https://otx.alienvault.com/api/v1/pulses/subscribed` | JSON | API key (NH_OTX_TOKEN) |
| Abuse.ch URLhaus | `https://urlhaus-api.abuse.ch/v1/urls/recent/` | JSON | None |
| Abuse.ch ThreatFox | `https://threatfox-api.abuse.ch/api/v1/` | JSON | None |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | JSON | None |
| Emerging Threats | `https://rules.emergingthreats.net/open/suricata/rules/emerging-web_server.rules` | Suricata rules | None |
| PhishTank | `https://data.phishtank.com/data/online-valid.json` | JSON | API key (NH_PHISHTANK_KEY) optional |
| Blocklist.de | `https://api.blocklist.de/getlast.php?time=86400` | Text (IPs) | None |
| Feodo Tracker | `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt` | Text (IPs) | None |
| OpenPhish | `https://openphish.com/feed.txt` | Text (URLs) | None |
| NVD/CVE API | `https://services.nvd.nist.gov/rest/json/cves/2.0` | JSON | API key (NH_NVD_KEY) optional |

**CLI:**
```
python3 scripts/feed-poller.py --feeds builtin [--feed-name urlhaus,cisa_kev] [--custom-config PATH]
python3 scripts/feed-poller.py --feeds custom --config PATH
python3 scripts/feed-poller.py --feeds all --config PATH
```

**Custom feed config** (in learnings/infrastructure/feeds.md frontmatter):
```yaml
custom:
  - name: "internal-threat-intel"
    url: "https://threatintel.internal/api/v1/indicators"
    format: stix
    auth_header_env: "THREAT_INTEL_TOKEN"
    poll_interval: "daily"
```

**Output:** Normalized indicators JSON:
```json
{
  "feed": "urlhaus",
  "polled_at": "2026-03-23T22:00:00Z",
  "indicators": [
    {
      "type": "url_path",
      "value": "/malware/download.php",
      "confidence": 0.9,
      "source": "urlhaus",
      "first_seen": "2026-03-22",
      "tags": ["malware", "dropper"]
    }
  ]
}
```

**Safety:**
- Credentials from env vars only (Invariant 18)
- Feed unavailable → continue without that feed, mark partial (Failure Policy)
- All feed data passes through sanitizer before reaching LLM
- HTTP timeout: 30 seconds per feed
- Rate limiting: respect feed provider limits

### THREAT-FEEDS.md

Reference document listing all 10 built-in feeds, custom feed configuration, auth setup, and polling best practices.

Commit.

---

## Task 7: Update /harden-nginx for Phase 3 routing

**Files:**
- Modify: `commands/harden-nginx.md`

Add routing for:
- `ioc <source>` → dispatch /ioc-nginx
- `recipe <action>` → dispatch /manage-recipes
- `aging` or `stale` → run rule-aging.py report

Update interactive menu:
```
1. Full lifecycle
2. Analyze logs
3. Audit config
4. Deploy
5. Respond to IoC / threat intel
6. Manage recipes
7. Manage exceptions
8. Review/manage learnings
9. Rollback
10. Rule aging report
```

Commit.

---

## Task 8: Update deploy-nginx.md for remote/canary

**Files:**
- Modify: `commands/deploy-nginx.md`

Add remote deployment section:
- `--remote` flag activates X1 execution class
- Uses canary-deployer.py for phased rollout
- Requires: NH_SSH_HOST, NH_SSH_USER, NH_SSH_KEY or NH_SSH_PASS_ENV
- Canary verification before full fanout
- Per-host results and rollback plan on partial failure

Commit.

---

## Task 9: Activate environment profiles

**Files:**
- Modify: `commands/audit-nginx.md` — Add `--profile` flag that loads profile-specific settings
- Modify: `commands/analyze-nginx-logs.md` — Add `--profile` flag
- Modify: `commands/harden-nginx.md` — Add `--profile` flag, auto-detect from config if possible

When a profile is set:
- Compatibility checker uses profile-specific severity levels
- Blast radius thresholds adjust per profile
- Rule class restrictions apply (e.g., internal-only blocks Class A)
- Default analysis level set per profile

Commit.

---

## Task 10: Update README and wiki for Phase 3

**Files:**
- Modify: `README.md`
- Update wiki pages

README updates:
- Mark Phase 3 as done in roadmap
- Add IoC/threat intel section with built-in feeds table
- Add recipe system section
- Add canary deployment section
- Add rule aging section
- Document remote deployment
- Document environment profile activation

Wiki updates:
- IoC-Response.md — Full examples with all sources
- Threat-Feeds.md — Built-in feed details, custom feed setup
- Recipes.md — Full examples with scheduling
- Commands.md — Add ioc, recipe commands, --profile flag
- Home.md — Mark Phase 3 complete

Commit and push both.

---

## Task 11: Phase 3 integration test

Full integration test:
1. All new scripts pass (canary-deployer.py, deploy-planner.py, rule-aging.py, feed-poller.py)
2. IoC command parses sample YARA rule and generates rules
3. Recipe create/list/run works
4. Feed poller connects to at least one public feed (CISA KEV — no auth required)
5. Rule aging report runs against test config + log data
6. Profile flag changes audit behavior
7. All Phase 1+2 scripts still pass
8. --json output valid on all commands
9. Git history clean

Final commit, push, and version bump to 1.0.0.
