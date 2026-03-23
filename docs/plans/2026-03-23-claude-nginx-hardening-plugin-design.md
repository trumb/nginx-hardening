# Design: `claude-nginx-hardening` Plugin

**Date:** 2026-03-23
**Status:** Approved
**Repo:** `claude-nginx-hardening` (public, standalone)
**Parent project:** `nginx-hardening` (security configs, separate repo)

---

## 1. Identity

* **Repo:** `claude-nginx-hardening`
* **Type:** Standalone Claude Code plugin
* **Runtime:** Claude Code on Linux/macOS
* **Purpose:** Full lifecycle nginx hardening workflow for detecting risk, analyzing hostile traffic, generating additive mitigations, staging or deploying reviewed controls, responding to indicators of compromise, and maintaining ongoing operational hygiene.

## 2. Design Goals

1. Preserve nginx availability while improving security posture.
2. Never expose raw attacker-controlled log content to LLM reasoning.
3. Keep all generated controls additive, reviewable, reversible, and narrowly scoped.
4. Make every write path deterministic, auditable, and rollbackable.
5. Support both human-driven and automation-friendly workflows.
6. Prefer staged recommendation over direct enforcement unless explicitly requested.

## 3. Non-Goals

* Full WAF replacement
* Destructive config rewrites
* Application-layer behavioral tuning outside nginx scope
* Autonomous emergency actions without explicit operator consent
* Secret storage inside plugin state

---

## 4. Top-Level Operating Modes

### 4.1 Recommendation Mode

Default for all commands unless explicitly overridden.

Produces:

* findings
* candidate rules
* risk scoring
* artifact bundle
* deployment plan
* exception deltas
* learning deltas

Does **not**:

* write nginx config
* reload nginx
* push to git
* install cron/systemd timers
* perform remote SSH deploys

### 4.2 Enforcement Mode

Explicit operator-selected mode.

May perform:

* local writes
* validation
* backup
* reload
* git commit/push
* remote sync/deploy
* recipe installation

Requires:

* explicit approval of staged actions
* invariant pass
* schema validation pass
* `nginx -t` pass
* backup success

---

## 5. Execution Policy Matrix

Every command and sub-action must declare its execution class.

### 5.1 Action Classes

* **R0 — Read-only:** Read configs, logs, recipes, learnings, feeds, and local metadata.
* **R1 — Stage-only:** Generate proposed rules, reports, JSON outputs, recipes, and deployment plans without touching active config.
* **W1 — Local write:** Write staged files, backups, reports, learning entries, exceptions, and optional local config snippets.
* **W2 — Network write:** Git push, feed polling state updates, remote API writes if ever added.
* **X1 — Remote exec:** SSH deploy, remote validation, remote reload, cron/systemd installation on remote systems.

### 5.2 Default Policy by Command

| Command | Default | `--apply` | `--deploy` |
|---------|---------|-----------|------------|
| `/harden-nginx` (bare) | R0 + R1 | — | — |
| `/harden-nginx audit` | R0 + R1 | W1 | W1 + W2 + X1 |
| `/harden-nginx analyze-logs` | R0 + R1 | — | — |
| `/harden-nginx ioc` | R0 + R1 | W1 | W1 + X1 |
| `/harden-nginx deploy` | requires explicit target | W1 | W1 + W2 + X1 |
| `/harden-nginx rollback` | R0 + R1 (preview) | W1 | W1 + X1 |
| `/harden-nginx recipe` | R0 + R1 | W1 | X1 |
| `/harden-nginx exceptions` | R0 + R1 | W1 | — |

---

## 6. Plugin Structure

```text
claude-nginx-hardening/
  .claude-plugin/
    plugin.json
  commands/
    harden-nginx.md
    audit-nginx.md
    analyze-nginx-logs.md
    deploy-nginx.md
    rollback-nginx.md
    ioc-nginx.md
    manage-recipes.md
    manage-exceptions.md
  skills/
    nginx-hardening/
      SKILL.md
      INVARIANTS.md
      EXECUTION-POLICY.md
      FAILURE-POLICY.md
      COMPATIBILITY-CHECKS.md
      EXCEPTIONS-SCHEMA.md
      LEARNINGS-SCHEMA.md
      RECIPES-SCHEMA.md
      FINDINGS-SCHEMA.md
      SANITIZED-EVENTS-SCHEMA.md
      RULE-CLASSES.md
      PROFILES.md
  agents/
    log-parser.md
    config-auditor.md
    deployment-planner.md
  scripts/
    sanitizer.py
    invariant-checker.py
    schema-validator.py
    compatibility-checker.py
    blast-radius.py
    rule-lifecycle.py
    backup-manager.py
    rollback-manager.py
    deploy-planner.py
    canary-deployer.py
  tests/
    fixtures/
      logs/
      configs/
      iocs/
      exceptions/
    golden/
      sanitized-events/
      findings/
      proposed-rules/
      invariant-results/
  learnings/
    LEARNINGS.md
    CHANGELOG.md
    attack-patterns/
    scanner-signatures/
    exceptions/
    infrastructure/
    recipes/
    ioc-responses/
  outputs/
    .gitkeep
  README.md
  LICENSE
```

---

## 7. Command Surface

### 7.1 Main Entry: `/harden-nginx`

* Natural-language routing
* Explicit subcommand routing
* Interactive menu on bare invocation
* Recipe execution
* Escalation only after action summary

### 7.2 Core Commands

| Command | Purpose |
|---------|---------|
| `/harden-nginx audit` | Static nginx config audit + optional live verification |
| `/harden-nginx analyze-logs` | Parse logs, sanitize events, identify patterns, propose rules |
| `/harden-nginx ioc <source>` | Parse IoCs, cross-reference logs, propose containment |
| `/harden-nginx deploy` | Apply accepted staged changes locally or remotely |
| `/harden-nginx rollback` | Restore a prior deployment state |
| `/harden-nginx recipe ...` | Create, run, edit, list, install, export recipes |
| `/harden-nginx exceptions ...` | Create, review, expire, validate exceptions |

---

## 8. Analysis Levels

### Level 1 — Static Config Analysis (always on)

Headers, TLS floor, cipher/protocol posture, unsafe directives, include hierarchy, duplicate/shadowed directives, location precedence risks, dangerous wildcarding, logging coverage, rate limiting posture, proxy/header propagation basics.

### Level 2 — Log Analysis (on if logs present)

Scanners, brute-force patterns, exploit paths, suspicious methods, abnormal status distributions, IoC hits, rate anomalies, recurring malicious UAs, benign crawler false-positive suppression.

### Level 3 — Live Verification (off by default, opt-in)

Header verification, TLS/protocol verification, response code checks, deny behavior verification, health endpoint verification.

**Forbidden by default:** Intrusive fuzzing, brute-force testing, content mutation attacks, high-rate probing.

---

## 9. Security Pipeline

### Layer 1 — `log-parser` agent

Read-only. Parses supplied log sources. Hex-encodes attacker-controlled fields. Emits structured raw parse objects only. Never proposes actions.

**Allowed tools:** `Bash(grep:*), Bash(zcat:*), Bash(wc:*), Bash(sort:*), Bash(uniq:*), Bash(head:*), Bash(tail:*)`

### Layer 2 — `sanitizer.py`

Deterministic, no LLM. Decodes/normalizes safe fields. Strips attacker-controlled payloads. Maps raw events to typed schema. Classifies path/method/status into normalized buckets. Attaches confidence and provenance. Emits `sanitized-findings.json`.

### Layer 3 — `config-auditor` agent

Consumes only typed sanitized schema and config summaries. Proposes rules, findings, and mitigations. Cannot write active config. Cannot inspect raw logs. Cannot generate shell commands using attacker-derived strings.

### Layer 4 — Decision gate and action planner

Presents findings and diffs. Groups by risk and scope. Requires accept/reject per finding or per batch. Produces deployment plan. Binds findings to rule IDs and exception deltas.

### Layer 5 — Deterministic enforcement

Runs: invariant checker, schema validator, compatibility checker, blast-radius analysis, `nginx -t`, backup manager, deploy/rollback machinery.

---

## 10. Typed Schema Boundary

### 10.1 Sanitized Event Schema

Layer 2 must emit a versioned schema only. No free-form raw payload content may cross into Layer 3.

**Required fields:** `schema_version`, `event_id`, `source_type`, `log_source_path`, `timestamp_bucket`, `remote_addr_class`, `method_class`, `path_class`, `status_bucket`, `user_agent_family`, `rate_signal`, `scanner_family`, `indicator_match_type`, `candidate_mitigation_type`, `confidence`, `provenance`, `ttl_recommendation`, `safe_notes`.

**Forbidden fields:** Raw request body, raw full URL if attacker-controlled, arbitrary query strings, unsanitized headers, shell fragments, raw user-agent strings unless normalized/allowlisted.

### 10.2 Finding Schema

Every finding must include: `finding_id`, `category`, `severity`, `confidence`, `source_layers`, `scope`, `blast_radius`, `recommended_action`, `rule_class`, `requires_live_test`, `exception_eligible`, `linked_artifacts`.

---

## 11. Rule Classes

| Class | Examples | Emergency Eligible | Auto-Generate |
|-------|----------|--------------------|---------------|
| **A — Containment** | IP/CIDR block, deny malicious path class, rate limit scanner, block bad UA | Yes (if narrow) | Yes |
| **B — Request Handling** | Method restrictions, exact-path deny, hardened location rules | No (default) | Yes |
| **C — Baseline Hardening** | Headers, TLS/protocol, timeouts, logging | No | Yes |
| **D — Behavioral/Routing** | Upstream routing, auth flow, broad rewrites | No | Recommendation only |

---

## 12. Environment Profiles

| Profile | Description |
|---------|-------------|
| `edge-public` | Internet-facing reverse proxy with public attack exposure |
| `internal-only` | Private/internal deployment with lower hostile traffic |
| `api-gateway` | Strict method handling, header correctness, rate protections |
| `static-site` | Aggressive header/TLS posture, minimal dynamic paths |
| `reverse-proxy-app` | Compatibility-sensitive for app-backed services |
| `high-risk-lockdown` | Favor containment, stricter defaults, lower false-negative tolerance |

Each profile defines: allowed rule classes, required compatibility checks, live test expectations, recommended recipes, emergency containment limits, default staging paths.

---

## 13. Compatibility Checks

Before any deploy, deterministic checks must run for: ACME/Let's Encrypt challenge paths, health/readiness endpoints, reverse proxy headers, websocket upgrade handling, admin/internal paths, include graph integrity, duplicate/shadowed directives, header inheritance conflicts, location precedence conflicts, proxy pass interactions, existing deny/allow interactions, profile-specific rules.

**Failure behavior:** Block deploy for critical failures. Downgrade to recommendation-only for medium. Emit explicit remediation guidance.

---

## 14. Blast Radius Model

Every proposed change gets a blast-radius label:

| Scope | Description |
|-------|-------------|
| `exact-location` | Single location block |
| `server-block` | One virtual host |
| `include-file` | Shared snippet |
| `vhost-group` | Multiple related vhosts |
| `global-http` | http-level directive |
| `unknown-shared` | Cannot determine scope |

Rules: Prefer smallest valid scope. Global scope requires elevated warning. Shared include modifications require explicit acknowledgment. UI sorts by blast radius before deployment.

---

## 15. Dry-Run Artifact Contract

Every run produces artifacts under `outputs/<run-id>/`:

* `run-summary.md`
* `sanitized-findings.json`
* `findings.json`
* `audit-report.md`
* `proposed-rules/`
* `deployment-plan.md`
* `exceptions-delta.md`
* `learnings-delta.md`
* `compatibility-report.md`
* `blast-radius-report.json`

Deploy commands consume these artifacts instead of re-deriving state.

---

## 16. IoC / Threat Intel

### 16.1 Supported Sources

**Local:** `.yar`, plain text lists, STIX JSON, manual entry.

**Built-in feeds (10):** AlienVault OTX, URLhaus, ThreatFox, CISA KEV, Emerging Threats, PhishTank, Blocklist.de, Feodo Tracker, OpenPhish, NVD/CVE API.

**User-defined:** Custom HTTP endpoints, auth via env vars only, configurable polling and normalization.

### 16.2 IoC Response Modes

| Mode | Behavior |
|------|----------|
| **Advisory** | Cross-reference only, no rule generation |
| **Stage** | Generate candidate rules + severity assessment |
| **Emergency Containment** | Class A controls only, narrow scope, TTL assigned, invariants enforced |

Emergency mode must not: modify TLS, alter headers, change routing, change location precedence, write broad regex rules.

---

## 17. Recipes

### 17.1 Required Metadata

`name`, `description`, `profile`, `execution_class`, `requires_network`, `requires_remote_exec`, `required_env_vars`, `confirmation_checkpoints`, `allows_emergency_mode`, `max_privilege_level`, `steps`, `outputs`, `schedule_mode`.

### 17.2 Scheduling Targets

* Local cron/systemd
* Remote install over SSH (key or sshpass via env vars)
* Generate-only

### 17.3 Safety Rules

* First execution always shows privilege summary
* Recipes cannot suppress invariants
* Recipes cannot embed secrets
* Write-capable recipes require confirmation unless explicitly marked non-interactive

---

## 18. Exception System

### 18.1 Required Fields

`exception_id`, `finding_id`, `reason`, `compensating_control`, `severity_tier`, `owner`, `scope`, `linked_config_path`, `approval_reference`, `created_at`, `last_reviewed_at`, `review_by`.

### 18.2 Scope Values

`exact-directive`, `location`, `server-block`, `include-file`, `hostname`, `global`.

### 18.3 Persistence

Exception file is source of truth. Inline config comment is trace marker only.

### 18.4 Expiry and Escalation

| Tier | Warn Schedule | On Expiry |
|------|---------------|-----------|
| Critical | 90, 60, 30 days | Blocks deploy |
| High | 60, 30 days | Prominent warning |
| Low | 30 days | Flagged |

Max lifetime: 365 days. Can be renewed with documented justification. Cannot override invariants 1–11.

---

## 19. Learnings System

* Structured markdown with frontmatter
* Status lifecycle: `draft` -> `active` -> `promoted`
* No attacker-controlled raw strings, secrets, or shell fragments
* Every entry linked to run ID and finding IDs
* Compact index above 150 lines; preserve counts, first-seen dates, promoted references
* `CHANGELOG.md` is append-only

---

## 20. Finding IDs and Traceability

Every finding gets a stable ID (e.g., `NH-AUDIT-HEADERS-0004`, `NH-LOG-SCANNER-0018`, `NH-IOC-CVE-0007`).

Each ID appears in: findings, proposed rules, exception records, learnings, changelog entries, deployment summaries, rollback metadata.

---

## 21. Rollback

First-class feature.

| Command | Behavior |
|---------|----------|
| `/harden-nginx rollback latest` | Restore most recent backup |
| `/harden-nginx rollback <backup-id>` | Restore specific version |
| `/harden-nginx rollback --preview` | Show what would change |

Restores: nginx config files, generated snippets, deployment metadata, linked artifact references. Optional: create revert commit if git-managed. No destructive git operations.

---

## 22. Canary Deployment

Remote deploy supports phased rollout:

1. Validate locally
2. Sync without reload
3. Reload canary host
4. Verify canary checks (`nginx -t`, reload success, health endpoint, key deny/header behavior)
5. Fan out to remaining hosts
6. Summarize outcome per host

---

## 23. Secrets Policy

* Environment variables only
* Never prompt user to paste secrets into chat
* Never write secrets to reports, learnings, recipes, changelog, commits, or staged outputs
* Redact secrets from logs and diffs
* Fail closed if required secrets are absent
* Remote credentials only from env vars or host-resident config

Recommended env naming: `NH_SSH_HOST`, `NH_SSH_USER`, `NH_SSH_KEY`, `NH_GIT_REMOTE`, `NH_OTX_TOKEN`, etc.

---

## 24. Machine-Readable Outputs

Every command supports `--json`. Outputs: findings JSON, rules JSON, deploy result JSON, rollback result JSON, recipe JSON, exceptions JSON, learning deltas JSON. CI-friendly and composable.

---

## 25. Failure Policy

| Failure | Behavior |
|---------|----------|
| Feed unavailable | Continue without enrichment, mark partial |
| Sanitizer failure | Stop log-derived rule generation, no deploy |
| Schema validation failure | Stop promotion/deploy, emit exact error |
| Invariant failure | Block enforcement, recommendation only |
| Compatibility failure | Block deploy for critical, stage only otherwise |
| `nginx -t` failure | No reload, restore backup |
| Reload failure | Immediate rollback attempt, mark run failed |
| Partial remote failure | Stop fanout, per-host results, offer rollback |

---

## 26. Invariants (18 total)

1. Additive-only for blocking rules
2. No regex negation in generated rules
3. Security headers are immutable
4. TLS floor at 1.2
5. Raw log data never enters LLM context
6. No attacker-controlled strings in shell commands
7. No attacker-controlled strings in commit messages
8. No attacker-controlled strings in learning content
9. `nginx -t` before every reload
10. Backup before every write
11. No destructive git operations
12. Exceptions require reason + compensating control
13. Exceptions cannot override invariants 1–11
14. Exceptions expire (max 365 days), tiered nag escalation
15. Changelog is append-only
16. Compaction preserves counts and first-seen dates
17. **Generated changes must be scoped as narrowly as possible**
18. **Secrets must never enter chat context, learnings, changelog, recipes, commit messages, or generated artifacts except redacted placeholders**

---

## 27. Finding Families

The 35 attack categories from `security-hardening.conf` map to broader finding families:

| Family | Categories |
|--------|------------|
| Transport security | TLS floor, cipher posture, protocol versions |
| Headers | Security headers, CORS, CSP |
| Request filtering | Method restriction, body limits, script extensions |
| Path exposure | Dotfiles, config files, source maps, package files, app settings, WEB-INF, SSH keys |
| Scanner detection | Known UAs, truncated UAs, ancient browsers, HTTP libraries, headless browsers |
| Brute-force detection | Login page discovery, rate anomalies |
| Enumeration behavior | WordPress, Swagger, GraphQL, Actuator, admin panels |
| IoC matches | JNDI/Log4Shell, Struts, CVE probes, phishing kits |
| Device exploitation | HNAP, IoT/OEM, VPN gateways, network infra, enterprise apps |
| Proxy safety | Proxy header propagation, websocket upgrade |
| Logging gaps | Missing access/error logs, log format coverage |
| Rate control | Missing rate limiting, burst configuration |
| Include hierarchy | Shadowed directives, precedence conflicts |
| Location precedence | Overlapping locations, regex/prefix conflicts |
| Stale control cleanup | Redundant rules, orphaned blocks |
| Exception hygiene | Expired exceptions, missing compensating controls |

Exact mappings defined in `FINDINGS-SCHEMA.md`.

---

## 28. Implementation Phases

### Phase 1 — Foundation

* Execution policy matrix
* Typed sanitized event schema
* Dry-run artifact contract
* Rule classes
* Failure policy
* Core commands (audit, analyze-logs)
* Security pipeline (all 5 layers)
* Invariant checker

### Phase 2 — Operational Depth

* Compatibility checker
* Blast-radius scoring
* Rollback manager
* Finding IDs and traceability
* Machine-readable outputs
* Exception system
* Learnings system

### Phase 3 — Advanced Operations

* Canary deploy
* Rule aging/decay
* Environment profiles
* Recipe system with scheduling
* IoC / threat intel integration
* Remote deployment (SSH/sshpass)
* Recipe privilege summaries
* Expanded exception ownership
