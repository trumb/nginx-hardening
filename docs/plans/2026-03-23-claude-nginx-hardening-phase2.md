# `claude-nginx-hardening` Phase 2 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add operational depth — compatibility checking, blast-radius scoring, rollback, finding traceability, machine-readable outputs, exception management command, and learnings management command.

**Architecture:** Builds on Phase 1 foundation. Adds 4 new Python scripts, 1 new agent, 2 new commands, and enhances existing commands with --json support.

**Tech Stack:** Python 3.10+ (stdlib only), Bash, existing plugin infrastructure from Phase 1.

---

## Task 1: Write compatibility-checker.py

**Files:**
- Create: `scripts/compatibility-checker.py`
- Create: `tests/fixtures/configs/app-with-websockets.conf`
- Create: `tests/fixtures/configs/app-with-acme.conf`

Deterministic Python script (stdlib only) that checks proposed nginx config changes for compatibility issues before deployment.

Checks:
- ACME/Let's Encrypt challenge paths (`/.well-known/acme-challenge/`) not blocked
- Health/readiness endpoints (`/health`, `/ready`, `/healthz`, `/status`) not blocked by new rules
- Reverse proxy headers (`proxy_set_header`, `X-Real-IP`, `X-Forwarded-For`) present when `proxy_pass` is used
- WebSocket upgrade handling (`proxy_set_header Upgrade`, `Connection "upgrade"`) present when websocket routes exist
- Include graph integrity — all `include` targets exist
- Duplicate directives that would cause unexpected behavior
- Header inheritance conflicts (add_header in server block vs location block)
- Location precedence — new locations don't shadow existing ones (exact > prefix > regex order)
- Existing deny/allow interactions — new rules don't conflict with explicit allows

CLI: `python3 scripts/compatibility-checker.py --config PATH [--proposed-rules DIR] [--profile PROFILE]`

Output JSON:
```json
{
  "compatible": true,
  "checks": {
    "acme_paths": {"status": "pass", "details": "..."},
    "health_endpoints": {"status": "pass"},
    "proxy_headers": {"status": "pass"},
    "websocket_upgrade": {"status": "warn", "details": "..."},
    "include_integrity": {"status": "pass"},
    "duplicate_directives": {"status": "pass"},
    "header_inheritance": {"status": "pass"},
    "location_precedence": {"status": "pass"},
    "deny_allow_conflicts": {"status": "pass"}
  },
  "critical_failures": [],
  "warnings": []
}
```

Exit 0 = compatible, exit 1 = critical failure, exit 2 = warnings only.

Commit after implementation and tests pass.

---

## Task 2: Write blast-radius.py

**Files:**
- Create: `scripts/blast-radius.py`

Deterministic Python script that analyzes proposed nginx config changes and labels each with a blast-radius scope.

Accepts: proposed rule file(s) + current nginx config.

For each proposed change, determines:
- `exact-location` — affects only one location block
- `server-block` — affects one virtual host
- `include-file` — affects a shared snippet (all includers impacted)
- `vhost-group` — affects multiple related vhosts
- `global-http` — http-level directive
- `unknown-shared` — cannot determine scope

Logic:
- If the change is a new `location` block in a site-specific config → `exact-location`
- If the change modifies `security-hardening.conf` (an include) → `include-file`
- If the change is a `server`-level directive → `server-block`
- If the change is in the `http` block or `nginx.conf` → `global-http`
- Count how many server blocks include the modified file to determine blast radius

Output JSON:
```json
{
  "changes": [
    {
      "file": "/etc/nginx/snippets/security-hardening.conf",
      "change_type": "add_location_block",
      "blast_radius": "include-file",
      "affected_server_blocks": 5,
      "details": "Shared snippet included by 5 server blocks"
    }
  ],
  "max_blast_radius": "include-file",
  "requires_elevated_warning": true
}
```

Commit after tests pass.

---

## Task 3: Write rollback-manager.py

**Files:**
- Create: `scripts/rollback-manager.py`

Manages backup creation, listing, and restoration for nginx configs.

Subcommands:
- `backup` — Create timestamped backup: `python3 scripts/rollback-manager.py backup --file PATH`
- `list` — List available backups: `python3 scripts/rollback-manager.py list --file PATH`
- `restore` — Restore from backup: `python3 scripts/rollback-manager.py restore --file PATH --backup-id ID`
- `preview` — Show diff between current and backup: `python3 scripts/rollback-manager.py preview --file PATH --backup-id ID`

Backup naming: `{filename}.bak.{YYYYMMDD-HHMMSS}`
Backup metadata: stored as JSON sidecar `{filename}.bak.{timestamp}.meta.json` with run_id, finding_ids, timestamp, user.

List output includes: backup ID, timestamp, size, run_id reference.

Commit after tests pass.

---

## Task 4: Write rule-lifecycle.py

**Files:**
- Create: `scripts/rule-lifecycle.py`

Manages finding ID generation and traceability across the system.

Functions:
- `generate-id` — Generate next finding ID: `python3 scripts/rule-lifecycle.py generate-id --source AUDIT --category HEADERS`
  Output: `NH-AUDIT-HEADERS-0001` (auto-incrementing, reads existing findings to avoid collisions)
- `trace` — Find all references to a finding ID across the codebase:
  `python3 scripts/rule-lifecycle.py trace --id NH-AUDIT-HEADERS-0001`
  Searches: findings, proposed rules, exceptions, learnings, changelog, deployment summaries
- `status` — Show lifecycle status of a finding:
  `python3 scripts/rule-lifecycle.py status --id NH-AUDIT-HEADERS-0001`
  Output: discovered → staged → deployed → promoted (with dates)

Commit after tests pass.

---

## Task 5: Write deployment-planner agent

**Files:**
- Create: `agents/deployment-planner.md`

New agent that creates structured deployment plans from accepted findings.

Responsibilities:
- Takes accepted findings + proposed rules from outputs/<run-id>/
- Runs compatibility-checker.py against the target config
- Runs blast-radius.py to score each change
- Groups changes by blast radius (narrow first)
- Generates deployment-plan.md with ordered steps
- Generates deployment-plan.json for machine consumption
- Flags any changes requiring elevated warnings

Cannot: write configs, run nginx commands, run git.

Commit.

---

## Task 6: Write /rollback-nginx command

**Files:**
- Create: `commands/rollback-nginx.md`

New command for restoring previous deployment state.

Subcommands:
- `/harden-nginx rollback` or `/rollback-nginx` — Interactive, shows recent backups
- `/harden-nginx rollback latest` — Restore most recent backup
- `/harden-nginx rollback <backup-id>` — Restore specific backup
- `/harden-nginx rollback --preview` — Show what would change without applying

Default: R0 + R1 (preview). With `--apply`: W1. With `--remote`: W1 + X1.

Workflow:
1. List available backups via rollback-manager.py
2. Show diff (preview mode)
3. On apply: restore config, run nginx -t, reload
4. Optionally create revert git commit (no force push)
5. Update CHANGELOG.md

Commit.

---

## Task 7: Write /manage-exceptions command

**Files:**
- Create: `commands/manage-exceptions.md`

Command for full exception lifecycle management.

Subcommands:
- `list` — Show all exceptions with status (active, expiring soon, expired)
- `create` — Interactive exception creation (prompts for all required fields)
- `review <exception-id>` — Show details, prompt for renewal or removal
- `renew <exception-id>` — Extend review_by date (new reason required)
- `expire` — List and handle all expired exceptions
- `validate` — Run schema-validator.py on all exception files

For `create`, interactive flow:
1. Select finding to except (from recent findings)
2. Enter reason (required)
3. Enter compensating control (required)
4. Select severity tier (auto-suggested based on finding)
5. Enter owner
6. Enter approval reference
7. Set review_by date (suggest 90/180/365 days)
8. Validate via schema-validator.py
9. Write exception file + inline config comment

Tiered nag display:
- Critical approaching: red warning with days remaining
- High approaching: yellow warning
- Expired: blocked indicator for critical, warning for others

Commit.

---

## Task 8: Enhance all commands with --json support

**Files:**
- Modify: `commands/harden-nginx.md`
- Modify: `commands/audit-nginx.md`
- Modify: `commands/analyze-nginx-logs.md`
- Modify: `commands/deploy-nginx.md`

Add `--json` flag documentation to each command. When --json is specified:
- Suppress human-readable output
- Output structured JSON to stdout
- Include: findings, rules, deploy results, rollback results, exceptions, learning deltas
- Machine-parseable for CI/CD integration
- Each command documents its JSON output schema

Commit.

---

## Task 9: Write COMPATIBILITY-CHECKS.md skill document

**Files:**
- Create: `skills/nginx-hardening/COMPATIBILITY-CHECKS.md`

Reference document listing all compatibility checks, when they run, what they catch, and failure behavior. Loaded by the deployment-planner agent.

Commit.

---

## Task 10: Update existing commands to use new scripts

**Files:**
- Modify: `commands/deploy-nginx.md` — Add compatibility-checker.py and blast-radius.py steps before deployment
- Modify: `commands/harden-nginx.md` — Reference rollback, exceptions, and new scripts in full lifecycle

The deploy command now runs:
1. invariant-checker.py
2. compatibility-checker.py
3. blast-radius.py
4. schema-validator.py
Then proceeds with backup (rollback-manager.py), write, test, reload.

The main command now routes `rollback` and `exceptions` subcommands to their respective commands.

Commit.

---

## Task 11: Write learnings management features

**Files:**
- Modify: `commands/harden-nginx.md` — Add learnings subcommand routing

Add learnings management to the main command:
- `list` — Show all learnings grouped by type and status
- `promote <learning-id>` — Change status from active to promoted
- `compact` — Run compaction if LEARNINGS.md exceeds 150 lines
- `export` — Export learnings as JSON for sharing

Compaction logic:
- Merge related attack patterns (same path_class) into single entries
- Sum hit counts, keep earliest discovered date
- Archive drafts older than 30 days that were never promoted
- Preserve all promoted references
- Append compaction record to CHANGELOG.md

Commit.

---

## Task 12: Update README and wiki for Phase 2

**Files:**
- Modify: `README.md` — Update roadmap, add new commands, mark Phase 2 features as done
- Update wiki pages: Commands.md, Failure-Modes.md (add compatibility/blast-radius), Exceptions.md (add command examples)

Commit and push.

---

## Task 13: Integration test for Phase 2

Run full integration test:
1. All new scripts pass their tests
2. New commands load correctly
3. Compatibility checker catches ACME/health conflicts
4. Blast radius correctly labels include-file vs exact-location
5. Rollback manager can create, list, preview, and restore backups
6. Exception creation + validation flow works
7. --json output is valid JSON from all commands
8. Finding ID generation is collision-free

Final commit and push.
