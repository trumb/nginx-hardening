#!/usr/bin/env python3
"""
nginx-autoharden: Automated honeypot log analysis and rule generation.

Parses nginx honeypot logs, detects new attack patterns, generates blocking
rules, updates the live nginx config, and pushes to the public repo.

Usage:
    python3 autoharden.py              # Full run: analyze, update, reload, push
    python3 autoharden.py --dry-run    # Preview changes without applying

Schedule management (mutually exclusive — only one can be active):
    python3 autoharden.py --enable-timer        # Enable systemd timer (15min)
    python3 autoharden.py --disable-timer       # Disable systemd timer
    python3 autoharden.py --enable-cron [MIN]   # Enable cron job (default: 15min)
    python3 autoharden.py --disable-cron        # Disable cron job
    python3 autoharden.py --status              # Show which scheduler is active

Release management:
    python3 autoharden.py --release             # Create GitHub draft release
    python3 autoharden.py --release --publish   # Create and publish release
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "config.json"
VERSION_PATH = SCRIPT_DIR / "VERSION"
CRON_MARKER = "# nginx-autoharden"
TIMER_UNIT = "nginx-autoharden.timer"
SERVICE_UNIT = "nginx-autoharden.service"

LOG_RE = re.compile(
    r'(?P<remote_addr>\S+) - (?P<cf_ip>\S+) '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d+) (?P<bytes>\d+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<ua>[^"]*)" '
    r'(?P<req_time>\S+)'
)

BROWSER_RE = re.compile(
    r'(KHTML, like Gecko\) Chrome/(8[0-9]|9[0-9]|1[0-9]{2})\.|'
    r'Firefox/(1[0-9]{2}|[89][0-9])\.|'
    r'Safari/[56][0-9]{2}\.|'
    r'Edg/(8[0-9]|9[0-9]|1[0-9]{2})\.)',
    re.IGNORECASE
)

ATTACK_MARKERS = [
    '.env', '.git', '.svn', '.htaccess', '.htpasswd', '.DS_Store',
    'admin', 'config', 'setup', 'debug', 'backup', 'dump', 'sql',
    'phpmyadmin', 'wp-admin', 'wp-login', 'actuator', 'swagger',
    'graphql', 'telescope', '_profiler', '_ignition', 'shell',
    'console', 'cgi-bin', '.php', '.asp', '.jsp',
]


# =============================================================================
# Version management
# =============================================================================

def get_version():
    if VERSION_PATH.exists():
        return VERSION_PATH.read_text().strip()
    return "0.0.0"


def bump_version(part='patch'):
    """Bump version. part: 'major', 'minor', or 'patch'."""
    ver = get_version()
    major, minor, patch = (int(x) for x in ver.split('.'))
    if part == 'major':
        major += 1; minor = 0; patch = 0
    elif part == 'minor':
        minor += 1; patch = 0
    else:
        patch += 1
    new_ver = f'{major}.{minor}.{patch}'
    VERSION_PATH.write_text(new_ver + '\n')
    return new_ver


def sync_version_to_repo(repo_path):
    """Copy VERSION file to repo."""
    repo = Path(repo_path)
    if repo.exists():
        shutil.copy2(str(VERSION_PATH), str(repo / 'VERSION'))


# =============================================================================
# Release management (GitHub draft releases for email sign-off)
# =============================================================================

def get_changelog_since_last_release(repo_path):
    """Get commit messages since the last tag."""
    result = subprocess.run(
        ['git', 'describe', '--tags', '--abbrev=0'],
        cwd=repo_path, capture_output=True, text=True
    )
    if result.returncode == 0:
        last_tag = result.stdout.strip()
        result = subprocess.run(
            ['git', 'log', f'{last_tag}..HEAD', '--oneline'],
            cwd=repo_path, capture_output=True, text=True
        )
        return result.stdout.strip()
    else:
        result = subprocess.run(
            ['git', 'log', '--oneline'],
            cwd=repo_path, capture_output=True, text=True
        )
        return result.stdout.strip()


def count_blocking_rules(conf_path):
    """Count total blocking categories and individual rules."""
    categories = 0
    rules = 0
    with open(conf_path) as f:
        for line in f:
            if re.match(r'\s*#\s*---\s*\d+\.', line):
                categories += 1
            if re.match(r'\s*location\s+~', line):
                rules += 1
            if re.match(r'\s*if\s+\(\$args', line):
                rules += 1
    return categories, rules


def count_ua_tools(site_conf_path):
    """Count scanner UA tools in the blocklist."""
    with open(site_conf_path) as f:
        content = f.read()
    m = re.search(r'http_user_agent\s+~\*\s+\(([^)]+)\)', content)
    if m:
        return len(m.group(1).split('|'))
    return 0


def generate_release_notes(config, version, changelog=None):
    """Generate release notes for a GitHub release."""
    conf_path = config['hardening_conf']
    site_conf = config['claw_site_conf']

    categories, rules = count_blocking_rules(conf_path)
    ua_count = count_ua_tools(site_conf)

    # Parse the hardening conf to extract category names
    category_list = []
    with open(conf_path) as f:
        for line in f:
            m = re.match(r'\s*#\s*---\s*(\d+)\.\s*(.+?)\s*---', line)
            if m:
                category_list.append(f'{m.group(1)}. {m.group(2)}')

    notes = f"""## nginx-hardening v{version}

### Blocking Summary

- **{categories} attack categories** blocked
- **{rules} individual blocking rules**
- **{ua_count} scanner User-Agent signatures** detected and dropped

### Attack Categories

"""
    for cat in category_list:
        notes += f"- {cat}\n"

    notes += f"""
### Scanner UA Blocking

Drops connections (nginx 444) from {ua_count} known scanner tools including:
nuclei, zgrab, masscan, censys, shodan, nmap, nikto, sqlmap, and more.

Also detects:
- Truncated Chrome UA (missing KHTML suffix)
- Bare "Mozilla/5.0" with no engine details
- Ancient Chrome versions (pre-2020)
- Empty User-Agent

### Security Headers

Every response includes: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection,
Referrer-Policy, Strict-Transport-Security, Permissions-Policy.
"""

    if changelog:
        notes += f"\n### Changes Since Last Release\n\n{changelog}\n"

    notes += "\n---\nGenerated by [autoharden.py](https://github.com/trumb/nginx-hardening)\n"
    return notes


def create_release(config, publish=False):
    """Create a GitHub release (draft by default for sign-off)."""
    repo_path = config['repo_path']
    version = get_version()

    # Sync version to repo
    sync_version_to_repo(repo_path)

    # Stage, commit, push version update if needed
    result = subprocess.run(
        ['git', 'diff', '--quiet', 'VERSION'],
        cwd=repo_path, capture_output=True
    )
    if result.returncode != 0:
        subprocess.run(['git', 'add', 'VERSION'], cwd=repo_path, capture_output=True)
        subprocess.run(
            ['git', 'commit', '-m', f'Release v{version}'],
            cwd=repo_path, capture_output=True
        )
        subprocess.run(['git', 'push'], cwd=repo_path, capture_output=True)

    # Get changelog
    changelog = get_changelog_since_last_release(repo_path)

    # Generate release notes
    notes = generate_release_notes(config, version, changelog)

    # Create release via gh CLI
    tag = f'v{version}'
    cmd = [
        'gh', 'release', 'create', tag,
        '--title', f'nginx-hardening {tag}',
        '--notes', notes,
        '--repo', 'trumb/nginx-hardening',
    ]
    if not publish:
        cmd.append('--draft')

    result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True)
    if result.returncode == 0:
        url = result.stdout.strip()
        status = "published" if publish else "draft (review and publish for sign-off)"
        print(f"Release {tag} created: {status}")
        print(f"URL: {url}")
        if not publish:
            print("\nGitHub will email the repo owner about this draft release.")
            print("Review and publish at the URL above to sign off.")
    else:
        print(f"Release creation failed: {result.stderr}")
        # Tag might already exist
        if 'already exists' in result.stderr:
            print(f"Tag {tag} already exists. Bump version first:")
            print(f"  Edit /opt/nginx-hardening/VERSION and try again")

    return result.returncode == 0


# =============================================================================
# Schedule management (systemd timer vs cron — mutually exclusive)
# =============================================================================

def is_timer_active():
    r = subprocess.run(
        ['systemctl', 'is-enabled', TIMER_UNIT],
        capture_output=True, text=True
    )
    return r.stdout.strip() == 'enabled'


def is_cron_active():
    r = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
    return CRON_MARKER in r.stdout


def disable_timer():
    subprocess.run(['systemctl', 'stop', TIMER_UNIT], capture_output=True)
    subprocess.run(['systemctl', 'disable', TIMER_UNIT], capture_output=True)


def disable_cron():
    r = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
    if r.returncode != 0:
        return
    lines = [l for l in r.stdout.splitlines() if CRON_MARKER not in l]
    new_crontab = '\n'.join(lines) + '\n' if lines else ''
    subprocess.run(['crontab', '-'], input=new_crontab, capture_output=True, text=True)


def enable_timer():
    if is_cron_active():
        print("Disabling cron job first (only one scheduler can be active)...")
        disable_cron()
    subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
    subprocess.run(['systemctl', 'enable', '--now', TIMER_UNIT], capture_output=True)
    print(f"Systemd timer enabled. Runs daily.")
    print(f"Check status: systemctl status {TIMER_UNIT}")


def enable_cron(interval_min=15):
    if is_timer_active():
        print("Disabling systemd timer first (only one scheduler can be active)...")
        disable_timer()
    script = f"/usr/bin/python3 {SCRIPT_DIR / 'autoharden.py'}"
    cron_line = f"*/{interval_min} * * * * {script} {CRON_MARKER}"
    r = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
    existing = r.stdout if r.returncode == 0 else ''
    lines = [l for l in existing.splitlines() if CRON_MARKER not in l]
    lines.append(cron_line)
    new_crontab = '\n'.join(lines) + '\n'
    subprocess.run(['crontab', '-'], input=new_crontab, capture_output=True, text=True)
    print(f"Cron job enabled. Runs every {interval_min} minutes.")
    print(f"Check: crontab -l | grep autoharden")


def show_status():
    timer = is_timer_active()
    cron = is_cron_active()
    version = get_version()
    print(f"Version: {version}")
    if timer and cron:
        print("WARNING: Both systemd timer AND cron are active! Disable one.")
    elif timer:
        print(f"Scheduler: systemd timer ({TIMER_UNIT})")
        subprocess.run(['systemctl', 'status', TIMER_UNIT, '--no-pager', '-l'])
    elif cron:
        print("Scheduler: cron")
        r = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if CRON_MARKER in line:
                print(f"  {line}")
    else:
        print("Scheduler: none")
        print("  --enable-timer    (systemd, recommended)")
        print("  --enable-cron     (cron)")


def handle_schedule_args():
    if '--status' in sys.argv:
        show_status()
        return True
    if '--enable-timer' in sys.argv:
        enable_timer()
        return True
    if '--disable-timer' in sys.argv:
        disable_timer()
        print("Systemd timer disabled.")
        return True
    if '--enable-cron' in sys.argv:
        idx = sys.argv.index('--enable-cron')
        interval = 15
        if idx + 1 < len(sys.argv) and sys.argv[idx + 1].isdigit():
            interval = int(sys.argv[idx + 1])
        enable_cron(interval)
        return True
    if '--disable-cron' in sys.argv:
        disable_cron()
        print("Cron job disabled.")
        return True
    if '--release' in sys.argv:
        config = load_config()
        publish = '--publish' in sys.argv
        create_release(config, publish)
        return True
    return False


# =============================================================================
# Config and state
# =============================================================================

def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def load_state(state_path):
    if os.path.exists(state_path):
        with open(state_path) as f:
            return json.load(f)
    return {}


def save_state(state_path, state):
    with open(state_path, 'w') as f:
        json.dump(state, f, indent=2)


def setup_logging(log_file):
    logger = logging.getLogger('autoharden')
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(log_file)
    fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter('%(levelname)s %(message)s'))
    logger.addHandler(sh)
    return logger


# =============================================================================
# Log parsing
# =============================================================================

def parse_log_entries(log_file, offset=0):
    entries = []
    try:
        size = os.path.getsize(log_file)
    except OSError:
        return entries, 0
    if size < offset:
        offset = 0
    with open(log_file) as f:
        f.seek(offset)
        for line in f:
            m = LOG_RE.match(line.strip())
            if m:
                d = m.groupdict()
                parts = d['request'].split()
                if len(parts) >= 2:
                    d['method'] = parts[0]
                    d['path'] = parts[1].split('?')[0]
                    d['full_path'] = parts[1]
                else:
                    d['method'] = d['request']
                    d['path'] = '/'
                    d['full_path'] = '/'
                d['status'] = int(d['status'])
                entries.append(d)
        new_offset = f.tell()
    return entries, new_offset


# =============================================================================
# Rule extraction and detection
# =============================================================================

def extract_existing_path_rules(conf_path):
    blocked = set()
    with open(conf_path) as f:
        for line in f:
            m = re.match(r'\s*location\s+~\*?\s+(.+?)\s*\{', line)
            if m:
                blocked.add(m.group(1))
    return blocked


def extract_existing_ua_tools(conf_path):
    tools = set()
    with open(conf_path) as f:
        content = f.read()
    m = re.search(r'http_user_agent\s+~\*\s+\(([^)]+)\)', content)
    if m:
        tools = set(t.strip() for t in m.group(1).split('|'))
    return tools


def is_whitelisted_path(path, config):
    for wp in config['whitelisted_paths']:
        if path.startswith(wp):
            return True
    for route in config['honeypot_routes']:
        if path.startswith(route) or path == route.rstrip('/'):
            return True
    return False


def is_legitimate_ua(ua, config):
    if not ua or ua == '-':
        return False
    for pattern in config['whitelisted_ua_patterns']:
        if pattern.lower() in ua.lower():
            return True
    if BROWSER_RE.search(ua):
        return True
    return False


def has_attack_markers(path):
    path_lower = path.lower()
    return any(marker in path_lower for marker in ATTACK_MARKERS)


def extract_tool_name(ua):
    m = re.match(r'(\w[\w.-]+)/[\d.]', ua)
    if m and m.group(1).lower() not in ('mozilla', 'applewebkit', 'safari', 'chrome', 'firefox', 'edg', 'opera'):
        return m.group(1)
    m = re.search(r'compatible;\s+(\w[\w.-]+)/', ua)
    if m:
        return m.group(1)
    m = re.match(r'(\w[\w.-]+)\s+\(', ua)
    if m and m.group(1).lower() not in ('mozilla',):
        return m.group(1)
    return None


def detect_new_patterns(entries, config, existing_rules, existing_ua_tools):
    new_path_rules = []
    new_ua_tools = []
    leaking_paths = defaultdict(int)
    suspicious_uas = defaultdict(set)
    attack_paths = defaultdict(int)

    for entry in entries:
        path = entry['path']
        status = entry['status']
        ua = entry['ua']
        ip = entry.get('cf_ip', entry['remote_addr'])

        if status == 200 and not is_whitelisted_path(path, config):
            leaking_paths[path] += 1
        if status not in (403, 404, 444) and has_attack_markers(path):
            if not is_whitelisted_path(path, config):
                attack_paths[path] += 1
        if ua and ua != '-' and not is_legitimate_ua(ua, config):
            tool = extract_tool_name(ua)
            if tool and tool.lower() not in {t.lower() for t in existing_ua_tools}:
                suspicious_uas[tool].add(ip)

    for path, count in sorted(leaking_paths.items(), key=lambda x: -x[1]):
        if count >= config['min_occurrences']:
            rule = path_to_nginx_rule(path)
            if rule and not rule_exists(rule, existing_rules):
                new_path_rules.append({'path': path, 'rule': rule, 'count': count, 'reason': 'path_leaking_200'})

    for path, count in sorted(attack_paths.items(), key=lambda x: -x[1]):
        if count >= 1:
            rule = path_to_nginx_rule(path)
            if rule and not rule_exists(rule, existing_rules):
                new_path_rules.append({'path': path, 'rule': rule, 'count': count, 'reason': 'attack_marker'})

    for tool, ips in sorted(suspicious_uas.items(), key=lambda x: -len(x[1])):
        if len(ips) >= 2:
            new_ua_tools.append({'tool': tool, 'ip_count': len(ips), 'reason': 'new_scanner_ua'})

    max_rules = config['max_rules_per_run']
    return new_path_rules[:max_rules], new_ua_tools[:max_rules]


def path_to_nginx_rule(path):
    path = path.strip()
    if not path or path == '/':
        return None
    return re.escape(path)


def rule_exists(rule, existing_rules):
    rule_lower = rule.lower()
    for existing in existing_rules:
        existing_lower = existing.lower()
        if rule_lower in existing_lower or existing_lower in rule_lower:
            return True
    return False


# =============================================================================
# Rule application
# =============================================================================

def apply_path_rules(conf_path, new_rules, dry_run, logger):
    if not new_rules:
        return
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
    lines = [
        f'\n# --- Auto-generated rules ({timestamp}) ---',
        f'# Source: honeypot log analysis by autoharden.py',
    ]
    for r in new_rules:
        lines.append(f'# Observed: {r["path"]} ({r["count"]}x, {r["reason"]})')
        lines.append(f'location ~* ^{r["rule"]} {{')
        lines.append(f'    return 404;')
        lines.append(f'}}')
    block = '\n'.join(lines) + '\n'
    if dry_run:
        logger.info(f'[DRY RUN] Would append to {conf_path}:\n{block}')
        return
    shutil.copy2(conf_path, conf_path + '.bak')
    with open(conf_path, 'a') as f:
        f.write(block)
    logger.info(f'Appended {len(new_rules)} path rules to {conf_path}')


def apply_ua_rules(site_conf_path, new_tools, dry_run, logger):
    if not new_tools:
        return
    with open(site_conf_path) as f:
        content = f.read()
    m = re.search(r'(if\s+\(\$http_user_agent\s+~\*\s+\()([^)]+)(\)\))', content)
    if not m:
        logger.warning(f'Could not find UA regex in {site_conf_path}')
        return
    existing_tools = m.group(2)
    new_tool_names = '|'.join(t['tool'].lower() for t in new_tools)
    updated_tools = existing_tools + '|' + new_tool_names
    if dry_run:
        logger.info(f'[DRY RUN] Would add to UA blocklist: {new_tool_names}')
        return
    shutil.copy2(site_conf_path, site_conf_path + '.bak')
    new_content = content[:m.start(2)] + updated_tools + content[m.end(2):]
    with open(site_conf_path, 'w') as f:
        f.write(new_content)
    logger.info(f'Added {len(new_tools)} scanner UAs to {site_conf_path}')


# =============================================================================
# Nginx validation and rollback
# =============================================================================

def validate_and_reload(dry_run, logger):
    if dry_run:
        logger.info('[DRY RUN] Would run: nginx -t && systemctl reload nginx')
        return True
    result = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f'nginx -t FAILED: {result.stderr}')
        return False
    result = subprocess.run(['systemctl', 'reload', 'nginx'], capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f'nginx reload FAILED: {result.stderr}')
        return False
    logger.info('nginx config validated and reloaded')
    return True


def rollback(conf_path, site_conf_path, logger):
    for path in [conf_path, site_conf_path]:
        bak = path + '.bak'
        if os.path.exists(bak):
            shutil.copy2(bak, path)
            logger.info(f'Rolled back {path} from {bak}')
    subprocess.run(['systemctl', 'reload', 'nginx'], capture_output=True)


# =============================================================================
# Repo sync
# =============================================================================

def sync_repo(repo_path, conf_path, new_path_rules, new_ua_tools, dry_run, logger):
    if dry_run:
        logger.info('[DRY RUN] Would sync to repo and push')
        return
    repo = Path(repo_path)
    if not repo.exists():
        logger.warning(f'Repo not found at {repo_path}, skipping sync')
        return

    # Copy hardening snippet and version
    shutil.copy2(conf_path, repo / 'security-hardening.conf')
    sync_version_to_repo(repo_path)

    result = subprocess.run(['git', 'diff', '--quiet'], cwd=repo_path, capture_output=True)
    if result.returncode == 0:
        # Check untracked files too
        result2 = subprocess.run(
            ['git', 'ls-files', '--others', '--exclude-standard'],
            cwd=repo_path, capture_output=True, text=True
        )
        if not result2.stdout.strip():
            logger.info('No repo changes to commit')
            return

    # Build commit message with details
    details = []
    for r in new_path_rules:
        details.append(f'  - Block {r["path"]} ({r["reason"]})')
    for t in new_ua_tools:
        details.append(f'  - Block UA: {t["tool"]} ({t["ip_count"]} IPs)')
    detail_str = '\n'.join(details) if details else '  (no new rules)'

    version = get_version()
    msg = f'v{version}: auto-update blocking rules from honeypot analysis\n\n{detail_str}\n\nCo-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>'

    subprocess.run(['git', 'add', '-A'], cwd=repo_path, capture_output=True)
    subprocess.run(['git', 'commit', '-m', msg], cwd=repo_path, capture_output=True)
    result = subprocess.run(['git', 'push'], cwd=repo_path, capture_output=True, text=True)
    if result.returncode == 0:
        logger.info(f'Pushed v{version} to repo')
    else:
        logger.warning(f'Git push failed: {result.stderr}')


# =============================================================================
# Main
# =============================================================================

def main():
    if handle_schedule_args():
        return

    dry_run = '--dry-run' in sys.argv
    config = load_config()
    logger = setup_logging(config['log_file'])
    state = load_state(config['state_file'])

    if dry_run:
        logger.info('=== DRY RUN MODE ===')
    logger.info(f'=== autoharden run started at {datetime.now().isoformat()} ===')

    all_entries = []
    for log_file in config['log_files']:
        key = f'offset:{log_file}'
        offset = state.get(key, 0)
        entries, new_offset = parse_log_entries(log_file, offset)
        all_entries.extend(entries)
        state[key] = new_offset

    logger.info(f'Parsed {len(all_entries)} new log entries')

    if not all_entries:
        logger.info('No new entries, nothing to do')
        save_state(config['state_file'], state)
        return

    existing_rules = extract_existing_path_rules(config['hardening_conf'])
    existing_ua_tools = extract_existing_ua_tools(config['claw_site_conf'])
    logger.info(f'Existing: {len(existing_rules)} path rules, {len(existing_ua_tools)} UA tools')

    new_path_rules, new_ua_tools = detect_new_patterns(
        all_entries, config, existing_rules, existing_ua_tools
    )

    logger.info(f'Detected: {len(new_path_rules)} new path rules, {len(new_ua_tools)} new UA tools')

    if not new_path_rules and not new_ua_tools:
        logger.info('No new patterns detected')
        save_state(config['state_file'], state)
        return

    for r in new_path_rules:
        logger.info(f'  NEW PATH: {r["path"]} ({r["count"]}x, {r["reason"]})')
    for t in new_ua_tools:
        logger.info(f'  NEW UA: {t["tool"]} ({t["ip_count"]} IPs)')

    # Bump patch version for auto-updates
    new_version = bump_version('patch')
    logger.info(f'Version bumped to {new_version}')

    apply_path_rules(config['hardening_conf'], new_path_rules, dry_run, logger)
    apply_ua_rules(config['claw_site_conf'], new_ua_tools, dry_run, logger)

    if not dry_run:
        if not validate_and_reload(dry_run, logger):
            logger.error('Validation failed — rolling back!')
            rollback(config['hardening_conf'], config['claw_site_conf'], logger)
            return

    sync_repo(
        config['repo_path'], config['hardening_conf'],
        new_path_rules, new_ua_tools, dry_run, logger
    )

    save_state(config['state_file'], state)
    logger.info('=== autoharden run complete ===\n')


if __name__ == '__main__':
    main()
