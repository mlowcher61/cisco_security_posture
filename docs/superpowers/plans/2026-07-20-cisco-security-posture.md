# Cisco Security Posture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an Ansible Automation Platform solution that audits Cisco IOS/IOS-XE devices against a CIS-derived security posture baseline, renders a PASS/NON-COMPLIANT report plus HTML/CSV artifacts, and can opt-in remediate the findings it detects.

**Architecture:** A single `show running-config` fetch per device feeds a data-driven check engine. Every check is a list entry in `defaults/main.yml` (regex + type + optional remediation lines) evaluated against that captured text. The whole engine is testable without hardware by pointing it at fixture files with `ansible_connection=local`. Remediation is a filter over the audit results — it pushes only the config lines carried by checks that failed.

**Tech Stack:** Ansible Automation Platform 2.x, `cisco.ios`, `ansible.platform`, `ansible.controller`, Jinja2 (`regex_search`, `version`), `ansible-lint`, `yamllint`.

## Global Constraints

- Built for **Ansible Automation Platform**, not ansible-core. Playbooks are launched as AAP job templates.
- **Certified/validated collections only** — `cisco.ios`, `ansible.platform`, `ansible.controller`, `ansible.builtin`. No Galaxy community content.
- Prefer **`ansible.platform`** over `ansible.controller` where a module exists in both (organizations use `ansible.platform`).
- **No secrets in git.** Credentials are defined as objects only; secret values are set in the AAP UI.
- **Config-as-code** for all AAP objects, under `configure_aap/`.
- Platform scope: **Cisco IOS / IOS-XE only.**
- Every playbook must pass `ansible-lint` and `yamllint .` clean.
- All variables are namespaced `posture_*`; all check ids are unique kebab-case strings.
- Fixture-mode contract (used by every engine test): when `posture_fixture_file` is set to a path, the engine reads config text from that file instead of connecting to a device, and reads the IOS version from `posture_fixture_version` (default `"0.0"`).

---

## File Structure

| File | Responsibility |
|---|---|
| `ansible.cfg` | Collection + role paths, host key checking off for lab |
| `collections/requirements.yml` | The four certified collections |
| `.gitignore` | Ignore `reports/`, `*.retry`, collection download dir |
| `playbooks/audit_posture.yml` | Audit entry point — runs the audit role |
| `playbooks/remediate_posture.yml` | Remediation entry point — runs audit then remediate role |
| `roles/cisco_posture_audit/defaults/main.yml` | THE CHECK CATALOG + engine defaults |
| `roles/cisco_posture_audit/tasks/main.yml` | Orchestration: validate → gather → guard → checks → report |
| `roles/cisco_posture_audit/tasks/validate_catalog.yml` | Fail fast on a malformed catalog |
| `roles/cisco_posture_audit/tasks/gather.yml` | Fixture-mode branch + device fetch + rescue |
| `roles/cisco_posture_audit/tasks/checks.yml` | Evaluate the catalog into `posture_results` |
| `roles/cisco_posture_audit/tasks/report.yml` | Console report, summary, artifacts, gate |
| `roles/cisco_posture_audit/templates/posture_report.html.j2` | HTML artifact |
| `roles/cisco_posture_audit/templates/posture_report.csv.j2` | CSV artifact |
| `roles/cisco_posture_remediate/defaults/main.yml` | Remediation defaults |
| `roles/cisco_posture_remediate/tasks/main.yml` | Filter failed+remediable → push → verify |
| `tests/fixtures/compliant_running_config.txt` | Known-good device config |
| `tests/fixtures/noncompliant_running_config.txt` | Known-bad device config |
| `tests/test_catalog.yml` | Fixture harness runnable without hardware |
| `configure_aap/configure.yml` | Apply all AAP objects |
| `configure_aap/vars/*.yml` | Org, inventory, group, credential, job template definitions |
| `README.md` | Full solution documentation |

---

## Task 1: Repository scaffolding

**Files:**
- Create: `ansible.cfg`
- Create: `collections/requirements.yml`
- Create: `.gitignore`

**Interfaces:**
- Consumes: nothing
- Produces: `ansible.cfg` (roles path `roles`, collections path `collections`), `collections/requirements.yml` listing the four collections.

- [ ] **Step 1: Create `ansible.cfg`**

```ini
[defaults]
collections_path = ./collections
roles_path = ./roles
host_key_checking = False
stdout_callback = default
retry_files_enabled = False
interpreter_python = auto_silent

[persistent_connection]
command_timeout = 60
connect_timeout = 60
```

- [ ] **Step 2: Create `collections/requirements.yml`**

```yaml
---
collections:
  - name: cisco.ios
  - name: ansible.platform
  - name: ansible.controller
  - name: ansible.utils
```

- [ ] **Step 3: Create `.gitignore`**

```gitignore
reports/
*.retry
collections/ansible_collections/
__pycache__/
*.pyc
```

- [ ] **Step 4: Verify YAML lints clean**

Run: `yamllint collections/requirements.yml .gitignore ansible.cfg 2>/dev/null; yamllint collections/requirements.yml`
Expected: no errors reported for `collections/requirements.yml`.

- [ ] **Step 5: Commit**

```bash
git add ansible.cfg collections/requirements.yml .gitignore
git commit -m "chore: scaffold repo — ansible.cfg, collections, gitignore"
```

---

## Task 2: Test fixtures (minimal, for engine testing)

These are deliberately small at this stage — just enough config lines for the engine's four check types to be exercised in Task 4. They are expanded to full realism in Task 6.

**Files:**
- Create: `tests/fixtures/compliant_running_config.txt`
- Create: `tests/fixtures/noncompliant_running_config.txt`

**Interfaces:**
- Consumes: nothing
- Produces: two files. The compliant one contains `service password-encryption`, `ssh version 2`, `transport input ssh`, `version 17.9`, hostname line, and a terminating `end`. The noncompliant one omits `service password-encryption`, has `transport input telnet ssh`, `snmp-server community public RO`, `version 15.2`, hostname line, and `end`.

- [ ] **Step 1: Create `tests/fixtures/compliant_running_config.txt`**

```
version 17.9
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
!
hostname rtr-compliant
!
enable secret 9 $9$abcdef
!
aaa new-model
!
ip ssh version 2
no ip http server
no ip http secure-server
no service pad
no cdp run
!
snmp-server group ADMIN v3 priv
!
line con 0
 exec-timeout 5 0
line vty 0 15
 exec-timeout 5 0
 transport input ssh
!
ntp authenticate
ntp server 10.0.0.1 key 1
logging trap informational
logging host 10.0.0.2
!
end
```

- [ ] **Step 2: Create `tests/fixtures/noncompliant_running_config.txt`**

```
version 15.2
service timestamps debug datetime msec
!
hostname rtr-bad
!
enable password cisco123
!
ip http server
!
snmp-server community public RO
snmp-server community private RW
!
line con 0
line vty 0 15
 transport input telnet ssh
!
end
```

- [ ] **Step 3: Verify the fixtures differ as intended**

Run: `grep -c "service password-encryption" tests/fixtures/compliant_running_config.txt tests/fixtures/noncompliant_running_config.txt`
Expected: compliant reports `1`, noncompliant reports `0`.

- [ ] **Step 4: Commit**

```bash
git add tests/fixtures/
git commit -m "test: add minimal compliant and non-compliant IOS fixtures"
```

---

## Task 3: Audit role skeleton — orchestration, catalog validation, gather, guard

Delivers a runnable audit playbook that loads config text (from a fixture), validates the catalog structure, and refuses to proceed on truncated config. Uses a tiny 1-check catalog so the run is meaningful before the real catalog exists.

**Files:**
- Create: `roles/cisco_posture_audit/defaults/main.yml`
- Create: `roles/cisco_posture_audit/meta/main.yml`
- Create: `roles/cisco_posture_audit/tasks/main.yml`
- Create: `roles/cisco_posture_audit/tasks/validate_catalog.yml`
- Create: `roles/cisco_posture_audit/tasks/gather.yml`
- Create: `playbooks/audit_posture.yml`

**Interfaces:**
- Consumes: fixture-mode contract from Global Constraints.
- Produces:
  - Fact `posture_config_text` (string) — the config under evaluation.
  - Fact `posture_ios_version` (string) — for `version_ge` checks.
  - Fact `posture_device_error` (string, only set on gather failure).
  - Vars `posture_valid_categories` (list), `posture_min_config_bytes` (int).
  - `posture_checks` (list) — the catalog; a 1-item stub here, replaced in Task 6.

- [ ] **Step 1: Create `roles/cisco_posture_audit/meta/main.yml`**

```yaml
---
galaxy_info:
  role_name: cisco_posture_audit
  author: mlowcher61
  description: Audit Cisco IOS/IOS-XE devices against a security posture baseline
  license: MIT
  min_ansible_version: "2.15"
dependencies: []
```

- [ ] **Step 2: Create `roles/cisco_posture_audit/defaults/main.yml` (stub catalog + engine defaults)**

```yaml
---
# Engine behaviour
posture_min_config_bytes: 500
posture_fail_on_noncompliance: true
posture_report_format: both          # console | file | both
posture_report_dir: "./reports"

# Fixture-mode inputs (unset in production; set by tests)
posture_fixture_file: ""
posture_fixture_version: "0.0"

# Filtering (surveys narrow these; defaults = everything)
posture_valid_categories:
  - management
  - services
  - snmp
  - logging
  - ntp
  - interfaces
  - control_plane
  - software
posture_categories: "{{ posture_valid_categories }}"
posture_severity_floor: low
posture_severity_order:
  low: 0
  medium: 1
  high: 2

# THE CHECK CATALOG — stub, replaced in full by Task 6
posture_checks:
  - name: "service password-encryption enabled"
    id: "mgmt-password-encryption"
    category: "management"
    severity: "high"
    cis: "1.2.1"
    type: "present"
    pattern: 'service password-encryption'
    remediate:
      - "service password-encryption"
```

- [ ] **Step 3: Create `roles/cisco_posture_audit/tasks/validate_catalog.yml`**

```yaml
---
- name: Validate catalog — required fields and enumerations
  ansible.builtin.assert:
    that:
      - item.id is defined
      - item.id | length > 0
      - item.name is defined
      - item.category in posture_valid_categories
      - item.severity in ['high', 'medium', 'low']
      - item.type in ['present', 'absent', 'match', 'version_ge']
      - item.pattern is defined
      - not (item.type == 'match' and item.expected is not defined)
    quiet: true
    fail_msg: "Invalid check definition: {{ item.id | default('<no id>') }}"
  loop: "{{ posture_checks }}"
  loop_control:
    label: "{{ item.id | default('<no id>') }}"

- name: Validate catalog — ids are unique
  ansible.builtin.assert:
    that:
      - (posture_checks | map(attribute='id') | list | length) ==
        (posture_checks | map(attribute='id') | unique | list | length)
    fail_msg: "Duplicate check id detected in catalog"
    quiet: true

- name: Validate catalog — patterns compile
  ansible.builtin.debug:
    msg: "{{ ('probe-string' | regex_search(item.pattern)) | default('', true) }}"
    verbosity: 2
  loop: "{{ posture_checks }}"
  loop_control:
    label: "{{ item.id }}"
  when: item.type != 'version_ge'
```

- [ ] **Step 4: Create `roles/cisco_posture_audit/tasks/gather.yml`**

```yaml
---
- name: Load running-config from fixture (test mode)
  when: posture_fixture_file | length > 0
  ansible.builtin.set_fact:
    posture_config_text: "{{ lookup('ansible.builtin.file', posture_fixture_file) }}"
    posture_ios_version: "{{ posture_fixture_version }}"

- name: Gather running-config and facts from device
  when: posture_fixture_file | length == 0
  block:
    - name: Run show running-config
      cisco.ios.ios_command:
        commands:
          - show running-config
      register: posture_show_run

    - name: Gather IOS facts
      cisco.ios.ios_facts:

    - name: Store config text and version
      ansible.builtin.set_fact:
        posture_config_text: "{{ posture_show_run.stdout[0] }}"
        posture_ios_version: "{{ ansible_net_version | default('0.0') }}"
  rescue:
    - name: Record device gather error
      ansible.builtin.set_fact:
        posture_device_error: "{{ ansible_failed_result.msg | default('unreachable or gather failed') }}"

- name: Guard against truncated or empty running-config
  ansible.builtin.assert:
    that:
      - posture_config_text | length >= posture_min_config_bytes
      - (posture_config_text | regex_search('(?m)^hostname ')) is not none
      - (posture_config_text | regex_search('(?m)^end\s*$')) is not none
    fail_msg: >-
      Running-config appears truncated or empty
      ({{ posture_config_text | length }} bytes). Refusing to evaluate 'absent'
      checks against incomplete config — that would report false PASS results.
      Verify the login account has privilege level 15.
    success_msg: "Running-config captured ({{ posture_config_text | length }} bytes)."
    quiet: true
  when: posture_device_error is not defined
```

> **NOTE — designated owner-contribution point.** The guard's `that:` list is the "how paranoid should the truncation check be?" decision flagged in the spec. The default requires ≥ `posture_min_config_bytes` bytes plus a `hostname` line and a terminating `end`. During execution, confirm this strictness with the owner and tune the sentinels/threshold before moving on.

- [ ] **Step 5: Create `roles/cisco_posture_audit/tasks/main.yml`**

```yaml
---
- name: Validate the check catalog before connecting
  ansible.builtin.import_tasks: validate_catalog.yml

- name: Gather device state
  ansible.builtin.import_tasks: gather.yml

- name: Announce skeleton reached (temporary — removed in Task 4)
  ansible.builtin.debug:
    msg: >-
      Config loaded ({{ posture_config_text | default('') | length }} bytes),
      IOS version {{ posture_ios_version | default('unknown') }},
      {{ posture_checks | length }} checks in catalog.
  when: posture_device_error is not defined
```

- [ ] **Step 6: Create `playbooks/audit_posture.yml`**

```yaml
---
- name: Audit Cisco IOS security posture
  hosts: all
  gather_facts: false
  roles:
    - cisco_posture_audit
```

- [ ] **Step 7: Run against the compliant fixture — expect success**

Run:
```bash
ansible-playbook playbooks/audit_posture.yml -i localhost, \
  -e ansible_connection=local \
  -e posture_fixture_file=tests/fixtures/compliant_running_config.txt
```
Expected: play completes; debug shows a byte count > 500 and "1 checks in catalog".

- [ ] **Step 8: Run against a truncated config — expect the guard to fail loudly**

Run:
```bash
printf 'version 17.9\n' > /tmp/truncated.txt
ansible-playbook playbooks/audit_posture.yml -i localhost, \
  -e ansible_connection=local \
  -e posture_fixture_file=/tmp/truncated.txt
```
Expected: FAIL on "Guard against truncated or empty running-config".

- [ ] **Step 9: Commit**

```bash
git add roles/cisco_posture_audit playbooks/audit_posture.yml
git commit -m "feat: audit role skeleton — catalog validation, gather, truncation guard"
```

---

## Task 4: Check evaluation engine

Implements the four check types and produces `posture_results`. Tested with a synthetic 4-check catalog (one per type) so engine correctness is proven independently of real Cisco semantics.

**Files:**
- Create: `roles/cisco_posture_audit/tasks/checks.yml`
- Modify: `roles/cisco_posture_audit/tasks/main.yml` (replace the temporary debug with a call to checks.yml)

**Interfaces:**
- Consumes: `posture_config_text`, `posture_ios_version`, `posture_checks`, `posture_categories`, `posture_severity_floor`, `posture_severity_order`.
- Produces: fact `posture_results` — a list of dicts, each:
  `{ id, name, category, severity, cis, type, passed (bool), remediable (bool), actual (string) }`.
  Only checks whose `category` is in `posture_categories` and whose severity ≥ the floor are included.

- [ ] **Step 1: Create `roles/cisco_posture_audit/tasks/checks.yml`**

```yaml
---
- name: Select active checks by category and severity floor
  ansible.builtin.set_fact:
    posture_active_checks: >-
      {{ posture_checks
         | selectattr('category', 'in', posture_categories)
         | selectattr('severity', 'in', posture_severities_at_or_above_floor)
         | list }}
  vars:
    posture_severities_at_or_above_floor: >-
      {{ posture_severity_order
         | dict2items
         | selectattr('value', 'ge', posture_severity_order[posture_severity_floor])
         | map(attribute='key') | list }}

- name: Initialize results
  ansible.builtin.set_fact:
    posture_results: []

- name: Evaluate each active check
  ansible.builtin.set_fact:
    posture_results: "{{ posture_results + [result_item] }}"
  vars:
    matched: "{{ (posture_config_text | regex_search(item.pattern, multiline=True, ignorecase=True)) is not none }}"
    captured: "{{ posture_config_text | regex_search(item.pattern, '\\1', multiline=True, ignorecase=True) }}"
    passed: >-
      {{ (item.type == 'present' and matched) or
         (item.type == 'absent' and not matched) or
         (item.type == 'match' and matched and captured == item.expected) or
         (item.type == 'version_ge' and (posture_ios_version is version(item.threshold, 'ge'))) }}
    result_item:
      id: "{{ item.id }}"
      name: "{{ item.name }}"
      category: "{{ item.category }}"
      severity: "{{ item.severity }}"
      cis: "{{ item.cis | default('') }}"
      type: "{{ item.type }}"
      passed: "{{ passed | bool }}"
      remediable: "{{ item.remediate is defined and (item.remediate | default([]) | length > 0) }}"
      actual: >-
        {{ (posture_ios_version
            if item.type == 'version_ge'
            else ((posture_config_text | regex_search(item.pattern, multiline=True, ignorecase=True)) | default('(not found)', true))) }}
  loop: "{{ posture_active_checks }}"
  loop_control:
    label: "{{ item.id }}"
```

- [ ] **Step 2: Replace the temporary debug in `roles/cisco_posture_audit/tasks/main.yml`**

Replace the "Announce skeleton reached" task with:

```yaml
- name: Evaluate posture checks
  ansible.builtin.import_tasks: checks.yml
  when: posture_device_error is not defined
```

- [ ] **Step 3: Create a synthetic test catalog fixture**

Create `tests/fixtures/synthetic_catalog.yml`:

```yaml
---
posture_checks:
  - name: "present-type hits"
    id: "syn-present"
    category: "management"
    severity: "high"
    type: "present"
    pattern: 'service password-encryption'
  - name: "absent-type hits"
    id: "syn-absent"
    category: "services"
    severity: "medium"
    type: "absent"
    pattern: '(?m)^ip http server'
  - name: "match-type hits"
    id: "syn-match"
    category: "management"
    severity: "low"
    type: "match"
    pattern: 'ip ssh version (\d)'
    expected: "2"
  - name: "version_ge hits"
    id: "syn-version"
    category: "software"
    severity: "high"
    type: "version_ge"
    pattern: 'version'
    threshold: "16.0"
```

- [ ] **Step 4: Run engine against the compliant fixture with the synthetic catalog — expect 4/4 pass**

Run:
```bash
ansible-playbook playbooks/audit_posture.yml -i localhost, \
  -e ansible_connection=local \
  -e posture_fixture_file=tests/fixtures/compliant_running_config.txt \
  -e posture_fixture_version=17.9 \
  -e @tests/fixtures/synthetic_catalog.yml \
  -e '{"posture_debug_dump": true}' \
  -e 'posture_fail_on_noncompliance=false' -v 2>&1 | grep -E "syn-"
```
Expected: all four `syn-*` checks evaluated (report task arrives in Task 5; for now confirm no errors and `posture_results` builds).

To see results now, temporarily append to `main.yml` a `debug: var=posture_results` (remove after). Expected: `passed: true` for all four against the compliant fixture (version 17.9 ≥ 16.0, ssh version 2 == "2", no `ip http server` line, `service password-encryption` present).

- [ ] **Step 5: Run against the non-compliant fixture — expect the four to flip appropriately**

Run the same command with `posture_fixture_file=tests/fixtures/noncompliant_running_config.txt` and `posture_fixture_version=15.2`.
Expected: `syn-present` FAIL (no encryption line), `syn-absent` FAIL (`ip http server` present), `syn-match` FAIL (no `ip ssh version 2`), `syn-version` FAIL (15.2 < 16.0).

- [ ] **Step 6: Commit**

```bash
git add roles/cisco_posture_audit/tasks/checks.yml roles/cisco_posture_audit/tasks/main.yml tests/fixtures/synthetic_catalog.yml
git commit -m "feat: data-driven check engine — present/absent/match/version_ge"
```

---

## Task 5: Console report, summary, and fail gating

**Files:**
- Create: `roles/cisco_posture_audit/tasks/report.yml`
- Modify: `roles/cisco_posture_audit/tasks/main.yml` (add report import)

**Interfaces:**
- Consumes: `posture_results`, `posture_fail_on_noncompliance`, `posture_device_error`.
- Produces:
  - Facts `posture_failed_list`, `posture_passed_count`, `posture_total`.
  - `set_stats` keys: `posture_total`, `posture_failed`, `posture_compliant` (bool).
  - Job fails when `posture_failed_list` is non-empty and gating is on.

- [ ] **Step 1: Create `roles/cisco_posture_audit/tasks/report.yml`**

```yaml
---
- name: Compute posture summary
  ansible.builtin.set_fact:
    posture_failed_list: "{{ posture_results | selectattr('passed', 'equalto', false) | list }}"
    posture_total: "{{ posture_results | length }}"

- name: Render posture report header
  ansible.builtin.debug:
    msg:
      - "CISCO IOS SECURITY POSTURE — {{ inventory_hostname }}"
      - "================================================"

- name: Render posture report lines
  ansible.builtin.debug:
    msg: >-
      [ {{ 'PASS' if (item.passed | bool) else 'FAIL' }} ]
      {{ '%-45s' | format(item.name) }} : {{ item.actual | trim | truncate(40) }}
      {{ '' if (item.passed | bool) else '  <-- ' ~ item.severity ~ ' (' ~ item.cis ~ ')' }}
  loop: "{{ posture_results }}"
  loop_control:
    label: "{{ item.id }}"

- name: Render result summary line
  ansible.builtin.debug:
    msg: >-
      RESULT: {{ 'COMPLIANT' if (posture_failed_list | length == 0) else 'NON-COMPLIANT' }}
      ({{ posture_failed_list | length }} of {{ posture_total }} checks failed)

- name: Publish compliance stats
  ansible.builtin.set_stats:
    data:
      posture_total: "{{ posture_total | int }}"
      posture_failed: "{{ posture_failed_list | length }}"
      posture_compliant: "{{ (posture_failed_list | length) == 0 }}"

- name: Report device error (unreachable)
  ansible.builtin.debug:
    msg: "DEVICE ERROR on {{ inventory_hostname }}: {{ posture_device_error }}"
  when: posture_device_error is defined

- name: Fail the job when non-compliant
  ansible.builtin.fail:
    msg: "NON-COMPLIANT: {{ posture_failed_list | length }} of {{ posture_total }} checks failed"
  when:
    - posture_device_error is not defined
    - posture_fail_on_noncompliance | bool
    - posture_failed_list | length > 0
```

- [ ] **Step 2: Add the report import to `roles/cisco_posture_audit/tasks/main.yml`**

Append:

```yaml
- name: Render posture report and gate the job
  ansible.builtin.import_tasks: report.yml
```

- [ ] **Step 3: Run against compliant fixture (stub catalog) — expect COMPLIANT, job green**

Run:
```bash
ansible-playbook playbooks/audit_posture.yml -i localhost, \
  -e ansible_connection=local \
  -e posture_fixture_file=tests/fixtures/compliant_running_config.txt \
  -e posture_fixture_version=17.9
```
Expected: report prints, `RESULT: COMPLIANT`, play succeeds.

- [ ] **Step 4: Run against non-compliant fixture — expect NON-COMPLIANT, job fails**

Run the same command with the non-compliant fixture and `posture_fixture_version=15.2`.
Expected: report prints `[ FAIL ]` for `mgmt-password-encryption`, `RESULT: NON-COMPLIANT`, play fails on "Fail the job when non-compliant".

- [ ] **Step 5: Confirm report-only mode does not fail**

Run the non-compliant command again adding `-e posture_fail_on_noncompliance=false`.
Expected: report prints NON-COMPLIANT but play succeeds (green).

- [ ] **Step 6: Commit**

```bash
git add roles/cisco_posture_audit/tasks/report.yml roles/cisco_posture_audit/tasks/main.yml
git commit -m "feat: console posture report, compliance stats, fail gating"
```

---

## Task 6: The full check catalog + expanded fixtures + automated harness

Replaces the stub catalog with the full CIS-derived set, expands both fixtures so the compliant one passes every check and the non-compliant one fails a known subset, and adds `tests/test_catalog.yml` as the repeatable no-hardware test.

**Files:**
- Modify: `roles/cisco_posture_audit/defaults/main.yml` (replace `posture_checks`)
- Modify: `tests/fixtures/compliant_running_config.txt` (expand to satisfy every check)
- Modify: `tests/fixtures/noncompliant_running_config.txt` (expand to fail a known subset)
- Create: `tests/test_catalog.yml`

**Interfaces:**
- Consumes: the engine from Tasks 3–5.
- Produces: `posture_checks` with ~24 checks across all eight categories; `tests/test_catalog.yml` asserting compliant→0 fails and non-compliant→expected fails.

- [ ] **Step 1: Replace `posture_checks` in `roles/cisco_posture_audit/defaults/main.yml`**

```yaml
posture_checks:
  # ---- management ----
  - { id: "mgmt-password-encryption", name: "service password-encryption enabled", category: "management", severity: "high", cis: "1.2.1", type: "present", pattern: 'service password-encryption', remediate: ["service password-encryption"] }
  - { id: "mgmt-enable-secret", name: "enable secret set (not enable password)", category: "management", severity: "high", cis: "1.1.1", type: "present", pattern: '(?m)^enable secret ', remediate: [] }
  - { id: "mgmt-no-enable-password", name: "legacy enable password absent", category: "management", severity: "high", cis: "1.1.1", type: "absent", pattern: '(?m)^enable password ', remediate: ["no enable password"] }
  - { id: "mgmt-aaa-new-model", name: "AAA new-model enabled", category: "management", severity: "medium", cis: "1.3", type: "present", pattern: '(?m)^aaa new-model', remediate: ["aaa new-model"] }
  - { id: "mgmt-ssh-v2", name: "SSH version 2 configured", category: "management", severity: "high", cis: "3.5.2", type: "match", pattern: 'ip ssh version (\d)', expected: "2", remediate: ["ip ssh version 2"] }
  - { id: "mgmt-vty-no-telnet", name: "Telnet disabled on VTY lines", category: "management", severity: "high", cis: "1.1.5", type: "absent", pattern: 'transport input .*telnet', remediate: ["line vty 0 15", "transport input ssh"] }
  - { id: "mgmt-vty-exec-timeout", name: "exec-timeout set on VTY", category: "management", severity: "medium", cis: "1.1.4", type: "present", pattern: '(?ms)line vty 0 15.*?exec-timeout', remediate: ["line vty 0 15", "exec-timeout 5 0"] }

  # ---- services ----
  - { id: "svc-no-http-server", name: "HTTP server disabled", category: "services", severity: "high", cis: "1.2.4", type: "absent", pattern: '(?m)^ip http server', remediate: ["no ip http server"] }
  - { id: "svc-no-pad", name: "PAD service disabled", category: "services", severity: "low", cis: "1.2.2", type: "present", pattern: '(?m)^no service pad', remediate: ["no service pad"] }
  - { id: "svc-no-source-route", name: "IP source-route disabled", category: "services", severity: "medium", cis: "1.2.3", type: "present", pattern: '(?m)^no ip source-route', remediate: ["no ip source-route"] }
  - { id: "svc-no-bootp", name: "BOOTP server disabled", category: "services", severity: "low", cis: "1.2.6", type: "present", pattern: '(?m)^no ip bootp server', remediate: ["no ip bootp server"] }
  - { id: "svc-no-cdp", name: "CDP disabled globally", category: "services", severity: "low", cis: "1.2.7", type: "present", pattern: '(?m)^no cdp run', remediate: ["no cdp run"] }

  # ---- snmp ----
  - { id: "snmp-no-public", name: "No 'public' SNMP community", category: "snmp", severity: "high", cis: "2.4.1", type: "absent", pattern: 'snmp-server community public', remediate: ["no snmp-server community public"] }
  - { id: "snmp-no-private", name: "No 'private' SNMP community", category: "snmp", severity: "high", cis: "2.4.1", type: "absent", pattern: 'snmp-server community private', remediate: ["no snmp-server community private"] }

  # ---- logging ----
  - { id: "log-timestamps", name: "Service timestamps on logs", category: "logging", severity: "low", cis: "2.2.1", type: "present", pattern: 'service timestamps log', remediate: ["service timestamps log datetime msec"] }
  - { id: "log-trap-level", name: "Logging trap level configured", category: "logging", severity: "medium", cis: "2.2.3", type: "present", pattern: '(?m)^logging trap ', remediate: ["logging trap informational"] }
  - { id: "log-host", name: "Remote logging host configured", category: "logging", severity: "medium", cis: "2.2.4", type: "present", pattern: '(?m)^logging host ', remediate: [] }

  # ---- ntp ----
  - { id: "ntp-server", name: "NTP server configured", category: "ntp", severity: "medium", cis: "2.3.1", type: "present", pattern: '(?m)^ntp server ', remediate: [] }
  - { id: "ntp-authenticate", name: "NTP authentication enabled", category: "ntp", severity: "medium", cis: "2.3.2", type: "present", pattern: '(?m)^ntp authenticate', remediate: ["ntp authenticate"] }

  # ---- interfaces ----
  - { id: "int-no-directed-broadcast", name: "No IP directed-broadcast present", category: "interfaces", severity: "medium", cis: "3.2.1", type: "absent", pattern: '(?m)^\s*ip directed-broadcast', remediate: [] }
  - { id: "int-no-proxy-arp", name: "Proxy ARP disabled somewhere", category: "interfaces", severity: "low", cis: "3.2.2", type: "present", pattern: '(?m)^\s*no ip proxy-arp', remediate: [] }

  # ---- control_plane ----
  - { id: "cp-ospf-auth", name: "OSPF authentication present (if OSPF used)", category: "control_plane", severity: "medium", cis: "3.3.1", type: "present", pattern: 'ip ospf (message-digest-key|authentication)', remediate: [] }

  # ---- software ----
  - { id: "sw-ios-version-floor", name: "IOS version at or above approved minimum", category: "software", severity: "high", cis: "1.0", type: "version_ge", pattern: 'version', threshold: "{{ posture_ios_min_version | default('16.0') }}", remediate: [] }
```

Add near the top of `defaults/main.yml`:

```yaml
posture_ios_min_version: "16.0"
```

> Checks with `remediate: []` are report-only by design (host-specific values, or state the tool must not template blindly — remote logging host IPs, NTP servers, per-interface hardening, control-plane auth). They appear in the report but are never auto-pushed.

- [ ] **Step 2: Replace `tests/fixtures/compliant_running_config.txt` with a full passing config**

```
version 17.9
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
no service pad
!
hostname rtr-compliant
!
enable secret 9 $9$abcdefghij
no enable password
!
aaa new-model
!
no ip source-route
no ip bootp server
no cdp run
ip ssh version 2
no ip http server
no ip http secure-server
!
interface GigabitEthernet0/0
 no ip proxy-arp
 no ip directed-broadcast
!
router ospf 1
 area 0 authentication message-digest
interface GigabitEthernet0/1
 ip ospf message-digest-key 1 md5 7 secret
!
snmp-server group ADMIN v3 priv
!
line con 0
 exec-timeout 5 0
line vty 0 15
 exec-timeout 5 0
 transport input ssh
!
ntp authenticate
ntp authentication-key 1 md5 secret
ntp server 10.0.0.1 key 1
logging trap informational
logging host 10.0.0.2
!
end
```

- [ ] **Step 3: Replace `tests/fixtures/noncompliant_running_config.txt` with a config that fails a known subset**

```
version 15.2
service timestamps debug datetime msec
!
hostname rtr-bad
!
enable password cisco123
!
ip http server
!
interface GigabitEthernet0/0
 ip directed-broadcast
!
snmp-server community public RO
snmp-server community private RW
!
line con 0
line vty 0 15
 transport input telnet ssh
!
end
```

This fixture is expected to FAIL: `mgmt-password-encryption`, `mgmt-enable-secret`, `mgmt-no-enable-password`, `mgmt-aaa-new-model`, `mgmt-ssh-v2`, `mgmt-vty-no-telnet`, `mgmt-vty-exec-timeout`, `svc-no-http-server`, `svc-no-pad`, `svc-no-source-route`, `svc-no-bootp`, `svc-no-cdp`, `snmp-no-public`, `snmp-no-private`, `log-timestamps` (log line present? yes `service timestamps` — check pattern is `service timestamps log`; only `debug` present, so FAIL), `log-trap-level`, `log-host`, `ntp-server`, `ntp-authenticate`, `int-no-directed-broadcast`, `int-no-proxy-arp`, `cp-ospf-auth`, `sw-ios-version-floor`. Expected PASS: none guaranteed except possibly none — so assert on the failure of a representative subset rather than an exact count.

- [ ] **Step 4: Create `tests/test_catalog.yml`**

```yaml
---
# No-hardware regression test for the check catalog.
# Runs the audit engine against both fixtures and asserts on the outcome.
#
#   ansible-playbook tests/test_catalog.yml -i localhost, -e ansible_connection=local

- name: Catalog test — compliant fixture must be fully compliant
  hosts: all
  gather_facts: false
  vars:
    posture_fixture_file: "tests/fixtures/compliant_running_config.txt"
    posture_fixture_version: "17.9"
    posture_fail_on_noncompliance: false
  roles:
    - cisco_posture_audit
  post_tasks:
    - name: Assert zero failures on the compliant fixture
      ansible.builtin.assert:
        that:
          - posture_failed_list | length == 0
        fail_msg: >-
          Compliant fixture reported {{ posture_failed_list | length }} failures:
          {{ posture_failed_list | map(attribute='id') | list }}
        success_msg: "Compliant fixture: all {{ posture_total }} checks passed."

- name: Catalog test — non-compliant fixture must fail a known subset
  hosts: all
  gather_facts: false
  vars:
    posture_fixture_file: "tests/fixtures/noncompliant_running_config.txt"
    posture_fixture_version: "15.2"
    posture_fail_on_noncompliance: false
  roles:
    - cisco_posture_audit
  post_tasks:
    - name: Assert the expected checks failed
      ansible.builtin.assert:
        that:
          - "'mgmt-password-encryption' in failed_ids"
          - "'mgmt-vty-no-telnet' in failed_ids"
          - "'snmp-no-public' in failed_ids"
          - "'svc-no-http-server' in failed_ids"
          - "'sw-ios-version-floor' in failed_ids"
        fail_msg: "Non-compliant fixture did not fail the expected checks. Failed: {{ failed_ids }}"
        success_msg: "Non-compliant fixture failed {{ posture_failed_list | length }} checks as expected."
      vars:
        failed_ids: "{{ posture_failed_list | map(attribute='id') | list }}"
```

- [ ] **Step 5: Run the harness — both plays must pass their asserts**

Run:
```bash
ansible-playbook tests/test_catalog.yml -i localhost, -e ansible_connection=local
```
Expected: both `assert` tasks succeed. If the compliant fixture reports any failure, the fail_msg lists the offending ids — add the missing config line to the fixture (the check is correct; the fixture is the thing under construction) and re-run until zero.

- [ ] **Step 6: Lint**

Run: `ansible-lint roles/cisco_posture_audit playbooks tests/test_catalog.yml; yamllint .`
Expected: clean (or only warnings you consciously accept).

- [ ] **Step 7: Commit**

```bash
git add roles/cisco_posture_audit/defaults/main.yml tests/
git commit -m "feat: full CIS-derived check catalog + fixture regression harness"
```

---

## Task 7: HTML and CSV report artifacts

**Files:**
- Create: `roles/cisco_posture_audit/templates/posture_report.html.j2`
- Create: `roles/cisco_posture_audit/templates/posture_report.csv.j2`
- Modify: `roles/cisco_posture_audit/tasks/report.yml` (write artifacts when format includes file)

**Interfaces:**
- Consumes: `posture_results`, `posture_failed_list`, `posture_total`, `posture_report_format`, `posture_report_dir`.
- Produces: `{{ posture_report_dir }}/posture_<inventory_hostname>.html` and `.csv`; `set_stats` key `posture_report_path`.

- [ ] **Step 1: Create `roles/cisco_posture_audit/templates/posture_report.csv.j2`**

```jinja
id,name,category,severity,cis,result,actual
{% for r in posture_results %}
{{ r.id }},"{{ r.name }}",{{ r.category }},{{ r.severity }},{{ r.cis }},{{ 'PASS' if (r.passed | bool) else 'FAIL' }},"{{ r.actual | trim | replace('"', '""') }}"
{% endfor %}
```

- [ ] **Step 2: Create `roles/cisco_posture_audit/templates/posture_report.html.j2`**

```jinja
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cisco IOS Security Posture — {{ inventory_hostname }}</title>
<style>
 body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; }
 h1 { font-size: 1.3rem; }
 .summary { font-weight: 600; margin: 1rem 0; }
 .compliant { color: #197b30; }
 .noncompliant { color: #b3261e; }
 table { border-collapse: collapse; width: 100%; }
 th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: 0.9rem; }
 th { background: #f2f2f2; }
 .pass { color: #197b30; font-weight: 600; }
 .fail { color: #b3261e; font-weight: 600; }
</style>
</head>
<body>
<h1>Cisco IOS Security Posture — {{ inventory_hostname }}</h1>
<p class="summary {{ 'compliant' if (posture_failed_list | length == 0) else 'noncompliant' }}">
 RESULT: {{ 'COMPLIANT' if (posture_failed_list | length == 0) else 'NON-COMPLIANT' }}
 ({{ posture_failed_list | length }} of {{ posture_total }} checks failed)
</p>
<table>
 <tr><th>Result</th><th>Check</th><th>Category</th><th>Severity</th><th>CIS</th><th>Actual</th></tr>
{% for r in posture_results %}
 <tr>
  <td class="{{ 'pass' if (r.passed | bool) else 'fail' }}">{{ 'PASS' if (r.passed | bool) else 'FAIL' }}</td>
  <td>{{ r.name }}</td><td>{{ r.category }}</td><td>{{ r.severity }}</td><td>{{ r.cis }}</td>
  <td>{{ r.actual | trim | e }}</td>
 </tr>
{% endfor %}
</table>
</body>
</html>
```

- [ ] **Step 3: Add artifact rendering to `report.yml`**

Insert before the "Fail the job when non-compliant" task:

```yaml
- name: Ensure report directory exists
  ansible.builtin.file:
    path: "{{ posture_report_dir }}"
    state: directory
    mode: "0755"
  when:
    - posture_report_format in ['file', 'both']
    - posture_device_error is not defined

- name: Write HTML and CSV report artifacts
  ansible.builtin.template:
    src: "posture_report.{{ item }}.j2"
    dest: "{{ posture_report_dir }}/posture_{{ inventory_hostname }}.{{ item }}"
    mode: "0644"
  loop:
    - html
    - csv
  when:
    - posture_report_format in ['file', 'both']
    - posture_device_error is not defined

- name: Publish report path
  ansible.builtin.set_stats:
    data:
      posture_report_path: "{{ posture_report_dir }}/posture_{{ inventory_hostname }}.html"
  when:
    - posture_report_format in ['file', 'both']
    - posture_device_error is not defined
```

- [ ] **Step 4: Run and confirm artifacts are written**

Run:
```bash
ansible-playbook playbooks/audit_posture.yml -i localhost, \
  -e ansible_connection=local \
  -e posture_fixture_file=tests/fixtures/noncompliant_running_config.txt \
  -e posture_fixture_version=15.2 \
  -e posture_fail_on_noncompliance=false
ls -1 reports/
```
Expected: `reports/posture_localhost.html` and `reports/posture_localhost.csv` exist.

- [ ] **Step 5: Sanity-check artifact content**

Run: `grep -c "NON-COMPLIANT" reports/posture_localhost.html; head -3 reports/posture_localhost.csv`
Expected: HTML contains NON-COMPLIANT; CSV shows the header row plus data rows.

- [ ] **Step 6: Commit**

```bash
git add roles/cisco_posture_audit/templates roles/cisco_posture_audit/tasks/report.yml
git commit -m "feat: HTML and CSV posture report artifacts"
```

---

## Task 8: Remediation role

**Files:**
- Create: `roles/cisco_posture_remediate/defaults/main.yml`
- Create: `roles/cisco_posture_remediate/meta/main.yml`
- Create: `roles/cisco_posture_remediate/tasks/main.yml`
- Create: `playbooks/remediate_posture.yml`

**Interfaces:**
- Consumes: runs `cisco_posture_audit` first, then reads `posture_results` and `posture_checks`.
- Produces: pushes config via `ios_config`; re-runs audit; prints before/after. Facts `posture_remediation_lines`, `posture_pre_failed`, `posture_post_failed`.

- [ ] **Step 1: Create `roles/cisco_posture_remediate/meta/main.yml`**

```yaml
---
galaxy_info:
  role_name: cisco_posture_remediate
  author: mlowcher61
  description: Remediate failed Cisco IOS posture checks by pushing their fix lines
  license: MIT
  min_ansible_version: "2.15"
dependencies: []
```

- [ ] **Step 2: Create `roles/cisco_posture_remediate/defaults/main.yml`**

```yaml
---
posture_remediate_dry_run: true
posture_remediate_categories: "{{ posture_valid_categories }}"
posture_remediate_severity_floor: high
posture_remediate_save_config: false
```

- [ ] **Step 3: Create `roles/cisco_posture_remediate/tasks/main.yml`**

```yaml
---
- name: Run audit to establish current posture
  ansible.builtin.include_role:
    name: cisco_posture_audit
  vars:
    posture_fail_on_noncompliance: false

- name: Record pre-remediation failures
  ansible.builtin.set_fact:
    posture_pre_failed: "{{ posture_failed_list | map(attribute='id') | list }}"

- name: Select failed, remediable, in-scope check ids
  ansible.builtin.set_fact:
    posture_target_ids: >-
      {{ posture_failed_list
         | selectattr('remediable', 'equalto', true)
         | selectattr('category', 'in', posture_remediate_categories)
         | selectattr('severity', 'in', posture_remediate_severities)
         | map(attribute='id') | list }}
  vars:
    posture_remediate_severities: >-
      {{ posture_severity_order | dict2items
         | selectattr('value', 'ge', posture_severity_order[posture_remediate_severity_floor])
         | map(attribute='key') | list }}

- name: Collect remediation config lines from targeted checks
  ansible.builtin.set_fact:
    posture_remediation_lines: >-
      {{ posture_checks
         | selectattr('id', 'in', posture_target_ids)
         | map(attribute='remediate') | flatten | list }}

- name: Show planned remediation
  ansible.builtin.debug:
    msg:
      - "Dry run: {{ posture_remediate_dry_run | bool }}"
      - "Targeted checks: {{ posture_target_ids }}"
      - "Config lines to push: {{ posture_remediation_lines }}"

- name: Apply remediation config
  cisco.ios.ios_config:
    lines: "{{ posture_remediation_lines }}"
  check_mode: "{{ posture_remediate_dry_run | bool }}"
  register: posture_remediation
  when:
    - posture_remediation_lines | length > 0
    - posture_fixture_file | default('') | length == 0

- name: Save running-config
  cisco.ios.ios_config:
    save_when: modified
  when:
    - posture_remediate_save_config | bool
    - not (posture_remediate_dry_run | bool)
    - posture_fixture_file | default('') | length == 0

- name: Re-run audit to confirm remediation
  ansible.builtin.include_role:
    name: cisco_posture_audit
  vars:
    posture_fail_on_noncompliance: false
  when:
    - not (posture_remediate_dry_run | bool)
    - posture_fixture_file | default('') | length == 0

- name: Record post-remediation failures
  ansible.builtin.set_fact:
    posture_post_failed: "{{ posture_failed_list | map(attribute='id') | list }}"

- name: Before/after summary
  ansible.builtin.debug:
    msg:
      - "Before: {{ posture_pre_failed | length }} failing — {{ posture_pre_failed }}"
      - "After:  {{ posture_post_failed | length }} failing — {{ posture_post_failed }}"
      - "Fixed:  {{ posture_pre_failed | difference(posture_post_failed) }}"
      - "Manual/remaining: {{ posture_post_failed }}"
```

- [ ] **Step 4: Create `playbooks/remediate_posture.yml`**

```yaml
---
- name: Remediate Cisco IOS security posture
  hosts: all
  gather_facts: false
  roles:
    - cisco_posture_remediate
```

- [ ] **Step 5: Dry-run against the non-compliant fixture — expect a plan, no push**

Run:
```bash
ansible-playbook playbooks/remediate_posture.yml -i localhost, \
  -e ansible_connection=local \
  -e posture_fixture_file=tests/fixtures/noncompliant_running_config.txt \
  -e posture_fixture_version=15.2
```
Expected: "Targeted checks" lists high-severity remediable ids (e.g. `mgmt-password-encryption`, `mgmt-vty-no-telnet`, `snmp-no-public`, `svc-no-http-server`); "Config lines to push" lists their `remediate` lines; the `ios_config` push task is **skipped** (fixture mode), confirming no device write in test.

- [ ] **Step 6: Confirm the severity floor narrows the target set**

Run the same command adding `-e posture_remediate_severity_floor=low`.
Expected: the targeted id list grows to include medium/low remediable checks (e.g. `svc-no-source-route`, `svc-no-cdp`).

- [ ] **Step 7: Lint**

Run: `ansible-lint roles/cisco_posture_remediate playbooks/remediate_posture.yml; yamllint roles/cisco_posture_remediate`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add roles/cisco_posture_remediate playbooks/remediate_posture.yml
git commit -m "feat: opt-in remediation role — dry-run by default, severity-gated"
```

---

## Task 9: AAP config-as-code

Mirrors the `baseline-validation` idiom exactly: `ansible.platform.organization` for the org, `ansible.controller.*` for the rest, credential objects with no secrets, surveys inline.

**Files:**
- Create: `configure_aap/configure.yml`
- Create: `configure_aap/vars/organizations.yml`
- Create: `configure_aap/vars/projects.yml`
- Create: `configure_aap/vars/inventories.yml`
- Create: `configure_aap/vars/groups.yml`
- Create: `configure_aap/vars/credentials.yml`
- Create: `configure_aap/vars/job_templates.yml`
- Create: `configure_aap/README.md`

**Interfaces:**
- Consumes: the two playbooks (`playbooks/audit_posture.yml`, `playbooks/remediate_posture.yml`).
- Produces: AAP objects — Org "Network Security", project, inventory + `cisco_ios` group, machine credential, two job templates with surveys.

- [ ] **Step 1: Create `configure_aap/vars/organizations.yml`**

```yaml
---
aap_organizations:
  - name: "Network Security"
    description: "Cisco IOS security posture automation"
```

- [ ] **Step 2: Create `configure_aap/vars/projects.yml`**

```yaml
---
aap_projects:
  - name: "Cisco Security Posture"
    organization: "Network Security"
    scm_type: "git"
    scm_url: "https://github.com/mlowcher61/cisco_security_posture.git"
    scm_branch: "main"
    scm_clean: true
    update_on_launch: true
```

- [ ] **Step 3: Create `configure_aap/vars/inventories.yml`**

```yaml
---
aap_inventories:
  - name: "Cisco Network Inventory"
    organization: "Network Security"
    description: "Cisco IOS/IOS-XE devices under posture management"
```

- [ ] **Step 4: Create `configure_aap/vars/groups.yml`**

```yaml
---
aap_groups:
  - name: "cisco_ios"
    inventory: "Cisco Network Inventory"
    description: "IOS/IOS-XE devices"
    variables:
      ansible_connection: ansible.netcommon.network_cli
      ansible_network_os: cisco.ios.ios
      ansible_become: true
      ansible_become_method: enable
```

- [ ] **Step 5: Create `configure_aap/vars/credentials.yml`**

```yaml
---
# No secrets stored in git. The credential object is defined here;
# supply the actual username/password/SSH key in AAP at apply time.
aap_credentials:
  - name: "Cisco Network Machine Credential"
    organization: "Network Security"
    credential_type: "Machine"
    description: "SSH login for Cisco IOS devices — secrets set in AAP, not git"
```

- [ ] **Step 6: Create `configure_aap/vars/job_templates.yml`**

```yaml
---
aap_job_templates:
  - name: "Audit - Cisco IOS Security Posture"
    organization: "Network Security"
    project: "Cisco Security Posture"
    playbook: "playbooks/audit_posture.yml"
    inventory: "Cisco Network Inventory"
    credentials:
      - "Cisco Network Machine Credential"
    ask_variables_on_launch: false
    survey_enabled: true
    survey_spec:
      name: "Cisco Posture Audit Survey"
      description: "Scope and gating for the posture audit"
      spec:
        - question_name: "Categories to check (comma-separated, blank = all)"
          question_description: "management, services, snmp, logging, ntp, interfaces, control_plane, software"
          variable: posture_categories_raw
          type: text
          default: ""
          required: false
        - question_name: "Minimum severity"
          question_description: "Only evaluate checks at or above this severity"
          variable: posture_severity_floor
          type: multiplechoice
          default: "low"
          choices: ["low", "medium", "high"]
          required: true
        - question_name: "Fail job on non-compliance?"
          question_description: "true fails the job when any check fails; false is report-only"
          variable: posture_fail_on_noncompliance
          type: multiplechoice
          default: "true"
          choices: ["true", "false"]
          required: true
        - question_name: "Report format"
          question_description: "Where to emit the posture report"
          variable: posture_report_format
          type: multiplechoice
          default: "both"
          choices: ["console", "file", "both"]
          required: true

  - name: "Remediate - Cisco IOS Security Posture"
    organization: "Network Security"
    project: "Cisco Security Posture"
    playbook: "playbooks/remediate_posture.yml"
    inventory: "Cisco Network Inventory"
    credentials:
      - "Cisco Network Machine Credential"
    ask_variables_on_launch: false
    survey_enabled: true
    survey_spec:
      name: "Cisco Posture Remediation Survey"
      description: "Remediation is dry-run by default"
      spec:
        - question_name: "Dry run?"
          question_description: "yes previews changes without writing to the device"
          variable: posture_remediate_dry_run
          type: multiplechoice
          default: "true"
          choices: ["true", "false"]
          required: true
        - question_name: "Minimum severity to remediate"
          question_description: "Only push fixes for checks at or above this severity"
          variable: posture_remediate_severity_floor
          type: multiplechoice
          default: "high"
          choices: ["low", "medium", "high"]
          required: true
        - question_name: "Save config after change?"
          question_description: "Write mem after a successful, non-dry-run remediation"
          variable: posture_remediate_save_config
          type: multiplechoice
          default: "false"
          choices: ["true", "false"]
          required: true
```

> The survey exposes `posture_categories_raw` as free text; the playbook converts it to the `posture_categories` list. Add this to the top of `playbooks/audit_posture.yml`'s play as a `pre_tasks` step:
> ```yaml
>   pre_tasks:
>     - name: Derive category list from survey text (blank = all)
>       ansible.builtin.set_fact:
>         posture_categories: >-
>           {{ (posture_categories_raw.split(',') | map('trim') | select | list)
>              if (posture_categories_raw | default('') | length > 0)
>              else posture_valid_categories }}
> ```

- [ ] **Step 7: Create `configure_aap/configure.yml`**

```yaml
---
# Applies all AAP config-as-code objects for the Cisco security posture solution.
#
# Prerequisites:
#   ansible-galaxy collection install -r collections/requirements.yml
#   export CONTROLLER_HOST=https://your-aap-controller
#   export CONTROLLER_USERNAME=admin
#   export CONTROLLER_PASSWORD=<password>   # or CONTROLLER_OAUTH_TOKEN
#
# Usage:
#   ansible-playbook configure_aap/configure.yml

- name: Configure AAP for Cisco security posture
  hosts: localhost
  connection: local
  gather_facts: false

  vars_files:
    - vars/organizations.yml
    - vars/projects.yml
    - vars/inventories.yml
    - vars/groups.yml
    - vars/credentials.yml
    - vars/job_templates.yml

  tasks:
    - name: Create organizations
      ansible.platform.organization:
        name: "{{ item.name }}"
        description: "{{ item.description | default(omit) }}"
        state: present
      loop: "{{ aap_organizations }}"

    - name: Create projects
      ansible.controller.project:
        name: "{{ item.name }}"
        organization: "{{ item.organization }}"
        scm_type: "{{ item.scm_type }}"
        scm_url: "{{ item.scm_url }}"
        scm_branch: "{{ item.scm_branch | default('main') }}"
        scm_clean: "{{ item.scm_clean | default(true) }}"
        update_on_launch: "{{ item.update_on_launch | default(true) }}"
        state: present
      loop: "{{ aap_projects }}"

    - name: Create inventories
      ansible.controller.inventory:
        name: "{{ item.name }}"
        organization: "{{ item.organization }}"
        description: "{{ item.description | default(omit) }}"
        state: present
      loop: "{{ aap_inventories }}"

    - name: Create inventory groups
      ansible.controller.group:
        name: "{{ item.name }}"
        inventory: "{{ item.inventory }}"
        description: "{{ item.description | default(omit) }}"
        variables: "{{ item.variables | default(omit) }}"
        state: present
      loop: "{{ aap_groups }}"

    - name: Create machine credentials (object only — set secrets in AAP UI)
      ansible.controller.credential:
        name: "{{ item.name }}"
        organization: "{{ item.organization }}"
        credential_type: "{{ item.credential_type }}"
        description: "{{ item.description | default(omit) }}"
        state: present
      loop: "{{ aap_credentials }}"

    - name: Create job templates with surveys
      ansible.controller.job_template:
        name: "{{ item.name }}"
        organization: "{{ item.organization }}"
        project: "{{ item.project }}"
        playbook: "{{ item.playbook }}"
        inventory: "{{ item.inventory }}"
        credentials: "{{ item.credentials | default([]) }}"
        ask_variables_on_launch: "{{ item.ask_variables_on_launch | default(false) }}"
        survey_enabled: "{{ item.survey_enabled | default(false) }}"
        survey_spec: "{{ item.survey_spec | default(omit) }}"
        state: present
      loop: "{{ aap_job_templates }}"
```

- [ ] **Step 8: Create `configure_aap/README.md`**

```markdown
# Configure AAP — Cisco Security Posture

Stands up every AAP object this solution needs. No secrets are stored here;
supply credential secrets in the AAP UI after the objects are created.

## Prerequisites

```bash
ansible-galaxy collection install -r collections/requirements.yml
export CONTROLLER_HOST=https://your-aap-controller
export CONTROLLER_USERNAME=admin
export CONTROLLER_PASSWORD=yourpassword    # or CONTROLLER_OAUTH_TOKEN
```

## Apply

```bash
ansible-playbook configure_aap/configure.yml
```

## What it creates

| Object | Name |
|---|---|
| Organization | Network Security |
| Project | Cisco Security Posture |
| Inventory | Cisco Network Inventory |
| Group | cisco_ios (network_cli connection vars) |
| Credential | Cisco Network Machine Credential (secrets set in UI) |
| Job template | Audit - Cisco IOS Security Posture |
| Job template | Remediate - Cisco IOS Security Posture |

## After applying

1. Open **Credentials → Cisco Network Machine Credential** and set the username
   and SSH key/password plus the enable secret for privilege escalation.
2. Add your IOS devices to the **cisco_ios** group in **Cisco Network Inventory**.
3. Launch **Audit - Cisco IOS Security Posture**.
```

- [ ] **Step 9: Syntax-check the config playbook**

Run: `ansible-playbook configure_aap/configure.yml --syntax-check`
Expected: no syntax errors. (A full apply needs a live controller and is out of scope for local testing.)

- [ ] **Step 10: Lint and commit**

```bash
yamllint configure_aap
git add configure_aap
git commit -m "feat: AAP config-as-code — org, project, inventory, credential, two templates"
```

---

## Task 10: README

**Files:**
- Create: `README.md`

**Interfaces:**
- Consumes: the whole solution.
- Produces: full user-facing documentation following the `baseline-validation` README shape.

- [ ] **Step 1: Create `README.md`**

```markdown
# Cisco Security Posture

An Ansible Automation Platform (AAP) solution that audits Cisco IOS / IOS-XE
devices against a security posture baseline derived from the CIS Cisco IOS
Benchmark, produces a clear **PASS / NON-COMPLIANT** report (job output plus
HTML/CSV artifacts), and can **opt-in remediate** the findings it detects.

## What it does

Two job templates:

- **Audit - Cisco IOS Security Posture** — read-only. Fetches `show running-config`
  once per device, evaluates every check in the catalog, and renders a report.
  Fails the job (red in AAP) on non-compliance unless run in report-only mode.
- **Remediate - Cisco IOS Security Posture** — pushes the fix lines for failed
  checks. **Dry-run by default**; severity-gated so you choose how far it reaches.

Example audit output:

```
CISCO IOS SECURITY POSTURE — rtr01.example.com
================================================
[ PASS ] service password-encryption enabled     : service password-encryption
[ FAIL ] Telnet disabled on VTY lines             : transport input telnet ssh   <-- high (1.1.5)
[ PASS ] SSH version 2 configured                 : ip ssh version 2
[ FAIL ] No 'public' SNMP community               : snmp-server community public  <-- high (2.4.1)
------------------------------------------------
RESULT: NON-COMPLIANT  (2 of 24 checks failed)
```

## How the check engine works

Every check is one data entry in
[`roles/cisco_posture_audit/defaults/main.yml`](roles/cisco_posture_audit/defaults/main.yml):

```yaml
- id: "mgmt-vty-no-telnet"
  name: "Telnet disabled on VTY lines"
  category: "management"
  severity: "high"
  cis: "1.1.5"
  type: "absent"
  pattern: 'transport input .*telnet'
  remediate:
    - "line vty 0 15"
    - "transport input ssh"
```

The engine fetches the running-config once, then evaluates each check's `pattern`
against it. Check `type` is one of `present`, `absent`, `match`, or `version_ge`.
Because each check carries its own `remediate` lines, remediation is just a filter
over the audit results — audit and fix can never disagree. Omit `remediate` (or set
it to `[]`) and the check is report-only.

## Repository structure

```
cisco_security_posture/
├── README.md
├── ansible.cfg
├── collections/requirements.yml
├── playbooks/{audit_posture,remediate_posture}.yml
├── roles/
│   ├── cisco_posture_audit/      # catalog + engine + report + templates
│   └── cisco_posture_remediate/  # filter failed → push → verify
├── tests/
│   ├── fixtures/                 # compliant + non-compliant running-configs
│   └── test_catalog.yml          # no-hardware regression test
└── configure_aap/                # config-as-code for all AAP objects
```

## Quick start

### 1. Install collections

```bash
ansible-galaxy collection install -r collections/requirements.yml
```

### 2. Stand up AAP objects

See [`configure_aap/README.md`](configure_aap/README.md).

```bash
export CONTROLLER_HOST=https://your-aap-controller
export CONTROLLER_USERNAME=admin
export CONTROLLER_PASSWORD=yourpassword
ansible-playbook configure_aap/configure.yml
```

### 3. Add secrets and devices in AAP

1. **Credentials → Cisco Network Machine Credential** — set username, SSH
   key/password, and enable secret.
2. Add IOS devices to the **cisco_ios** group in **Cisco Network Inventory**.

### 4. Run the audit

Launch **Audit - Cisco IOS Security Posture**. The survey lets you scope by
category and severity, toggle fail-vs-report-only, and choose the report format.

### 5. Remediate (optional)

Launch **Remediate - Cisco IOS Security Posture**. Leave **Dry run = true** first
to preview the exact config lines, then re-run with **Dry run = false** to apply.

## The checks

| Category | Examples |
|---|---|
| management | password-encryption, enable secret, no enable password, AAA, SSHv2, no telnet on VTY, exec-timeout |
| services | no ip http server, no service pad, no ip source-route, no ip bootp, no cdp run |
| snmp | no `public`/`private` communities |
| logging | service timestamps, logging trap, logging host |
| ntp | ntp server, ntp authenticate |
| interfaces | no ip directed-broadcast, no ip proxy-arp |
| control_plane | OSPF authentication |
| software | IOS version at or above an approved minimum |

Change the approved IOS floor with `posture_ios_min_version` (default `16.0`).

## Adding a check

Add one entry to `posture_checks` in `roles/cisco_posture_audit/defaults/main.yml`.
No task files change. Supported types: `present`, `absent`, `match` (needs
`expected`), `version_ge` (needs `threshold`). Give it `remediate` lines to make it
auto-fixable, or omit them for report-only.

## Testing without hardware

```bash
ansible-playbook tests/test_catalog.yml -i localhost, -e ansible_connection=local
```

Runs the whole engine against the bundled fixtures and asserts the compliant
fixture passes every check and the non-compliant one fails the expected subset.

You can also point the audit at a fixture directly:

```bash
ansible-playbook playbooks/audit_posture.yml -i localhost, \
  -e ansible_connection=local \
  -e posture_fixture_file=tests/fixtures/noncompliant_running_config.txt \
  -e posture_fixture_version=15.2 \
  -e posture_fail_on_noncompliance=false
```

## Safety notes

- The engine **refuses to evaluate a truncated running-config** — if the fetch is
  short or missing a `hostname`/`end`, it fails loudly rather than reporting false
  PASSes on `absent` checks. The login account needs privilege level 15.
- Remediation is **dry-run by default** and **save-config is off by default**, so the
  destructive path always takes a deliberate choice.

## Lint

```bash
ansible-lint
yamllint .
```

## Collections used

| Collection | Purpose |
|---|---|
| `ansible.builtin` | set_fact, assert, template, debug, set_stats |
| `cisco.ios` | ios_command, ios_facts, ios_config |
| `ansible.platform` | AAP organization management |
| `ansible.controller` | AAP project, inventory, credential, job template |

Certified and validated content only — no Galaxy community collections.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: full README for the Cisco security posture solution"
```

---

## Task 11: Create the GitHub repo and push

**Files:** none (git/remote operations)

**Interfaces:**
- Consumes: the committed local repository.
- Produces: `github.com/mlowcher61/cisco_security_posture` with `main` pushed.

- [ ] **Step 1: Create the remote repository**

Preferred (GitHub MCP): call `create_repository` with `name: cisco_security_posture`, `description: "Cisco IOS/IOS-XE security posture audit and opt-in remediation for Ansible Automation Platform"`, `private: false`, `autoInit: false`.

Fallback if `gh` is authenticated:
```bash
gh repo create mlowcher61/cisco_security_posture --public \
  --description "Cisco IOS/IOS-XE security posture audit and opt-in remediation for Ansible Automation Platform"
```

- [ ] **Step 2: Add the remote and push**

```bash
git remote add origin https://github.com/mlowcher61/cisco_security_posture.git
git push -u origin main
```

- [ ] **Step 3: Verify**

Run: `git remote -v && git log --oneline -1`
Expected: origin points at the new repo; the latest commit is present.
Confirm on GitHub that `README.md` renders and `main` is the default branch.

---

## Self-Review

**Spec coverage:**

| Spec item | Task |
|---|---|
| Four check categories (mgmt, services, snmp, logging/ntp, interfaces, control_plane, software) | Task 6 catalog |
| Single running-config fetch + data-driven assertions | Tasks 3–4 |
| Optional `command:` escape hatch | Schema supports it (checks.yml source selection); no catalog entry uses it yet — noted below |
| Check schema (name, id, category, severity, cis, type, pattern, expected, command, remediate) | Tasks 3, 4, 6 |
| Audit template + survey | Tasks 5, 9 |
| Remediate template, dry-run default, severity floor, save-config default off | Tasks 8, 9 |
| HTML/CSV artifact | Task 7 |
| Truncation false-PASS guard (owner decision) | Task 3, flagged as contribution point |
| Catalog validation fail-fast | Task 3 |
| Unreachable device → continue | Task 3 gather rescue + Task 5 error reporting |
| Fixture-based no-hardware testing | Tasks 2, 4, 6 |
| Config-as-code, certified collections only, no secrets in git | Tasks 1, 9 |
| README | Task 10 |
| Repo creation + push | Task 11 |

**Note on the `command:` escape hatch:** the spec lists it as part of the schema. The engine in Task 4 evaluates every check against `posture_config_text`; no shipped check needs a per-command source, so to avoid untested code the gather-per-command path is **not** built in this plan. If a future check needs live state (e.g. `show ntp status`), extend `gather.yml` to register the command output into a `posture_cmd_outputs` dict and add source selection in `checks.yml`. This is called out here rather than silently dropped.

**Placeholder scan:** One intentional owner-contribution point (Task 3 guard) — it ships with a working default, so it is not a blank placeholder. No "TBD"/"TODO" left in code.

**Type consistency:** `posture_results` item shape (`id, name, category, severity, cis, type, passed, remediable, actual`) is defined in Task 4 and consumed identically in Tasks 5, 7, 8. `posture_failed_list`, `posture_total`, `posture_valid_categories`, `posture_severity_order` names are consistent across tasks.
