# Cisco Security Posture — Design

**Date:** 2026-07-20
**Status:** Approved
**Repository:** `github.com/mlowcher61/cisco_security_posture`

## Purpose

An Ansible Automation Platform solution that audits Cisco IOS / IOS-XE devices against a
security posture baseline derived from the CIS Cisco IOS Benchmark, renders a clear
PASS / NON-COMPLIANT report, and can optionally remediate the findings it detects.

Two job templates:

1. **Audit - Cisco IOS Security Posture** — read-only, always safe to run.
2. **Remediate - Cisco IOS Security Posture** — pushes fixes for failed checks, dry-run by default.

## Scope

### In scope

Check categories, all four confirmed:

| Category | Coverage |
|---|---|
| Management plane | `service password-encryption`, `enable secret` over `enable password`, SSHv2-only, no telnet on VTY, `exec-timeout` on con/vty/aux, AAA new-model, login banners, `login block-for`, password min-length |
| Insecure services | `no ip http server`, `no service pad`, `no ip bootp server`, `no ip source-route`, `no service config`, `no cdp run` |
| SNMP | no `public`/`private` communities, v3 preferred, community ACLs applied |
| Logging & NTP | `logging host`, `logging trap`, service timestamps, buffered size, NTP configured and authenticated |
| Interface hardening | `no ip directed-broadcast`, `no ip proxy-arp`, `no ip redirects` / `unreachables` on untrusted interfaces |
| Control plane | Routing protocol authentication (OSPF/EIGRP/BGP), CoPP present, uRPF |
| Software currency | Running IOS version against an approved minimum |

Platform: **Cisco IOS / IOS-XE only.** NX-OS and ASA are explicitly out of scope; the check
catalog is structured so an NX-OS catalog could be added later as a sibling list without
redesigning the engine.

Output: console report in job output, plus an HTML and CSV report artifact.

### Out of scope

- Cisco PSIRT openVuln API CVE lookup (considered, dropped — needs a Cisco API credential and
  outbound internet from the execution node)
- ServiceNow / ITSM ticket creation
- NX-OS, ASA, and any non-Cisco platform

## Architecture

### Approach

**Single running-config fetch + data-driven assertions.**

One `ios_command: show running-config` and one `ios_facts` call per device. Every check is a
data entry in `defaults/main.yml` evaluated against that captured config text. Checks that
genuinely need live state (NTP sync status, negotiated SSH version) declare an optional
`command:` field that overrides the default source.

Alternatives rejected:

- **Per-check `show` command execution** — precise, but ~40 SSH round-trips per device. Slow
  and noisy in job output.
- **Structured facts + `cisco.ios` resource modules** — cleanest where resource modules exist,
  but coverage is incomplete. Roughly a third of CIS checks have no resource module, forcing a
  hybrid engine anyway.

### Repository layout

```
cisco_security_posture/
├── README.md
├── .gitignore
├── ansible.cfg
├── collections/requirements.yml
├── playbooks/
│   ├── audit_posture.yml
│   └── remediate_posture.yml
├── roles/
│   ├── cisco_posture_audit/
│   │   ├── defaults/main.yml
│   │   ├── meta/main.yml
│   │   ├── tasks/
│   │   │   ├── main.yml
│   │   │   ├── validate_catalog.yml
│   │   │   ├── gather.yml
│   │   │   ├── checks.yml
│   │   │   └── report.yml
│   │   └── templates/
│   │       ├── posture_report.html.j2
│   │       └── posture_report.csv.j2
│   └── cisco_posture_remediate/
│       ├── defaults/main.yml
│       ├── meta/main.yml
│       └── tasks/
│           ├── main.yml
│           ├── remediate.yml
│           └── verify.yml
├── tests/
│   ├── fixtures/
│   │   ├── compliant_running_config.txt
│   │   └── noncompliant_running_config.txt
│   └── test_catalog.yml
└── configure_aap/
    ├── README.md
    ├── configure.yml
    └── vars/
        ├── organizations.yml
        ├── projects.yml
        ├── inventories.yml
        ├── groups.yml
        ├── credentials.yml
        └── job_templates.yml
```

### Check schema

Every check is one list entry in `roles/cisco_posture_audit/defaults/main.yml`:

```yaml
- name: "Telnet disabled on VTY lines"
  id: "mgmt-vty-no-telnet"
  category: "management"
  severity: "high"
  cis: "1.1.5"
  type: "absent"
  pattern: "transport input .*telnet"
  remediate:
    - "line vty 0 15"
    - "transport input ssh"
```

| Field | Required | Purpose |
|---|---|---|
| `name` | yes | Human-readable label shown in the report |
| `id` | yes | Stable identifier, unique across the catalog |
| `category` | yes | One of: `management`, `services`, `snmp`, `logging`, `ntp`, `interfaces`, `control_plane`, `software` |
| `severity` | yes | `high`, `medium`, or `low` — drives report grouping and the remediation severity floor |
| `cis` | no | CIS Cisco IOS Benchmark reference, carried into the report for audit evidence |
| `type` | yes | `present`, `absent`, `match`, or `version_ge` |
| `pattern` | yes | Regex evaluated against the config text |
| `expected` | for `match` | Value the regex capture group is compared against |
| `command` | no | `show` command whose output replaces running-config as the evaluation source |
| `remediate` | no | Config lines that fix the finding. **Omitted means report-only** — the check is flagged "manual remediation required" |

Check types:

- `present` — regex must match, else FAIL
- `absent` — regex must not match, else FAIL
- `match` — regex must match and capture group 1 must equal `expected`
- `version_ge` — IOS version from `ios_facts` compared against a minimum

### Data flow

**Audit** (`playbooks/audit_posture.yml`):

1. Validate the check catalog — required fields present, regexes compile, `id` values unique.
2. Gather: `ios_command: show running-config`, `ios_facts`, plus any per-check `command:` outputs.
3. Guard: verify the captured config is plausibly complete (see Error handling).
4. Evaluate every check in the catalog against its source text.
5. Render the console report, grouped by category, showing every check with its result.
6. Render HTML and CSV artifacts.
7. Publish a compliance summary via `set_stats`.
8. Fail the job if any check failed, unless `posture_fail_on_noncompliance: false`.

**Remediate** (`playbooks/remediate_posture.yml`):

1. Run the audit role to establish current state.
2. Filter failed checks to those that have `remediate` lines, match the selected categories,
   and meet the severity floor.
3. Push the collected config lines with `ios_config`, in `check_mode` when dry-run is on.
4. Re-run the audit role.
5. Print a before/after comparison — checks fixed, checks still failing, checks requiring
   manual remediation.

Because each check carries its own remediation lines, audit and remediation cannot disagree —
there is no separate desired-state document to keep in sync.

### AAP objects (config-as-code)

Created by `configure_aap/configure.yml` using `ansible.platform` and `ansible.controller`:

| Object | Name |
|---|---|
| Organization | Network Security |
| Project | Cisco Security Posture |
| Inventory | Cisco Network Inventory |
| Inventory group | `cisco_ios`, with `ansible_network_os: cisco.ios.ios` connection vars |
| Credential | Machine credential for network device login |
| Job template 1 | Audit - Cisco IOS Security Posture |
| Job template 2 | Remediate - Cisco IOS Security Posture |

No custom credential type is required — with the PSIRT API out of scope there is no
third-party service to authenticate against, so the built-in Machine credential covers it.
No secrets are stored in the repository.

**Audit survey:**

| Question | Variable | Default |
|---|---|---|
| Categories to check | `posture_categories` | all |
| Minimum severity | `posture_severity_floor` | `low` |
| Fail job on non-compliance | `posture_fail_on_noncompliance` | `true` |
| Report format | `posture_report_format` | `both` |

**Remediation survey:**

| Question | Variable | Default |
|---|---|---|
| Dry run | `posture_remediate_dry_run` | `true` |
| Categories to remediate | `posture_remediate_categories` | all |
| Minimum severity | `posture_remediate_severity_floor` | `high` |
| Save config after change | `posture_remediate_save_config` | `false` |

Dry-run defaults on and save-config defaults off so that the destructive path always requires
a deliberate choice.

## Error handling

**Unreachable device.** Gather tasks run inside `block`/`rescue`. A device that cannot be
reached is marked `ERROR` in the report and the play continues across the rest of the
inventory rather than aborting the run.

**Truncated or empty running-config.** This is the critical failure mode: if
`show running-config` returns empty or truncated output — most commonly because the login
account lacks privilege 15 — every `absent` check trivially passes and the device reports as
fully compliant. The engine must detect this and fail loudly rather than report a false PASS.
The specific guard is an open implementation decision, to be settled during implementation.

**Malformed catalog.** Catalog validation runs before any device connection, so a typo in a
regex or a missing required field fails within seconds instead of mid-audit.

## Testing

`tests/fixtures/` holds a known-compliant and a known-non-compliant
`show running-config` capture. `tests/test_catalog.yml` runs the full check engine against
those fixtures with `ansible_connection=local`, asserting that the compliant fixture yields
zero failures and the non-compliant fixture yields the expected set.

This matters more here than in a Linux baseline role: Cisco checks have no `localhost`
fallback, so without fixtures every catalog edit would require live hardware to validate.

Lint: `ansible-lint` and `yamllint .`

## Collections

| Collection | Purpose |
|---|---|
| `ansible.builtin` | `set_fact`, `assert`, `debug`, `template`, `include_tasks` |
| `cisco.ios` | `ios_command`, `ios_facts`, `ios_config` |
| `ansible.platform` | AAP organization management in config-as-code |
| `ansible.controller` | AAP project, inventory, credential, job template management |

Certified and validated content only — no Galaxy community collections.

## Open questions

1. **`absent`-check false-negative guard.** How strictly should the engine validate that the
   captured running-config is complete before trusting `absent` results? To be decided during
   implementation with input from the repository owner.
