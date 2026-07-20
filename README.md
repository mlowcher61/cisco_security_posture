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
├── .yamllint / .ansible-lint     # lint config-as-code
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
| management | password-encryption, enable secret, no enable password, AAA, SSHv2, no telnet on VTY, exec-timeout, password min-length |
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

The engine runs against bundled fixtures with a local connection — no device
needed. The regression test asserts the compliant fixture passes every check and
the non-compliant one fails the expected subset:

```bash
ansible-playbook tests/test_catalog.yml -i localhost, -e ansible_connection=local
```

You can also point the audit at a fixture directly. Pass an **absolute** fixture
path (the file lookup resolves relative paths against the playbook, not your shell):

```bash
ansible-playbook playbooks/audit_posture.yml -i localhost, \
  -e ansible_connection=local \
  -e posture_fixture_file="$(pwd)/tests/fixtures/noncompliant_running_config.txt" \
  -e posture_fixture_version=15.2 \
  -e posture_fail_on_noncompliance=false
```

## Safety notes

- The engine **refuses to evaluate a truncated running-config** — if the fetch is
  short (under `posture_min_config_bytes`, default 500) or missing a
  `hostname`/`end`, it fails loudly rather than reporting false PASSes on `absent`
  checks. The login account needs privilege level 15.
- Remediation is **dry-run by default** and **save-config is off by default**, so the
  destructive path always takes a deliberate choice.
- Fixture mode never writes to a device: the `ios_config` push is skipped whenever
  `posture_fixture_file` is set.

## Lint

```bash
yamllint .
ansible-lint --offline
```

`--offline` is used because the certified collections (`ansible.platform`,
`ansible.controller`) are present in the AAP execution environment but are not
installable from public Galaxy; `.ansible-lint` mocks their modules for local runs.

## Collections used

| Collection | Purpose |
|---|---|
| `ansible.builtin` | set_fact, assert, template, debug, set_stats |
| `cisco.ios` | ios_command, ios_facts, ios_config |
| `ansible.platform` | AAP organization management |
| `ansible.controller` | AAP project, inventory, credential, job template |

Certified and validated content only — no Galaxy community collections.
