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
