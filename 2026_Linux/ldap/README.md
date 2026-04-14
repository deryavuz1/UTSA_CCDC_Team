# LDAP Toolbox — Credential Manager

An interactive bash toolkit for managing credentials across LDAP and Kerberos environments. Designed for CCDC/lab use where rapid, bulk credential rotation is needed. Must be run as root.

---

## Structure

```
toolbox.sh          ← entry point / main menu
lib/
  common.sh         ← shared helpers, session management, LDAP/crypto utilities
modules/
  01_enum.sh        ← environment discovery
  02_filter.sh      ← user exclusion management
  03_select.sh      ← per-user action assignment
  04_generate.sh    ← password and SSH key generation
  05_output.sh      ← output file generation
  06_apply.sh       ← apply changes to LDAP
  07_admin_passwd.sh← admin credential rotation
sessions/           ← auto-created; stores all session data and output files
```

---

## Usage

```sh
sudo ./toolbox.sh
```

---

## Main Menu Options

**1) Run Full Workflow** — runs all five pipeline stages in sequence: Enum → Filter → Select → Generate → Output. Start here on a fresh system.

**2) Enumerate Environment Only** — discovers and saves LDAP/Kerberos configuration and user data without making any changes. Useful for recon before deciding on actions.

**3) Load Latest Session & Modify** — reloads the most recent session and lets you re-run part of the pipeline (re-select users, re-filter, or just regenerate output files).

**4) Apply Changes** *(destructive)* — applies `changes.ldif` to LDAP via `ldapmodify`. Requires typing `APPLY` then `YES` at two separate confirmation prompts. Kerberos changes are never applied automatically.

**5) Change Admin Passwords** — rotate the LDAP admin account, Kerberos admin principal, or both. Also handles the KDC LDAP service account (`cn=krbadmin`) including keyfile re-stash and KDC restart, if the KDC uses an LDAP backend.

**6) View Output File Paths** — shows what files were generated in the current session and their line counts.

**7) List All Sessions** — lists all saved sessions with user counts.

---

## Pipeline Stages

### 01 — Enumeration
Auto-detects LDAP connection details from `/etc/sssd/sssd.conf` or `/etc/ldap/ldap.conf`, falling back to manual prompts. Detects Kerberos from `/etc/krb5.conf` and checks for KRB principals in LDAP. Discovers user OUs, then collects per-user data (DN, groups, SSH key, SSHA hash, Kerberos principal) into the session directory.

### 02 — Filter
Auto-excludes users matching competition service account patterns (e.g. `whiteteam`, `scorebot`, `blackteam`, `redteam`). Presents an interactive menu to add/remove users from the filter or add new patterns. Filtered users are excluded from all password changes by default.

### 03 — Selection
Displays an interactive table of all non-filtered users. For each user you assign one of:
- `r <user>` / `r all` — generate a random password
- `s <user> <password>` — set a specific password
- `n <user>` / `n all` — skip (no change)

Users can also be re-enabled from the filter here with `enable <user>`.

### 04 — Generation
Reads selections and generates random passwords where requested. Produces an ED25519 SSH keypair for every non-skipped user. Stores all generated material in the session directory.

### 05 — Output
Assembles all generated data into the following files under `sessions/<name>/output/`:

| File | Contents |
|---|---|
| `new_passwords.txt` | username,plaintext password for all changed users |
| `old_hashes.txt` | username,SSHA hash captured before changes |
| `changes.ldif` | LDAP modify operations for passwords and SSH keys |
| `revert.ldif` | LDAP modify operations to restore pre-change state |
| `krb5_changes.sh` | Shell script to update Kerberos principals (if detected) |
| `sshkeys/` | ED25519 keypairs for all changed users |

### 06 — Apply
Reads `changes.ldif` and submits it to LDAP via `ldapmodify`. Supports using a separate write-privileged DN if the enumeration bind DN is read-only. `krb5_changes.sh` must always be run manually.

### 07 — Admin Passwords
Separate from the user workflow. Rotates:
- LDAP admin account via `ldappasswd`
- Kerberos admin principal via `kadmin` or `kadmin.local`
- KDC LDAP service account (`cn=krbadmin`) — updates the LDAP entry, re-stashes the password into the keyfile via `kdb5_ldap_util`, and restarts the KDC

---

## Dependencies

| Tool | Purpose |
|---|---|
| `ldap-utils` (`ldapsearch`, `ldapmodify`, `ldappasswd`) | LDAP operations |
| `openssl` | SSHA hash generation |
| `ssh-keygen` | ED25519 keypair generation |
| `krb5-user` (`kadmin`) | Kerberos password changes — optional |
| `krb5-kdc-ldap` (`kdb5_ldap_util`) | KDC LDAP service account rotation — optional |
