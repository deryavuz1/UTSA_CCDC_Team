# BSD Hardening Toolkit

A two-module interactive bash toolkit for enumerating and hardening FreeBSD and OpenBSD systems. Designed for use in competitive environments (CCDC) where fast, guided hardening is needed. All scripts auto-detect the BSD variant and adjust behavior accordingly.

---

## Scripts

### `bsd_main_launcher.sh`
The entry point. Run this as root — it handles privilege escalation automatically via `sudo` or `doas` if needed. On startup it attempts to pull the latest section scripts from GitHub, then presents a menu to run either section.

```
1) Section 1 - Enumeration
2) Section 2 - Initial Hardening
0) Exit
```

All output is logged to `/root/bsd_hardening.log`.

---

### `bsd_section1_enumeration.sh`
A guided walkthrough that collects a full picture of the system before any changes are made. Covers:

- OS version, hostname, and network interfaces
- Listening ports and active connections
- DNS, NIS/YP, and Kerberos configuration
- Users, groups, shells, and UID 0 accounts
- sudo/doas permissions
- Active sessions and login history
- Enabled startup services and rc.conf
- Installed packages (with vulnerability check on FreeBSD)
- SUID/SGID file scan (runs in background, results shown at end)
- File integrity check via `pkg check -s` / `pkg_check`
- World-writable files and directories
- Mounts, ZFS datasets, and snapshots
- SSH keys and sshd_config
- FreeBSD jail enumeration
- PF firewall status and existing ruleset
- Kernel security sysctls
- Root password change and SSH public key injection
- Optional: move the `sudo` binary to a hidden path

---

### `bsd_section2_initial_hardening.sh`
Applies hardening interactively, prompting before each significant change. Covers:

- Move privilege escalation binaries (`sudo`, `doas`, `chflags`) out of PATH
- Move high-risk tool binaries (`nc`, `curl`, `wget`, `gcc`, compilers, etc.)
- Review and edit `/etc/group`
- Review `/etc/passwd` with optional user deletion
- Identify and remove risky installed packages
- Resource limits via `/etc/login.conf` (nproc, nofile, coredump)
- Review file integrity output from Section 1
- Disable unneeded services (avahi, cups, rpcbind, inetd, sendmail, etc.)
- Kernel sysctl hardening (IP forwarding, redirects, TCP/UDP blackhole, ptrace, coredumps, etc.) — written to `/etc/sysctl.conf` and applied live
- ZFS dataset hardening (`exec=off`, `setuid=off` on `/tmp`, `/var/tmp`, `/usr/ports`)
- Temporary mount point review (`/tmp`, `/var/tmp`)
- FreeBSD jail hardening (secure `jail.conf` defaults, per-jail sysctl, SSH config)
- Backup of password and auth files to `/root/backup/`
- SSH hardening (PermitRootLogin, key-only or password auth, forwarding disabled, etc.)

---

## Usage

```sh
chmod +x bsd_main_launcher.sh
sudo ./bsd_main_launcher.sh
```

Sections can also be run directly if already sourcing the launcher:

```sh
sudo ./bsd_section1_enumeration.sh
sudo ./bsd_section2_initial_hardening.sh
```

> **Run Section 1 before Section 2.** Section 2 references output files (installed packages, integrity results) that Section 1 generates.
