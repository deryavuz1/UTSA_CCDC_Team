# Linux Multi-Script Toolkit

## Files
- `main_launcher.sh` - Launcher (sudo enforcement, optional GitHub script sync, section menu)
- `section1_enumeration.sh`
- `section2_initial_hardening.sh`
- `section3_password_changes.sh`
- `section4_setup_logging.sh`
- `section5_setup_rsyslog.sh`

## Run
```bash
cd "/path/to/your/scripts"
chmod +x *.sh
sudo ./main_launcher.sh
```

## GitHub Placeholder URLs (set before launch)
```bash
export SECTION1_URL="https://github.com/ORG/REPO/raw/main/section1_enumeration.sh"
export SECTION2_URL="https://github.com/ORG/REPO/raw/main/section2_initial_hardening.sh"
export SECTION3_URL="https://github.com/ORG/REPO/raw/main/section3_password_changes.sh"
export SECTION4_URL="https://github.com/ORG/REPO/raw/main/section4_setup_logging.sh"
export SECTION5_URL="https://github.com/ORG/REPO/raw/main/section5_setup_rsyslog.sh"
export AUDIT_RULES_URL="https://github.com/ORG/REPO/raw/main/audit.rules"
```

## Notes
- Scripts are intentionally interactive and pause between checklist blocks.
- High-risk actions (moving binaries, disabling services) are confirmation-gated.
- Output and actions are logged to `/root/linux_hardening.log`.
