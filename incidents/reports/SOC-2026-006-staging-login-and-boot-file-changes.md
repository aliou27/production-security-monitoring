# SOC-2026-006: Short SSH session and boot file changes on staging

| Field | Value |
|---|---|
| Severity | Medium at detection, none after verification |
| Classification | Login: benign positive (administrator). Boot files: false positive (content unchanged) |
| Status | Closed, with one open confirmation and one tuning to apply |
| Affected asset | `zikrou-staging`: SSH, `/boot/efi` |
| Detection source | Rules 5715, 5501, 5502 (SSH session); rule 550 (file integrity monitoring) |
| ATT&CK | T1078 Valid Accounts (ruled out), T1542 Pre-OS Boot (ruled out) |
| Analyst | Aliou Ba |

## 1. Executive summary

Reviewing staging's alerts revealed two unrelated events. A successful SSH login that lasted only 6 seconds turned out to be the administrator, with his staging key and his own connection. Eight integrity alerts on boot loader files in `/boot/efi` turned out to concern only the files' inode numbers: the content of every file was unchanged. The first explanation, a reboot, was checked and disproved; the leading explanation is the way Linux assigns inode numbers on a FAT partition. No compromise.

## 2. Timeline (UTC)

| Time | Event |
|---|---|
| 2026-11-20 17:48 | Last reboot of staging (still running at investigation time) |
| 2026-11-22 12:12:10 | 8 alerts 550 on `/boot/efi`, changed attribute: inode only |
| 2026-11-22 18:06:40 | Accepted public key for `ubuntu`; session closed 6 seconds later |
| 2026-11-23 12:11 | Both events spotted on the dashboard |
| 2026-11-23 12:13 | Alerts of Nov 22 read from the daily archive |
| 2026-11-23 12:36 | Reboot hypothesis disproved |
| 2026-11-23 12:51 | Login key confirmed by the administrator |

## 3. Indicators

| Type | Value | Notes |
|---|---|---|
| Login source | Administrator's connection (redacted) | Same IPv4 as in SOC-2026-005 |
| Login key | `SHA256:lZmafoq...` | Staging key pair, confirmed as the administrator's |
| Files | `/boot/efi/EFI/BOOT/BOOTX64.EFI`, `fbx64.efi`, `mmx64.efi`, `/boot/efi/EFI/ubuntu/grubx64.efi`, `shimx64.efi`, `mmx64.efi`, `BOOTX64.CSV`, `grub.cfg` | Changed attribute: `inode` only |

## 4. Investigation

### The login

| Question | Check | Result |
|---|---|---|
| Who logged in? | `full_log` of rule 5715 in the Nov 22 archive | User `ubuntu`, key `lZmafoq...`, from the administrator's IPv4 |
| Whose key is it? | Fingerprint of the staging key pair on the administrator's machine | Same fingerprint |
| Why 6 seconds? | Timing | One minute before the administrator logged in to production: most likely the wrong terminal tab, opened then closed |

Staging has no automatic deployment, so a login there cannot be explained by CI/CD. A short session like this one deserved the check.

### The boot files

| Question | Check | Result |
|---|---|---|
| What changed? | `syscheck.path` and `changed_attributes` of rule 550 | 8 files, all in `/boot/efi`, attribute `inode` only |
| Did the content change? | Same alerts | No: the MD5, SHA1 and SHA256 checks did not report a difference, nor did size or permissions |
| Was it a reboot? | `uptime -s`, `last -x reboot` on staging | **No.** Last reboot on Nov 20 at 17:48. Hypothesis disproved. |
| Leading explanation | Filesystem behaviour | `/boot/efi` is a FAT partition, which stores no inode numbers. Linux makes them up when it loads a file and can give a new one after dropping the file from its cache, which a small server under memory pressure does regularly. |

Why this mattered: a modified boot loader is how a bootkit survives reinstalls (T1542). A real change would show `size` and hash changes on `grubx64.efi` or `shimx64.efi`, not an inode alone.

## 5. Impact assessment

None. The login was legitimate and the boot files are byte-for-byte unchanged.

## 6. Response actions

None required.

## 7. Recommendations

| Recommendation | Owner | Status |
|---|---|---|
| Confirm the FAT explanation: memory pressure on staging and whether the same inode-only alerts recur on other days and servers | Analyst | Open |
| Narrow tuning: stop checking the inode under `/boot/efi` only, keeping size, permissions and hashes. A change to the content still alerts. | Analyst | Open, after confirmation |
| Use a distinct prompt or terminal colour per server, to avoid opening the wrong one | Administrator | Suggested |

## 8. Detection review

- Rule 550 did its job: it reported a real attribute change on critical files.
- The alert text ("Integrity checksum changed") is misleading when only the inode changed. The analyst must read `changed_attributes` before drawing conclusions.
- Alerts older than one day are in the daily archives (`/var/ossec/logs/alerts/<year>/<month>/`), not in `alerts.json`. The first search returned nothing for that reason.

## 9. Lessons learned

1. A hypothesis that fits is not a verdict. The reboot explanation looked right and was wrong; checking it took one command.
2. In a file integrity alert, *what* changed matters more than *that* something changed: here, the content was intact.
3. Know where historical data lives before concluding "nothing found".
4. Separate events that are close in time: the login and the file alerts were six hours apart and unrelated.
