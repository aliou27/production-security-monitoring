# SOC-2026-004: "Trojaned" system commands on production

| Field | Value |
|---|---|
| Severity | High at detection, none after verification |
| Classification | False positive |
| Status | Closed: verified with package checksums, rule tuned |
| Affected asset | `zikrou-prod`, system binaries |
| Detection source | Wazuh rootcheck, rule 510 |
| ATT&CK | T1014 Rootkit (ruled out) |
| Analyst | Aliou Ba |

## 1. Executive summary

When the agent first scanned production, rootcheck raised 59 alerts reporting trojaned versions of `ls`, `cat`, `chmod` and other system commands, a classic sign of a rootkit. The investigation showed that production runs Ubuntu 26.04, whose commands come from rust-coreutils, a Rust rewrite that rootcheck's text-pattern heuristic misreads. The package manager's checksums confirmed every binary is exactly as Ubuntu shipped it. No compromise. A narrow exception was added, with file integrity monitoring as the compensating control.

## 2. Timeline (2026-11-22, UTC)

| Time | Event |
|---|---|
| 12:22:48 to 12:23:02 | Rootcheck alerts (rule 510) during the agent's first scan |
| 18:03 | Alerts grouped by type and file |
| 18:07 | Binaries verified against package checksums: verdict reached |
| 18:10 | Exception rule 100400 deployed |

The verdict came hours after detection because other alerts were handled first (SOC-2026-002 and 003). In a staffed SOC, a "trojan" alert would be triaged first.

## 3. Indicators

| Type | Value |
|---|---|
| Files | `/bin` and `/usr/bin`: `cat`, `chgrp`, `chmod`, `chown`, `date`, `echo`, `env`, `ls`, `md5sum`, `uname` |
| Alert title | Trojaned version of file detected |

## 4. Investigation

| Question | Check (read-only) | Result |
|---|---|---|
| What exactly is flagged? | Group alerts by title and file | 1 title, 10 commands, each as `/bin/x` and `/usr/bin/x`, about 3 scans each |
| Why each file twice? | `ls -ld /bin` | `/bin` is a link to `usr/bin`: same file |
| What are these binaries? | `readlink -f /usr/bin/ls`, `dpkg -S` | `/usr/lib/cargo/bin/coreutils/ls`, package `rust-coreutils` |
| Were they modified? | `dpkg --verify rust-coreutils` | No output, exit code 0: all files match the checksums recorded at installation |

Why the heuristic fails: rootcheck searches binaries for text patterns typical of old C trojans. A single Rust binary implementing all the commands naturally contains these patterns. An attacker typically replaces a few targeted commands; here the whole family was flagged at once, which pointed to the platform rather than an intrusion.

## 5. Impact assessment

None. The binaries are genuine.

## 6. Response actions

| Action | Justification |
|---|---|
| Rule 100400 (level 0), child of 510: this title **and** these 10 commands in `/bin` or `/usr/bin` only | A trojan alert on any other file still fires |
| No change on the production server | The fix belongs in the detection, not the system |

## 7. Recommendations

| Recommendation | Owner | Status |
|---|---|---|
| Review rule 100400 when Wazuh updates its trojan signatures for rust-coreutils | Analyst | Open |
| Run `dpkg --verify` on critical packages after any suspected intrusion | Analyst | Procedure |

## 8. Detection review

Silencing an alert on `ls` is a real trade-off, since a rootkit would replace exactly these files. Two controls compensate:

- File integrity monitoring (syscheck) watches `/bin` and `/usr/bin` with hashes, not patterns, and alerts on any change.
- `dpkg --verify` remains the reference check.

## 9. Lessons learned

1. A detection heuristic is tied to the era it was written for. When the platform changes (C to Rust), it can turn into a stream of false positives.
2. Never close a "trojan" alert on a guess, even a very likely one. Prove it with a stronger check.
3. Prioritize by potential impact: this alert deserved to be triaged before the noisier but harmless ones.
