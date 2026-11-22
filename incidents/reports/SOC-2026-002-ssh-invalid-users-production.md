# SOC-2026-002: SSH login attempts with invalid users on production

| Field | Value |
|---|---|
| Severity | Low |
| Classification | True positive, no compromise |
| Status | Closed |
| Affected asset | `zikrou-prod`, SSH service |
| Detection source | Wazuh agent, `sshd` logs, rule 5710 |
| ATT&CK | T1110 Brute Force, T1078 Valid Accounts (checked) |
| Analyst | Aliou Ba |

## 1. Executive summary

Four minutes after the production server joined the SIEM, rule 5710 reported an SSH login attempt with a non-existent user. The investigation found 475 such attempts in 24 hours, from internet bots, none of which could succeed because password authentication is disabled. All 4 successful logins in the period were legitimate: the administrator's key from two connections, and the CI/CD deploy key. No compromise. The investigation confirmed that the CI/CD pipeline connects as root, which is reported as a high-severity finding.

## 2. Timeline (UTC)

| Time | Event |
|---|---|
| Before 2026-11-22 | Continuous SSH attempts from internet bots, not visible: no agent yet |
| 2026-11-21 18:53:57 | Successful login with the CI/CD deploy key, from a Microsoft Azure IP |
| 2026-11-21 18:55:30 | Production API restarted by the deployment of PR #16 |
| 2026-11-22 12:22 | Wazuh agent active on production |
| 2026-11-22 12:26:32 | Rule 5710: login attempt with a non-existent user |
| 2026-11-22 12:30 | Investigation: attempt volume, sources, successful logins, SSH configuration |
| 2026-11-22 12:31 | Deploy key confirmed; incident closed |

Time from alert to verdict: about 5 minutes.

## 3. Indicators

Top sources of invalid-user attempts over 24 hours:

| Source IP | Attempts |
|---|---|
| 195.178.110.30 | 255 |
| 2.57.122.150 | 45 |
| 121.228.250.70 | 31 |
| 2.57.121.25 | 22 |
| 2.57.121.112 | 16 |
| 193.46.255.86 | 16 |
| 193.32.162.84 | 16 |
| 14.103.111.16 | 14 |
| 93.152.221.43 | 10 |
| 92.118.39.77 | 9 |

These are internet-wide scanners, not targeted attackers. They are listed for reference, not as proof of malicious intent toward Zikrou.

## 4. Investigation

The one question that matters: **did any attempt succeed?**

| Check | Command (read-only) | Result |
|---|---|---|
| Volume | `journalctl -u ssh` count of "Invalid user", 24 h | 475 |
| Sources | Same, grouped by IP | 1 IP made 255 attempts; the next 9 made 9 to 45 each |
| Can a password work? | `sshd -T` | `passwordauthentication no`: keys only |
| Successful logins | `journalctl -u ssh` lines "Accepted" | 4, all `publickey` |
| Who logged in? | Key fingerprint and source of each login | 3 with the administrator's key (2 home connections); 1 with a different key from an Azure IP |
| Is the Azure login legitimate? | Key fingerprint against `authorized_keys`; timing against the deployment | Deploy key; GitHub Actions runners run on Azure; the API restarted 1.5 minutes later from that deployment |

## 5. Impact assessment

No unauthorized access. Without a private key, password-guessing bots cannot log in. All successful logins are explained.

## 6. Response actions

No containment needed. Blocking these IPs would bring nothing: they rotate constantly and cannot succeed against key-only authentication.

## 7. Recommendations

| Recommendation | Owner | Status |
|---|---|---|
| Dedicated `deploy` user for GitHub Actions with limited rights, personal `aliou` user with sudo, then `PermitRootLogin no` | Production team | Open (finding F2, high) |
| Rate-limit new SSH connections (for example with UFW `limit` or a cloud firewall rule) to reduce noise | Production team | Open |
| Keep the deploy key's fingerprint documented, so the next investigation takes seconds | Production team | Open |

## 8. Detection review

- Rule 5710 (level 5) is noise on a public SSH port: hundreds per day, never actionable on its own when passwords are disabled.
- The alerts that matter are a **successful** login from an unknown source and a success after many failures. These will be built and tested in the SSH detection phase.

## 9. Lessons learned

1. The SIEM did not create this traffic, it revealed it: it existed before, invisible.
2. Answer the question that matters (did anything succeed?) instead of reacting to volume.
3. Correlating two independent sources (SSH logs and the production team's deployment timeline) turned "very probably the CI" into a proven verdict.
4. Investigating legitimate activity surfaced a real risk: the CI/CD pipeline holds root access to production.
