# SOC-2026-005: Successful SSH login minutes after a brute-force burst

| Field | Value |
|---|---|
| Severity | High at detection, none after verification |
| Classification | Benign positive: the login was the administrator's |
| Status | Closed |
| Affected asset | `zikrou-prod`, SSH and AppArmor |
| Detection source | Rules 5712, 5758, 5710 (brute force), 5715 and 5501 (successful login), 52002 (AppArmor) |
| ATT&CK | T1110 Brute Force, T1078 Valid Accounts (ruled out) |
| Analyst | Aliou Ba |

## 1. Executive summary

A brute-force burst against SSH (rule 5712, level 10) was followed five minutes later by a successful root login and, one second after it, six AppArmor denials. Read together, the sequence looked like the most dangerous scenario: an attacker who gets in, then gets blocked by the system. The investigation showed three unrelated facts: the brute force came from two internet scanners and failed; the login was the administrator's, with his key and his own connection; and the AppArmor denials came from the `who` command run by Ubuntu's login banner. No compromise.

## 2. Timeline (2026-11-22, UTC)

| Time | Event |
|---|---|
| 18:02:37 | SSH brute-force burst with non-existent users: rules 5710, 5758, 2501, then 5712 (level 10) |
| 18:07:18 | Accepted public key for root (rule 5715), session opened (5501) |
| 18:07:19 | Six AppArmor denials (rule 52002) |
| 18:23 | Sequence spotted on the dashboard; investigation starts |
| 18:25 | Login source and key verified |
| 18:26 | Administrator's public IPv4 confirmed |
| 18:27 | AppArmor denials explained; incident closed |

Time from review to verdict: about 4 minutes.

## 3. Indicators

| Type | Value | Notes |
|---|---|---|
| Brute-force source | 121.228.250.70 | 4 alerts 5712; already among the top sources in SOC-2026-002 |
| Brute-force source | 88.96.39.28 | 1 alert 5712 |
| Successful login source | Administrator's connection (redacted) | Confirmed by the administrator |
| Key | `SHA256:TEBCj9el6k...` | Administrator's key, used for all his previous logins |
| AppArmor | profile `who`, files `/etc/passwd` and `/etc/nsswitch.conf`, read denied | |

## 4. Investigation

Three questions, each answered with a separate check. Everything was read from the SIEM; nothing was run on production.

| Question | Check | Result |
|---|---|---|
| Who logged in at 18:07? | `full_log` of rule 5715 | Root, public key `TEBCj...` (the administrator's), from a Senegalese IPv4 |
| Is that IP the administrator's? | `curl -4 ifconfig.me` from his machine | Same IPv4. (A first attempt returned an IPv6 address; the check had to force IPv4, the protocol of the SSH login.) |
| Is it linked to the brute force? | Source IPs of rule 5712 | Two different scanner IPs, neither one the login's. Password authentication is disabled, so they could not succeed. |
| What did AppArmor block? | `full_log` of rule 52002, parsed as JSON | Process `who`, AppArmor profile `who`, read of `/etc/passwd` and `/etc/nsswitch.conf` denied, as root, one second after the login |

**Why `who` runs at login (most likely explanation).** Ubuntu's login banner shows system information, including the number of logged-in users, which it gets from `who`. On Ubuntu 26.04, `who` runs under an AppArmor profile that does not allow reading the user database, so the read is denied. The command fails silently, and the banner simply shows less information.

**Confirmed on a second server (2026-11-23):** when logging in to the Need Academy server, also on Ubuntu 26.04, the banner said "Users logged in: 0" during an active session: `who` fails there the same way.

An attacker's tool would not normally run as `who` within one second of an interactive login and touch only these two files. Combined with the verified key and IP, the explanation is consistent.

## 5. Impact assessment

None. The brute force failed, the login was legitimate, and the AppArmor denials only affected a line of the login banner.

## 6. Response actions

None required.

## 7. Recommendations

| Recommendation | Owner | Status |
|---|---|---|
| Disable root SSH login after creating personal and deploy users (finding F2). A login as a named user would have made this verdict immediate. | Production team | Open |
| Keep a list of the administrators' key fingerprints, so a login can be attributed in seconds | Analyst | Open |

## 8. Detection review

- The built-in rules detected each step, but separately. Wazuh's correlation for "failures followed by success" only links events **from the same source IP**. A successful login from a **different** IP shortly after a brute force raises no combined alert. This case needs a human to connect the dots.
- Rule 52002 (AppArmor denied, level 3) will repeat at every administrator login. It stays visible for now: AppArmor denials are rare and valuable on a production server.

## 9. Lessons learned

1. Alerts that are close in time are not necessarily related. Each link must be proven: here, three separate checks for three events.
2. A key fingerprint is stronger evidence than an IP address, which changes with the network.
3. When checking an IP, match the protocol: the machine had both IPv4 and IPv6 addresses.
4. Root logins make attribution harder. Named accounts would have answered "who?" directly.
