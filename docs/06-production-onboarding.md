# 06: Production onboarding and first triage

**Date:** 2026-11-22
**Goal:** bring the Zikrou production server into the SOC: private tunnel, Wazuh agent, web logs. Production is only observed here, never attacked.

**Result:** production reports to Wazuh through WireGuard. Four minutes after the agent started, the SIEM raised its first real alert from the internet, which was triaged and closed.

## 1. What changes on production

Only two background services are added: WireGuard and the Wazuh agent. The application, Docker, the database and Caddy are not modified. The production team was informed.

| Item | Value |
|---|---|
| Server | Zikrou production (Hetzner, Ubuntu 26.04) |
| Tunnel IP | `10.10.0.2` |
| Agent | `zikrou-prod`, ID 002, version 4.14.10 |
| New inbound port on production | **None** |

## 2. WireGuard: production becomes a spoke

Same design as staging ([report 03](03-wireguard-network.md)):

- **The spoke opens the connection** to the hub on UDP 51820 and keeps it alive every 25 seconds. Production only sends outbound traffic, and the firewall lets the replies back, so no port is opened on production.
- `AllowedIPs = 10.10.0.1/32` on production: the tunnel carries SIEM traffic only. A compromised production server cannot use it to reach staging.
- On the hub, production is bound to its own key and to `10.10.0.2/32` only.

![Tunnel up on production](images/06/prod-wireguard-up.png)

### Mistake and correction

The first attempt declared **the hub's own public key** as the production peer on the hub. WireGuard silently ignores a peer that has the interface's own key, so `wg show` listed staging only, and the wrong `[Peer]` block was written in the hub's config file.

Correction: remove the wrong peer from the running interface, then rewrite the hub's whole `wg0.conf` with both real peers, so staging was never interrupted.

**Rule to remember:** each side's config contains the **other side's** public key. The hub's key goes in the spoke's file, and the spoke's key goes in the hub's file.

## 3. Wazuh agent

| Choice | Reason |
|---|---|
| Agent version pinned to the manager's (`4.14.10`), then `apt-mark hold` | An agent newer than the manager is not supported. A routine `apt upgrade` must never break that match. |
| Manager address `10.10.0.1` | Agent traffic goes through the tunnel, never the internet. |
| Enrollment password given through `read -s` | The password never appears on screen nor in the shell history. |
| Signed Wazuh APT repository | Packages verified against Wazuh's GPG key. |

The agent is active, with its tunnel IP:

![Staging and production agents active](images/06/agents-staging-and-prod-active.png)

And the connection really goes through the tunnel (`10.10.0.2` to `10.10.0.1:1514`):

![Agent connection through the tunnel](images/06/prod-agent-through-tunnel.png)

## 4. First alert from production: triage

![First production events](images/06/prod-first-events.png)

Four minutes after the agent started, rule **5710** fired: *sshd: attempt to login using a non-existent user*. The login did not come from me, so it was triaged.

**Question to answer:** did any SSH attempt succeed?

| Check | Result |
|---|---|
| Invalid-user attempts in 24 hours | **475** |
| Top source | One IP alone made 255 attempts; the next 9 sources made between 9 and 45 each. |
| Password authentication | `passwordauthentication no`: without a private key, none of these attempts can succeed. |
| Successful logins in 24 hours | 4, all with SSH keys |

The successful logins:

| Source | Key | Verdict |
|---|---|---|
| My connection (2 IPs, 2 days) | My key | Legitimate |
| A Microsoft Azure IP in the US | A different key | **Checked:** the fingerprint matches the CI/CD deploy key, and a GitHub Actions deploy ran at that exact minute. GitHub Actions runners are hosted on Azure. Legitimate. |

**Verdict:** true positive (real attempts), no impact. Closed as internet background noise.

**What the triage revealed:** the CI/CD pipeline connects to production **as root**. A leaked deploy key would give full control of the server. This confirms an existing finding: create a dedicated `deploy` user with limited rights and set `PermitRootLogin no`. Reported to the production team.

**Lesson:** this traffic was there before; it was simply invisible. The SIEM did not create the noise, it revealed it. The value of the analyst is to answer the one question that matters (did anything succeed?) instead of reacting to the volume.

## 5. Production web logs

Production already writes Caddy access logs in JSON, with the same fields as staging. The detection rules written in [report 04](04-web-logs-and-custom-detections.md) apply as they are, with no change.

| Site | Log file |
|---|---|
| API | `/var/log/caddy/api.zikrou.com.log` |
| Web app (Flutter) | `/var/log/caddy/app.zikrou.com.log` |
| Admin panel | `/var/log/caddy/admin.zikrou.com.log` |

Configuration: [`configs/wazuh/agent/prod-localfile-caddy.xml`](../configs/wazuh/agent/prod-localfile-caddy.xml). The agent's config was backed up before the change.

![Agent reading the three Caddy logs](images/06/prod-caddy-logcollector.png)

**Volume.** Production writes about 200 MB of API access logs per day. The agent reads only new lines from the moment it starts, so the existing logs are not replayed. Only lines matching a rule become alerts. Rule 100201 (every 4xx response, level 3) may become noisy with real users, because expired sessions produce ordinary 401s. It will be measured over a few days and tuned if needed.

**Validation without attacking production.** No test attack is sent to production. Internet bots probe `/.env`, `/.git/config` and admin paths on every public site; their requests are expected to trigger rule 100210 on their own.

## 6. Rootcheck events

When the agent started, the rootkit scan (rootcheck) produced 15 alerts with rule 510. They will be triaged separately: on servers running Docker, these are often false positives caused by container files.

## 7. Next steps

- Measure the volume of web alerts from production after a few days, then tune rule 100201.
- Triage the rootcheck alerts.
- Deploy the application security audit logs to production (see [report 05](05-api-security-logs-and-reset-code-vulnerability.md)), after the production team ships the log cleanup.
