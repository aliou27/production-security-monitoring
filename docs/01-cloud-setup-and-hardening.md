# 01: Cloud setup and server hardening

**Date:** 2026-11-19
**Goal:** deploy a dedicated server for the Wazuh SIEM and harden it before installing anything on it.

A SIEM holds the evidence of every incident. If it is compromised, the attacker can read the detection rules and delete the logs. The SIEM server therefore has to be the best-protected machine in the lab, starting from its first boot.

## 1. Hosting decision

The Wazuh central components (indexer, server, dashboard) need about 8 GB of RAM. Wazuh's official sizing for 1 to 25 agents is 4 vCPU, 8 GiB of RAM and 50 GB of storage.

| Option | Result |
|---|---|
| A production server (Zikrou, Need Academy) | **Rejected.** It would compete with real users for resources, and a compromised server would give the attacker control of the SIEM. |
| Oracle Cloud Always Free (2 Arm cores, 12 GB) | **Not possible.** The verification card was refused as a prepaid card. |
| A new AWS account | **Rejected.** Free-plan accounts close after 6 months or when credits run out, which would be in the middle of my internship. Opening extra accounts to collect free-tier credits also goes against AWS's terms. |
| **Azure for Students** | **Chosen.** $100 of credit valid 12 months, renewable while I am a student, no card required. Spending stops when the credit runs out, so there is no risk of unexpected charges. |

## 2. Virtual machine

| Setting | Value | Reason |
|---|---|---|
| Region | Spain Central | Close to Senegal and to the Hetzner servers in Germany. Available for the student subscription. |
| Image | Ubuntu Server 24.04 LTS x64 | Officially supported by Wazuh. |
| Size | Standard_B2s_v2 (2 vCPU, 8 GiB) | Meets the 8 GiB RAM recommendation. B2ms was not available in the region. B-series VMs are burstable: they accumulate CPU credits while idle, which fits a small deployment with low, irregular load. 4 GiB sizes were rejected because the indexer would run out of memory. |
| Spot pricing | Off | Spot VMs can be evicted at any moment. Not acceptable for a SIEM. |
| OS disk | 64 GiB Standard SSD (E6) | Enough for 30-day retention with a handful of agents. A managed disk can be enlarged but never shrunk. |
| Authentication | SSH key only, Ed25519 | No password exists that could be brute-forced. Ed25519 is the modern default: short keys, fast, strong. |
| Resource group | `rg-soc-lab` | Groups every resource of the project so cost can be tracked and everything deleted at once. |

## 3. Cost controls

The budget is $100 for 12 months, so the project only pays for what runs.

| Item | Billing | Estimated per month |
|---|---|---|
| VM (about $0.09/hour) | Only while running. About 2 hours a day. | About $5.50 |
| 64 GiB Standard SSD | Always, even when the VM is stopped | About $5 |
| Static public IP | Always | About $3.50 |
| **Total** | | **About $14** |

Controls put in place:

- **Monthly budget of $15** in Cost Management, with alerts at 50% actual, 100% actual and 100% forecasted spend. The forecasted alert warns before the money is spent.
- **Auto-shutdown at 23:00 UTC** on the VM, in case I forget to stop it.
- **Habit:** stop the VM from the portal after each session and check that it shows **Stopped (deallocated)**. A VM shut down from inside Linux is still billed.

## 4. Hardening

The server is protected by three independent layers. If one is misconfigured, the others still hold.

### Layer 1: cloud firewall (Azure NSG)

Only TCP 22 (SSH) is allowed inbound. Everything else is dropped before it reaches the VM.

### Layer 2: host firewall (UFW)

The same policy, enforced on the server itself: deny all incoming traffic, allow outgoing, allow TCP 22.

See [`configs/ufw/wazuh-server-rules.sh`](../configs/ufw/wazuh-server-rules.sh).

```
Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
22/tcp                     ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
```

### Layer 3: SSH hardening

File: `/etc/ssh/sshd_config.d/01-hardening.conf`, see [`configs/ssh/01-hardening.conf`](../configs/ssh/01-hardening.conf).

| Directive | Effect |
|---|---|
| `PermitRootLogin no` | `root` is the first account bots try. It is refused outright. |
| `PasswordAuthentication no` | Passwords are not accepted at all. |
| `KbdInteractiveAuthentication no` | Closes the keyboard-interactive path, which can otherwise act as a password prompt. |
| `PubkeyAuthentication yes` | Key-based login is the only method. |
| `MaxAuthTries 3` | A connection is cut after 3 failed attempts. |
| `LoginGraceTime 30` | A connection that has not authenticated within 30 seconds is closed. |
| `X11Forwarding no` | Disables a feature a server does not need. Less attack surface. |
| `AllowUsers aliou` | Only this account may log in over SSH, even with a valid key for another user. |

**Detail that matters:** when OpenSSH finds the same setting in several files, the first value it reads wins. Files in `sshd_config.d/` are read in alphabetical order, so this file is named `01-` to be read before Azure's `50-cloud-init.conf`.

The configuration was validated with `sshd -t` before reloading, so a syntax error could not lock me out. A second SSH session was then opened to confirm access still worked before closing the first one.

What an attacker without the key sees:

```
$ ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password aliou@<WAZUH_PUBLIC_IP>
Permission denied (publickey).
```

There is no password prompt to brute-force. Every attempt is still logged in `/var/log/auth.log`, which will become detection data once Wazuh is running.

### Key handling

- The private key is stored only in `~/.ssh/` on my laptop (permissions `400`, folder `700`) and backed up in a password manager.
- It is never committed, shared or uploaded. The repository's `.gitignore` excludes `*.pem` and `*.key`.

### Patching and OS version

- Full upgrade (`apt full-upgrade`) and reboot before anything else was installed.
- `unattended-upgrades` confirmed active, so security patches install automatically.
- The OS stays on **Ubuntu 24.04 LTS** even though 26.04 is offered: Wazuh's supported list stops at 24.04, and a SIEM should run on a supported platform.

### Time

The system clock is in UTC and synchronized. A SOC with an incorrect clock produces wrong incident timelines, and logs from different servers cannot be correlated.

## 5. Verification

```
$ sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|allowusers'
permitrootlogin no
passwordauthentication no
allowusers aliou

$ df -h /
Filesystem      Size  Used Avail Use% Mounted on
/dev/root        61G  2.1G   59G   4% /
```

The settings were checked again after a full VM restart.

## 6. ATT&CK coverage

| Technique | How this phase mitigates it |
|---|---|
| T1110 Brute Force | No password authentication exists. Root login is disabled. |
| T1021.004 Remote Services: SSH | Only one named user with a key can log in. |
| T1078 Valid Accounts | No default or shared accounts are allowed over SSH. |
| T1190 Exploit Public-Facing Application | Only one service is exposed. Security updates install automatically. |

## 7. Issues met and lessons learned

1. **The OS disk was created at 30 GB instead of 64 GB.** The size set in the creation wizard did not apply. It was caught by checking `df -h /` on first login, before installing anything. Fix: stop the VM, resize the managed disk in the portal, start the VM. Ubuntu grew the partition automatically at boot. **Lesson:** verify what was actually deployed, not what was requested.
2. **Hardening commands were pasted into the wrong terminal.** A dropped SSH session to another server left a terminal on my laptop, and the commands ran there. They failed at the `sudo` password prompt, so nothing changed. Had they run on the other server, `AllowUsers aliou` would have locked out that server's deploy user. **Lesson:** check the prompt (`user@host`) before every command, and treat hardening configs as host-specific.

## 8. Residual risks

| Risk | Current mitigation | Possible improvement |
|---|---|---|
| SSH open to the whole internet | Key-only authentication, 3 attempts per connection | Restrict the NSG rule to my IP. My home IP is dynamic, so this would need updating often. |
| Private key stolen from my laptop | Key never leaves the laptop and password manager | Passphrase on the key, or a hardware key |
| Pre-authentication flaw in OpenSSH (for example regreSSHion, CVE-2024-6387, in 2024) | Automatic security updates | Monitor patch status with Wazuh's vulnerability detection |
| Loss of the single SIEM server | Configs and rules are versioned in this repository | Periodic snapshots of the disk |

## 9. Next step

Install the Wazuh central components with the official installation assistant (run inside `tmux` so a dropped connection cannot break it), then access the dashboard through an SSH tunnel.
