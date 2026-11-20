# 03: Private network with WireGuard

**Date:** 2026-11-20
**Goal:** connect the monitored servers to the Wazuh server through an encrypted private network, so that no Wazuh port is ever exposed to the internet.

## 1. Why a private network

Wazuh agents send their events to the manager on TCP 1514 and enroll on TCP 1515. Exposing these ports to the internet would let anyone probe the SIEM, try to enroll fake agents, or attack the manager directly.

Instead, every monitored server joins a WireGuard tunnel, and the Wazuh ports are only reachable **inside** that tunnel.

## 2. Design

```mermaid
flowchart LR
    S["Zikrou staging<br/>AWS, 10.10.0.4"]
    N["Need Academy<br/>Hetzner, 10.10.0.3"]
    Z["Zikrou API<br/>Hetzner, 10.10.0.2"]
    H["Wazuh server (hub)<br/>Azure, 10.10.0.1<br/>UDP 51820"]
    S -- "encrypted tunnel" --> H
    N -. "planned" .-> H
    Z -. "planned" .-> H
```

**Hub and spoke.** The Wazuh server is the hub. Each monitored server is a spoke that connects to the hub only.

| Host | Tunnel IP | Status |
|---|---|---|
| Wazuh server (hub) | 10.10.0.1 | Up |
| Zikrou API | 10.10.0.2 | Planned |
| Need Academy | 10.10.0.3 | Planned |
| Zikrou staging | 10.10.0.4 | **Connected** |

## 3. Security properties

| Property | How it is achieved |
|---|---|
| **Strong cryptography** | Each machine has a Curve25519 key pair. Only public keys are exchanged. |
| **No identity spoofing** | WireGuard's "cryptokey routing": each peer is bound to one key and one tunnel IP (`AllowedIPs = 10.10.0.4/32`). A packet claiming to be `10.10.0.4` but not encrypted with that peer's key is dropped. |
| **Least privilege between servers** | Each spoke has `AllowedIPs = 10.10.0.1/32`: it can reach the hub only. A compromised spoke cannot use the tunnel to reach another monitored server. Only SIEM traffic goes through the tunnel; the application's normal traffic is untouched. |
| **Invisible service** | WireGuard never answers a packet that is not signed by a known key. A port scan of UDP 51820 sees nothing. |
| **Wazuh ports bound to the tunnel** | UFW allows TCP 1514 and 1515 **only on the `wg0` interface**. Even if the cloud firewall were opened by mistake, the agent ports would remain unreachable from the internet. |
| **Private keys never in config files** | Keys are generated with `umask 077` (readable by root only from the moment they are written) and loaded at startup through `PostUp = wg set %i private-key <file>`. The config files contain no secret and are versioned in this repository. |
| **No accidental key leak** | Peers are added to the hub with `wg set` (live) plus an append to `wg0.conf` (persistent). `wg-quick save` is deliberately avoided because it would write the hub's private key into the config file. |
| **NAT resilience** | `PersistentKeepalive = 25` on the spoke keeps the tunnel open through cloud NAT, which would otherwise forget an idle connection. |

## 4. Firewall changes on the hub

Two layers, both updated:

- **Azure NSG:** new inbound rule `Allow-WireGuard`, UDP 51820, priority 310.
- **UFW:** `51820/udp` allowed, and `1514,1515/tcp` allowed **on wg0 only**.

See [`configs/ufw/wazuh-server-rules.sh`](../configs/ufw/wazuh-server-rules.sh).

![UFW rules on the hub](images/03/hub-ufw-rules.png)

The line `1514,1515/tcp on wg0` is the key result: the agent ports exist, but only inside the tunnel.

## 5. Steps

### Hub

WireGuard installed, key pair generated, interface `wg0` started and enabled at boot.

See [`configs/wireguard/hub-wg0.conf`](../configs/wireguard/hub-wg0.conf).

![WireGuard hub up](images/03/hub-wireguard-up.png)

### First spoke: Zikrou staging

Staging was chosen first because a mistake there has no impact on users.

**Before installing anything, the server was patched.** The login banner showed 34 pending updates and `System restart required` (a kernel update). After `apt full-upgrade` and a reboot, the kernel moved from `7.0.0-1014-aws` to `7.0.0-1018-aws` with 0 pending updates. A machine joining the SOC should not start with known unpatched flaws.

WireGuard was then installed and configured on the spoke. See [`configs/wireguard/spoke-staging-wg0.conf`](../configs/wireguard/spoke-staging-wg0.conf).

### Registering the spoke on the hub

The spoke's public key was added to the hub, live and in the config file:

![Staging peer added on the hub](images/03/hub-add-staging-peer.png)

This screenshot was taken right after the peer was added, before the first handshake, which is why no handshake line appears yet.

## 6. Verification

From staging, through the tunnel:

![Ping and wg show from staging](images/03/staging-ping-and-wg-show.png)

- `ping 10.10.0.1`: 3 packets sent, 3 received, 0% loss, about 48 ms (Stockholm to Spain).
- `latest handshake: 10 seconds ago`: the encrypted session is established.
- `persistent keepalive: every 25 seconds`: the tunnel will stay open while idle.

The hub's public IP is masked in the screenshot.

## 7. Observations on the staging server

Reading the login banner like an analyst:

| Observation | Meaning | Action |
|---|---|---|
| 34 updates, restart required | Server behind on patches | Patched and rebooted before joining the SOC |
| Disk at 72% of 18 GB | Little headroom; Docker images are a likely cause | Old kernel packages removed; monitor disk usage |
| RAM at 64%, swap in use | Small, busy instance | The Wazuh agent is light enough, but resource use will be checked after install |
| Last logins from two different IPs | Both were my own connections, from different networks | Confirms my home IP is dynamic, so SSH cannot simply be restricted to one IP |

## 8. Residual risks

| Risk | Current state | Next improvement |
|---|---|---|
| NSG rule for UDP 51820 open to any source | WireGuard ignores unknown peers | Restrict the source to the spokes' fixed IPs |
| Staging's public IP may change on stop/start | Not an issue for the tunnel (the spoke initiates) | Attach an Elastic IP before restricting the NSG |
| The hub is a single point of failure | Agents buffer events while disconnected | Acceptable for a lab; document recovery steps |
| No key rotation yet | Keys are new | Define a rotation procedure |

## 9. Next step

Install the Wazuh agent on staging, enroll it with the manager at `10.10.0.1` through the tunnel, and confirm it appears as `active` in the dashboard.
