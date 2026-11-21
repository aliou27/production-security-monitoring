# SOC Homelab

A cloud-based Security Operations Center built from scratch to practice and demonstrate SOC analyst skills: log collection, detection engineering, alert triage and incident response.

The SIEM monitors two real production web applications that I build and run, plus lab machines that I attack on purpose to produce detections.

## Architecture

```mermaid
flowchart TB
    subgraph prod["Production servers (watch only)"]
        Z["Zikrou API<br/>Hetzner"]
        N["Need Academy<br/>Hetzner"]
    end
    subgraph lab["Lab targets (attacks allowed)"]
        S["Zikrou staging<br/>AWS EC2"]
        W["Windows lab VM<br/>Azure + Sysmon"]
    end
    subgraph azure["Azure for Students, Spain Central"]
        WZ["Wazuh server<br/>manager + indexer + dashboard"]
    end
    A["Analyst laptop"]

    Z -- "WireGuard" --> WZ
    N -- "WireGuard" --> WZ
    S -- "WireGuard" --> WZ
    W -- "Azure VNet, private IP" --> WZ
    A -- "SSH tunnel" --> WZ
```

Design principles:

- **The SIEM never runs on a machine it monitors.** If a production server is compromised, the attacker cannot erase the evidence.
- **No SIEM port is exposed to the internet.** Agents reach the server through WireGuard, and the dashboard is only reachable through an SSH tunnel.
- **Production is observed, never attacked.** Attack simulations only target dedicated lab machines.
- **Defense in depth.** Cloud firewall, host firewall and hardened SSH are independent layers.

## Stack

| Layer | Tool |
|---|---|
| SIEM / XDR | Wazuh 4.14 (single-node) |
| Cloud | Microsoft Azure (Azure for Students) |
| OS | Ubuntu Server 24.04 LTS |
| Agent transport | WireGuard (hub and spoke) |
| Windows telemetry | Sysmon |
| Attack simulation | Atomic Red Team, Nmap, Hydra |
| Frameworks | MITRE ATT&CK, Sigma |

## Progress

| # | Phase | Status | Write-up |
|---|---|---|---|
| 1 | Cloud setup and server hardening | Done | [docs/01-cloud-setup-and-hardening.md](docs/01-cloud-setup-and-hardening.md) |
| 2 | Wazuh installation | Done | [docs/02-wazuh-installation.md](docs/02-wazuh-installation.md) |
| 3 | WireGuard network and agent enrollment | In progress: hub up, first agent (staging) active | [docs/03-wireguard-network.md](docs/03-wireguard-network.md) |
| 4 | Web logs and custom detections (Caddy) | Done on staging | [docs/04-web-logs-and-custom-detections.md](docs/04-web-logs-and-custom-detections.md) |
| 5 | API security logs and auth detections, critical vulnerability found and fixed | Done on staging | [docs/05-api-security-logs-and-reset-code-vulnerability.md](docs/05-api-security-logs-and-reset-code-vulnerability.md) |
| 4b | Windows lab with Sysmon | Planned | |
| 6 | Baseline: one week of normal traffic | Planned | |
| 7 | First detection: SSH brute force (T1110) | Planned | |
| 8 | Attack and detect cycles, incident reports | Planned | |
| 9 | Alert enrichment and triage automation | Planned | |

## Repository layout

```
docs/          one write-up per phase
docs/images/   screenshots, one folder per phase
configs/       configuration files applied to the servers (no secrets)
```

## Security note

This repository contains no secrets, keys, passwords or public IP addresses. Placeholders such as `<WAZUH_PUBLIC_IP>` are used instead.
