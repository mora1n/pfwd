# pfwd

VPS-friendly port forwarding with **nftables**, domain targets, traffic stats,
and practical kernel tuning helpers.

`pfwd` is a single Bash script for quickly creating and maintaining DNAT
forwarding rules. It keeps the rule state in one local file, rebuilds nftables
from that state, and provides an interactive menu for common operations.

## Overview

- nftables DNAT forwarding with software flowtable fast path where supported.
- Simple shortcut syntax: `pfwd 8080 1.2.3.4 80`.
- TCP, UDP, dual-stack, port ranges, port mappings, comments, MSS, and SNAT.
- Domain forwarding rules that re-resolve on refresh/start/maintenance.
- Rule-level traffic statistics from conntrack state.
- Import/export with JSON backups.
- Optional kernel optimization profiles for VPS forwarding workloads.

## Install

```bash
curl -fsSL <url>/pfwd.sh -o /usr/local/bin/pfwd.sh
chmod +x /usr/local/bin/pfwd.sh

# First root run installs the shortcut: /usr/local/bin/pfwd
/usr/local/bin/pfwd.sh
```

After that, use:

```bash
pfwd
```

## Quick Start

```bash
# Forward local 8080 to 1.2.3.4:8080
pfwd 8080 1.2.3.4

# Forward local 8080 to 1.2.3.4:80
pfwd 8080 1.2.3.4 80

# Forward multiple ports
pfwd 80,443 1.2.3.4

# Forward a domain target
pfwd 443 example.com

# Replace an existing rule for the same port/protocol/IP family
pfwd 8080 1.2.3.4 --replace

# Open the interactive menu
pfwd
```

## Common Commands

| Task | Command |
|------|---------|
| Add full-syntax rule | `pfwd -m nft -t 1.2.3.4 80,443` |
| Add TCP + UDP | `pfwd -m nft -t 1.2.3.4 --both 443` |
| Add IPv4-only rule | `pfwd -m nft -4 -t 1.2.3.4 443` |
| Map local to remote port | `pfwd 33389 1.2.3.4 3389` |
| List rules | `pfwd list` |
| Filter displayed rules | `pfwd list -f 8080` |
| Delete rule | `pfwd del -m nft 8080` |
| Rebuild from saved state | `pfwd refresh` |
| Start / stop forwarding | `pfwd start` / `pfwd stop` |
| Show status | `pfwd status` |
| Run diagnostics | `pfwd doctor` |
| Probe TCP backends | `pfwd doctor --tcp-probe` |
| Show traffic totals | `pfwd stats` |
| Show traffic rate | `pfwd stats --rate` |
| Export backup | `pfwd export backup.json` |
| Import backup | `pfwd import backup.json` |
| Uninstall nft state | `pfwd uninstall nft` |

Run `pfwd help` for the full CLI reference.

## Port Formats

| Format | Example |
|--------|---------|
| Single port | `80` |
| Multiple ports | `80,443` |
| Port range | `8080-8090` |
| Port mapping | `33389:3389` |
| Range mapping | `8080-8090:3080-3090` |
| Mixed | `80,443,8080-8090,33389:3389` |

## Advanced Usage

```bash
# Domain rules stay as hostnames in state and are re-resolved on refresh/start.
pfwd domains list
pfwd domains update
pfwd domains interval 5m
pfwd domains status

# MSS / SNAT options
pfwd -m nft -t 10.0.0.2 --mss-clamp 443
pfwd -m nft -4 -t 10.0.0.2 --snat-source 192.168.1.2 9443:443

# Kernel tuning profiles
pfwd optimize
pfwd optimize lowmem
pfwd optimize relay
pfwd optimize balanced --nic-steering
pfwd optimize balanced --egress-rate 100mbit --ingress-rate 100mbit --tc-iface eth0
```

Notes:

- Saved forwarding rules live in `/var/lib/pfwd/forward-rules.tsv`.
- `refresh`, `start`, and periodic maintenance rebuild nftables from saved state.
- `pfwd.service` restores saved forwarding rules after reboot while active rules exist.
- The maintenance timer starts automatically only after forwarding rules are active.
- Domain rules do not use a separate database or daemon.
- Dynamic domain commands ignore localhost-style static hostnames.
- Traffic stats are collected out of band from conntrack, not nft hot-path counters.
- Import/export uses the current JSON v3 schema with `forward_rules`.
- Current versions only read the active runtime state file.
- Hardware NIC offload is not required; the default target is portable VPS/cloud forwarding.

## File Locations

| File | Purpose |
|------|---------|
| `/usr/local/bin/pfwd.sh` | installed script |
| `/usr/local/bin/pfwd` | shortcut command |
| `/var/lib/pfwd/` | rules and traffic state |
| `/etc/systemd/system/pfwd.service` / `pfwd.timer` | boot restore and maintenance units |
| `/etc/sysctl.d/99-pfwd.conf` | pfwd-managed sysctl tuning |

## Requirements

- Linux with root access.
- `nftables` (`nft`)
- `iproute2` / `iproute` (`ip`)
- `jq` for import/export.
- `conntrack` / `conntrack-tools` recommended for traffic stats.
- Linux kernel >= 4.16 recommended for flowtable acceleration.

Package examples:

| Distro | Command |
|--------|---------|
| Debian / Ubuntu | `apt-get install -y nftables iproute2 jq conntrack` |
| Fedora / Rocky / Alma / Amazon Linux / Oracle Linux | `dnf install -y nftables iproute jq conntrack-tools` |
| CentOS / RHEL | `yum install -y nftables iproute jq conntrack-tools` |
| openSUSE / SUSE | `zypper install -y nftables iproute2 jq conntrack-tools` |
| Arch Linux | `pacman -Sy --needed nftables iproute2 jq conntrack-tools` |
| Alpine | `apk add nftables iproute2 jq conntrack-tools` |

## License

MIT
