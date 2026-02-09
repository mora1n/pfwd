# pfwd - Port Forwarding Tool

A streamlined port forwarding management tool supporting **nftables** (with flowtable fast path acceleration) and **realm** (userspace Rust proxy).

## Features

- **nftables forwarding** with flowtable fast path offloading for minimal CPU overhead
- **realm forwarding** for domain-based targets and userspace proxying
- **Flexible port syntax** — single ports, ranges, mappings, mixed formats
- **Manual IPv4/IPv6 control** (`-4`, `-6`, `-46`)
- **CLI + Interactive menu** interface
- **Traffic statistics** via nftables counters
- **Backup/Import/Export** in JSON format
- **Boot persistence** via systemd services
- **Enhanced kernel optimization** (BBR, TCP tuning, conntrack, flowtable)
- **Flowtable diagnostics** — kernel version detection, automatic module loading, actionable fix suggestions
- **Duplicate port detection** — prevents adding duplicate nftables rules or realm endpoints for the same port
- **Auto-persist nf_flow_table** — automatically writes `/etc/modules-load.d/nf_flow_table.conf` after loading the module

## Quick Start

```bash
# Install
curl -fsSL <url>/pfwd.sh -o /usr/local/bin/pfwd && chmod +x /usr/local/bin/pfwd

# Or just copy the script
cp pfwd.sh /usr/local/bin/pfwd

# Interactive mode
pfwd

# CLI examples (new syntax with -t)
pfwd -m nft -t 1.2.3.4 80,443,8080-8090
pfwd -m realm -t example.com 80,443 -c "web"

# CLI examples (legacy syntax)
pfwd -m nft -4 --both 10280:1.2.3.4:10280
pfwd -m realm -46 10280:example.com:10280
```

## Usage

```
pfwd [command] [options] [rules...]

Commands:
  (none/add)  Add forwarding rules (default)
  del         Delete forwarding rules
  list        List all forwarding rules
  start       Start forwarding (nft / realm / all)
  stop        Stop forwarding (nft / realm / all)
  restart     Restart forwarding (nft / realm / all)
  stats       Traffic statistics
  export      Export config to JSON
  import      Import config from JSON
  install     Install realm binary
  uninstall   Uninstall (realm / nftables / all)
  optimize    Run kernel optimization only
  help        Show help
```

### Add Rules

**New syntax** (recommended):

```bash
pfwd -m nft|realm -t <target> [options] <ports>
```

**Legacy syntax**:

```bash
pfwd -m nft|realm [options] local_port:target:target_port[,...]
```

| Option | Description |
|--------|-------------|
| `-m, --method` | `nft` or `realm` (required) |
| `-t, --target` | Target IP or domain (enables new syntax) |
| `-4` | IPv4 only |
| `-6` | IPv6 only |
| `-46` | Dual-stack (default) |
| `--tcp` | TCP only (default) |
| `--udp` | UDP only |
| `--both` | TCP + UDP |
| `-c, --comment` | Comment (realm only) |
| `-q, --quiet` | Quiet mode |

### Port Formats (with `-t`)

| Format | Example | Description |
|--------|---------|-------------|
| Single port | `80` | Forward port 80 |
| Multiple ports | `80,443` | Forward ports 80 and 443 |
| Port range | `8080-8090` | Forward ports 8080 through 8090 |
| Port mapping | `33389:3389` | Forward local 33389 to remote 3389 |
| Range mapping | `8080-8090:3080-3090` | Map local range to remote range |
| Mixed | `80,443,8080-8090,33389:3389` | Combine any formats |

### Examples

```bash
# New syntax: nftables with port range
pfwd -m nft -t 1.2.3.4 10280-10281

# New syntax: nftables with mixed ports, IPv4 only, TCP+UDP
pfwd -m nft -t 1.2.3.4 -4 --both 80,443,8080-8090

# New syntax: realm with domain target
pfwd -m realm -t example.com 80,443 -c "web"

# New syntax: port mapping (local 33389 -> remote 3389)
pfwd -m nft -t 1.2.3.4 33389:3389

# Legacy syntax: nftables IPv4 TCP+UDP forwarding
pfwd -m nft -4 --both 10280:1.2.3.4:10280

# Legacy syntax: realm multiple endpoints
pfwd -m realm -46 10280:example.com:10280,10281:example.com:10281

# Legacy syntax: port range
pfwd -m nft 8080-8090:1.2.3.4:3080-3090

# Delete rules
pfwd del -m nft 10280
pfwd del -m realm 10280,10281

# Start/Stop/Restart
pfwd stop nft
pfwd start all
pfwd restart realm

# List all rules
pfwd list

# Traffic stats
pfwd stats

# Export/Import
pfwd export ~/backup.json
pfwd import ~/backup.json -m nft
pfwd import --url https://example.com/backup.json
```

## Methods

### nftables (with flowtable)

Kernel-level DNAT forwarding with flowtable fast path acceleration. Established connections are offloaded to the ingress hook, bypassing the entire netfilter stack for near-zero CPU overhead.

Flowtable requires Linux kernel >= 4.16 and the `nf_flow_table` module. pfwd will automatically:
- Detect kernel version and skip flowtable on older kernels
- Attempt to load the `nf_flow_table` module via `modprobe`
- Persist the module to `/etc/modules-load.d/nf_flow_table.conf` for boot survival (idempotent)
- Provide actionable suggestions if the module is unavailable (e.g. `apt install linux-modules-extra-$(uname -r)`)
- Fall back gracefully to standard forwarding if flowtable is not available
- Detect and skip duplicate rules when adding the same port/protocol/IP-version combination

Best for: IP-based targets, maximum performance.

### realm

Userspace proxy written in Rust. Supports domain-based targets natively. Duplicate endpoint detection prevents adding the same listen port twice.

Best for: Domain targets, environments where kernel-level forwarding is not suitable.

Install realm: `pfwd install`

## Performance

| Feature | Description |
|---------|-------------|
| **Flowtable fast path** | Established connections offloaded to ingress, bypassing netfilter |
| **BBR congestion control** | Optimized for throughput |
| **TCP fast open** | Reduced connection latency |
| **Conntrack tuning** | 1M max connections, optimized timeouts |
| **Buffer optimization** | 256MB TCP buffers |
| **MTU probing** | Auto MTU discovery to avoid fragmentation |

## File Locations

| File | Purpose |
|------|---------|
| `/etc/modules-load.d/nf_flow_table.conf` | nf_flow_table module auto-persistence |
| `/etc/nftables.d/port_forward.nft` | nftables persistent rules |
| `/etc/realm/config.toml` | realm configuration |
| `/etc/systemd/system/realm-forward.service` | realm systemd service |
| `/etc/systemd/system/pfwd-nft-restore.service` | nftables boot restore |
| `/var/lib/pfwd/restore-nft.sh` | nftables restore script |
| `/var/lib/pfwd/backup_*.json` | backup files |
| `/usr/local/bin/realm` | realm binary |
| `/etc/sysctl.d/99-pfwd.conf` | kernel optimizations |

## JSON Backup Format

```json
{
  "export_info": {
    "version": "1.0.0",
    "tool": "pfwd",
    "export_time": "2026-02-09T15:30:45",
    "source_ip": "1.2.3.4"
  },
  "forward_rules": [
    {
      "type": "nftables",
      "local_port": "10280",
      "target_ip": "1.2.3.4",
      "target_port": "10280",
      "protocol": "tcp",
      "ip_ver": "4"
    },
    {
      "type": "realm",
      "local_port": "10281",
      "target_ip": "ix.cnix.taphip.com",
      "target_port": "10281",
      "ip_ver": "46",
      "comment": "taphip-cnix"
    }
  ]
}
```

## Requirements

- Linux with root access
- nftables (for nft method)
- Linux kernel >= 4.16 (for flowtable acceleration; older kernels fall back to standard forwarding)
- jq (auto-installed for import/export)
- curl or wget (for realm installation and URL imports)

## License

MIT
