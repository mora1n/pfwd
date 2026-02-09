# pfwd - Port Forwarding Tool

A streamlined port forwarding management tool supporting **nftables** (with flowtable fast path acceleration) and **realm** (userspace Rust proxy).

## Features

- **nftables forwarding** with flowtable fast path offloading for minimal CPU overhead
- **realm forwarding** for domain-based targets and userspace proxying
- **Manual IPv4/IPv6 control** (`-4`, `-6`, `-46`)
- **CLI + Interactive menu** interface
- **Traffic statistics** via nftables counters
- **Backup/Import/Export** in JSON format
- **Boot persistence** via systemd services
- **Enhanced kernel optimization** (BBR, TCP tuning, conntrack, flowtable)

## Quick Start

```bash
# Install
curl -fsSL <url>/pfwd.sh -o /usr/local/bin/pfwd && chmod +x /usr/local/bin/pfwd

# Or just copy the script
cp pfwd.sh /usr/local/bin/pfwd

# Interactive mode
pfwd

# CLI examples
pfwd -m nft -4 --both 3489:1.2.3.4:3489
pfwd -m realm -46 8080:example.com:8080
```

## Usage

```
pfwd [command] [options] [rules...]

Commands:
  (none/add)  Add forwarding rules (default)
  del         Delete forwarding rules
  list        List all forwarding rules
  stats       Traffic statistics
  export      Export config to JSON
  import      Import config from JSON
  install     Install realm binary
  uninstall   Uninstall (realm / nftables / all)
  optimize    Run kernel optimization only
  help        Show help
```

### Add Rules

```bash
pfwd -m nft|realm [options] local_port:target:target_port[,...]
```

| Option | Description |
|--------|-------------|
| `-m, --method` | `nft` or `realm` (required) |
| `-4` | IPv4 only |
| `-6` | IPv6 only |
| `-46` | Dual-stack (default) |
| `--tcp` | TCP only (default) |
| `--udp` | UDP only |
| `--both` | TCP + UDP |
| `-c, --comment` | Comment (realm only) |
| `-q, --quiet` | Quiet mode |

### Examples

```bash
# nftables: IPv4 TCP+UDP forwarding
pfwd -m nft -4 --both 3489:1.2.3.4:3489

# nftables: dual-stack TCP
pfwd -m nft -46 443:backend.example.com:443

# realm: multiple endpoints
pfwd -m realm -46 3489:ix.cnix.taphip.com:3489,8080:ix.cnix.taphip.com:8080

# Delete rules
pfwd del -m nft 3489
pfwd del -m realm 3489,8080

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

Best for: IP-based targets, maximum performance.

### realm

Userspace proxy written in Rust. Supports domain-based targets natively.

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
      "local_port": "3489",
      "target_ip": "1.2.3.4",
      "target_port": "3489",
      "protocol": "tcp",
      "ip_ver": "4"
    },
    {
      "type": "realm",
      "local_port": "8080",
      "target_ip": "ix.cnix.taphip.com",
      "target_port": "8080",
      "ip_ver": "46",
      "comment": "taphip-cnix"
    }
  ]
}
```

## Requirements

- Linux with root access
- nftables (for nft method)
- jq (auto-installed for import/export)
- curl or wget (for realm installation and URL imports)

## License

MIT
