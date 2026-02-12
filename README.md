# pfwd - Port Forwarding Tool

A streamlined port forwarding management tool supporting **nftables** (with flowtable fast path acceleration) and **realm** (userspace Rust proxy).

## Features

- **nftables forwarding** with flowtable fast path offloading for minimal CPU overhead
- **realm forwarding** for domain-based targets and userspace proxying
- **Shortcut syntax** — `pfwd 8080 1.2.3.4` just works
- **Batch mode** — bulk add/delete with single save/restart cycle
- **nft output caching** — TTL-based cache eliminates redundant `nft list` calls
- **Flexible port syntax** — single ports, ranges, mappings, mixed formats
- **Manual IPv4/IPv6 control** (`-4`, `-6`, `-46`)
- **CLI + Interactive menu** with numbered rules and color coding
- **Rule filtering** — `pfwd list -f <pattern>` for regex search
- **Traffic statistics** with optional live rate display (`pfwd stats --rate`)
- **Kernel optimization profiles** — balanced / gaming / lowmem
- **Backup/Import/Export** in JSON format
- **Boot persistence** via systemd services
- **Smart download** with GitHub mirror support
- **`--no-color` / `--no-clear`** modes for scripting

## Quick Start

```bash
# Install
curl -fsSL <url>/pfwd.sh -o /usr/local/bin/pfwd && chmod +x /usr/local/bin/pfwd

# Interactive mode
pfwd

# Shortcut (auto nft)
pfwd 8080 1.2.3.4
pfwd 80,443 1.2.3.4

# Full syntax
pfwd -m nft -t 1.2.3.4 80,443,8080-8090
pfwd -m realm -t example.com 80,443 -c "web"
```

## Usage

```
pfwd [command] [options] [rules...]

Commands:
  (none/add)  Add forwarding rules (default)
  del         Delete forwarding rules
  list        List all forwarding rules
  status      Show running status and rule counts
  start/stop/restart  Control forwarding (nft / realm / all)
  stats       Traffic statistics
  export      Export config to JSON
  import      Import config from JSON
  install     Install realm binary
  uninstall   Uninstall (realm / nftables / all)
  optimize    Kernel optimization [balanced|gaming|lowmem]
  help        Show help
```

### Add Rules

```bash
pfwd -m nft|realm -t <target> [options] <ports>

# Or shortcut (defaults to nft):
pfwd <ports> <target> [target_port]
```

| Option | Description |
|--------|-------------|
| `-m, --method` | `nft` or `realm` (required) |
| `-t, --target` | Target IP or domain (required) |
| `-4` / `-6` / `-46` | IPv4 only / IPv6 only / Dual-stack (default) |
| `--tcp` / `--udp` / `--both` | Protocol selection (default: tcp) |
| `-c, --comment` | Comment |
| `-q, --quiet` | Quiet mode |
| `--no-color` | Disable colored output |
| `--no-clear` | Don't clear screen in interactive menu |

### Port Formats

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
# Shortcut
pfwd 8080 1.2.3.4
pfwd 80,443 1.2.3.4
pfwd 8080 1.2.3.4 80          # local 8080 -> remote 80

# nftables
pfwd -m nft -t 1.2.3.4 80,443,8080-8090
pfwd -m nft -t 1.2.3.4 -4 --both 80 443 8080-8090
pfwd -m nft -t 1.2.3.4 33389:3389

# realm (domain targets)
pfwd -m realm -t example.com 80,443 -c "web"

# Delete
pfwd del -m nft 3389
pfwd del -m nft 80,443,8080-8082
pfwd del -m realm 3389

# List / Filter
pfwd list
pfwd list -f 8080

# Traffic
pfwd stats
pfwd stats --rate

# Kernel optimization
pfwd optimize              # balanced (default)
pfwd optimize gaming       # low latency
pfwd optimize lowmem       # for small VPS

# Export/Import
pfwd export ~/backup.json
pfwd import ~/backup.json -m nft
pfwd import --url https://example.com/backup.json
```

## Methods

### nftables (with flowtable)

Kernel-level DNAT forwarding with flowtable fast path acceleration. Established connections are offloaded to the ingress hook, bypassing the entire netfilter stack.

Requires Linux kernel >= 4.16 and `nf_flow_table` module. pfwd auto-detects, loads, and persists the module, falling back gracefully if unavailable.

Best for: IP-based targets, maximum performance.

### realm

Userspace proxy written in Rust. Supports domain-based targets natively.

Best for: Domain targets, environments where kernel-level forwarding is not suitable.

Install: `pfwd install`

## Performance

| Feature | Description |
|---------|-------------|
| Flowtable fast path | Established connections offloaded to ingress |
| nft output cache | TTL-based cache avoids redundant nft list calls |
| Batch mode | Bulk add/delete defers save/restart to end |
| Batch delete | Single chain fetch for multi-port deletion |
| O(1) traffic matching | Hash-based postrouting lookup (replaces O(n²) loop) |
| Pure-bash format_bytes | No awk fork for human-readable byte formatting |
| BBR + TCP tuning | Optimized congestion control and buffers |

## File Locations

| File | Purpose |
|------|---------|
| `/etc/nftables.d/port_forward.nft` | nftables persistent rules |
| `/root/.pfwd_backup/nftables_*.nft` | nftables rule backups (last 5) |
| `/etc/realm/config.toml` | realm configuration |
| `/etc/systemd/system/realm-forward.service` | realm systemd service |
| `/etc/systemd/system/pfwd-nft-restore.service` | nftables boot restore |
| `/etc/sysctl.d/99-pfwd.conf` | kernel optimizations |
| `/var/lib/pfwd/` | backup files and restore scripts |

## Requirements

- Linux with root access
- nftables (for nft method)
- Linux kernel >= 4.16 (for flowtable; older kernels fall back to standard forwarding)
- jq (auto-installed for import/export)
- curl or wget (for realm installation and URL imports)

## License

MIT
