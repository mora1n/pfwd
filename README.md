# pfwd - Port Forwarding Tool

A streamlined port forwarding management tool focused on **nftables** with flowtable fast path acceleration.

## Features

- **nftables forwarding** with flowtable fast path offloading for minimal CPU overhead
- **Shortcut syntax** — `pfwd 8080 1.2.3.4` just works
- **Safe conflict handling** — duplicate nft port/protocol/IP-family rules are rejected unless you pass `--replace`
- **Atomic nft persistence** — saved nft config is written via temp file + atomic replace
- **Batch mode** — bulk add/delete with single save/restart cycle
- **nft output caching** — TTL-based cache eliminates redundant `nft list` calls
- **Flexible port syntax** — single ports, ranges, mappings, mixed formats
- **Manual IPv4/IPv6 control** (`-4`, `-6`, `-46`)
- **CLI + Interactive menu** with numbered rules and color coding
- **Rule filtering** — `pfwd list -f <pattern>` for regex search
- **Traffic statistics** with optional live rate display (`pfwd stats --rate`)
- **Per-rule traffic limits** for inbound / outbound / total traffic
- **Automatic reset and recovery** with daily / monthly / yearly cycles or absolute reset time
- **Collector interval control** (`pfwd stats --interval [30s|1m|5m|10m|30m|1h]`)
- **First-run shortcut install** — running from a persistent path as root auto-creates `/usr/local/bin/pfwd`
- **Kernel optimization profiles** — balanced / gaming / lowmem
- **Backup/Import/Export** in JSON format (current v2 schema)
- **Boot persistence** via systemd services
- **`--no-color` / `--no-clear`** modes for scripting

## Quick Start

```bash
# Install from a persistent path
curl -fsSL <url>/pfwd.sh -o /usr/local/bin/pfwd.sh && chmod +x /usr/local/bin/pfwd.sh

# First root run will auto-create /usr/local/bin/pfwd -> /usr/local/bin/pfwd.sh
/usr/local/bin/pfwd.sh

# Interactive mode
pfwd

# Shortcut (auto nft)
pfwd 8080 1.2.3.4
pfwd 80,443 1.2.3.4
pfwd 8080 1.2.3.4 --replace

# Full syntax
pfwd -m nft -t 1.2.3.4 80,443,8080-8090
```

## Usage

```
pfwd [command] [options] [rules...]

Commands:
  (none/add)  Add forwarding rules (default)
  del         Delete forwarding rules
  list        List all forwarding rules
  status      Show running status and rule counts
  doctor      Run forwarding diagnostics
  start/stop/restart  Control forwarding (nft / all)
  stats       Traffic statistics
  limit       Manage traffic limits
  export      Export config to JSON
  import      Import config from JSON
  uninstall   Uninstall (nftables / all)
  optimize    Kernel optimization [balanced|gaming|lowmem]
  help        Show help
```

### Add Rules

```bash
pfwd -m nft -t <target> [options] <ports>

# Or shortcut (defaults to nft):
pfwd <ports> <target> [target_port]
```

| Option | Description |
|--------|-------------|
| `-m, --method` | `nft` (required) |
| `-t, --target` | Target IP or domain (required) |
| `-4` / `-6` / `-46` | IPv4 only / IPv6 only / Dual-stack (default) |
| `--tcp` / `--udp` / `--both` | Protocol selection (default: tcp) |
| `--replace` | nft only: replace an existing rule for the same local port/protocol/IP family |
| `--limit-in <size>` | nft only: inbound traffic limit, e.g. `500M`, `2G` |
| `--limit-out <size>` | nft only: outbound traffic limit |
| `--limit-total <size>` | nft only: total inbound+outbound traffic limit |
| `--limit-reset-every <Nd|Nmo|Ny>` | nft only: reset cycle, e.g. `1d`, `2mo`, `1y` |
| `--limit-reset-at <time>` | nft only: absolute reset time, e.g. `2026-04-01 00:00:00` |
| `-c, --comment` | Single-line comment (tabs/newlines rejected) |
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
pfwd 8080 1.2.3.4 --replace   # replace an existing nft rule explicitly

# nftables
pfwd -m nft -t 1.2.3.4 80,443,8080-8090
pfwd -m nft -t 1.2.3.4 -4 --both 80 443 8080-8090
pfwd -m nft -t 1.2.3.4 33389:3389
pfwd -m nft -t 2.2.2.2 --replace 33389:3389

# Delete
pfwd del -m nft 3389
pfwd del -m nft 80,443,8080-8082

# List / Filter
pfwd list
pfwd list -f 8080

# Traffic
pfwd doctor
pfwd stats
pfwd stats --rate
pfwd stats --interval
pfwd stats --interval 1m

# Traffic limits
pfwd -m nft -t 1.2.3.4 --limit-total 100G --limit-reset-every 1mo 443
pfwd -m nft -t 1.2.3.4 --limit-in 50G --limit-out 20G --limit-reset-at "2026-04-01 00:00:00" 8443:443
pfwd limit list
pfwd limit set 443 --limit-total 200G --limit-reset-every 2mo
pfwd limit restore 443
pfwd limit unset 443

# Kernel optimization
pfwd optimize              # balanced (default)
pfwd optimize gaming       # low latency
pfwd optimize lowmem       # for small VPS

# Export/Import
pfwd export ~/backup.json
pfwd import ~/backup.json -m nft
pfwd import --url https://example.com/backup.json
```

Notes:

- `pfwd export` writes the current v2 JSON schema.
- `pfwd import` requires the current v2 schema with `forward_rules`.
- Legacy traffic cache records are ignored; regenerate stats with the current collector if needed.
- Rule comments must be single-line text; tabs/newlines are rejected.
- `jq` must already be installed for import/export and traffic-limit commands.

## Method

### nftables (with flowtable)

Kernel-level DNAT forwarding with flowtable fast path acceleration. Established connections are offloaded to the ingress hook, bypassing the entire netfilter stack.

Requires Linux kernel >= 4.16 and `nf_flow_table` module. pfwd auto-detects, loads, and persists the module, falling back gracefully if unavailable.

Best for: IP-based targets, maximum performance.

## Traffic Limit Semantics

- Limits are configured per nft forwarding rule.
- `--limit-in`, `--limit-out` and `--limit-total` can be used together. Any one reaching its threshold blocks that rule.
- When a rule is blocked by limit, pfwd removes that forwarding rule from nftables until the next reset or a manual `pfwd limit restore`.
- Manual restore always clears the current cycle counters before bringing the rule back.
- Reset policy supports:
  - `--limit-reset-every <Nd|Nmo|Ny>` for periodic reset
  - `--limit-reset-at "<time>"` for one absolute reset point
  - both together, where the absolute time is treated as the first boundary and the cycle continues afterwards
- If only `--limit-reset-at` is configured, pfwd performs one automatic reset at that time and does not schedule a later one.

## Performance

| Feature | Description |
|---------|-------------|
| Flowtable fast path | Established connections offloaded to ingress |
| nft output cache | TTL-based cache avoids redundant nft list calls |
| Batch mode | Bulk add/delete defers save and reload to end |
| Batch delete | Single chain fetch for multi-port deletion |
| O(1) traffic matching | Hash-based postrouting lookup (replaces O(n²) loop) |
| Pure-bash format_bytes | No awk fork for human-readable byte formatting |
| BBR + TCP tuning | Optimized congestion control and buffers |

## File Locations

| File | Purpose |
|------|---------|
| `/etc/nftables.d/port_forward.nft` | nftables persistent rules |
| `/root/.pfwd_backup/nftables_*.nft` | nftables rule backups (last 5) |
| `/etc/systemd/system/pfwd-nft-restore.service` | nftables boot restore service (calls `pfwd __restore-nft`) |
| `/etc/systemd/system/pfwd-traffic-save.service` | traffic collector service |
| `/etc/systemd/system/pfwd-traffic-save.timer` | traffic collector timer |
| `/var/lib/pfwd/traffic_stats.dat` | accumulated traffic counters |
| `/var/lib/pfwd/traffic_limits.json` | traffic-limit config and cycle state |
| `/etc/sysctl.d/99-pfwd.conf` | kernel optimizations |
| `/var/lib/pfwd/` | backup files and runtime state |

## Requirements

- Linux with root access
- nftables
- Linux kernel >= 4.16 (for flowtable; older kernels fall back to standard forwarding)
- jq (required for import/export and traffic-limit management)

## Compatibility

- Old `realm` rules in backup files are skipped during import.
- Exported JSON now uses the v2 schema; imports remain backward-compatible with older flat exports.
- Existing system-level `realm` files or services are not managed by this script anymore.

## License

MIT
