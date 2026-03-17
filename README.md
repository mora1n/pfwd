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
- **Per-rule traffic statistics** with optional live rate display (`pfwd stats --rate`)
- **Observer-only traffic collection** via conntrack or `/proc/net/nf_conntrack`, without per-rule nft counters
- **Collector interval control** (`pfwd stats --interval [30s|1m|5m|10m|30m|1h]`)
- **First-run shortcut install** — running from a persistent path as root auto-creates `/usr/local/bin/pfwd`
- **Kernel optimization profiles** — balanced / gaming / lowmem
- **Backup/Import/Export** in JSON format (current v3 schema)
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
| `-c, --comment` | Single-line comment (tabs/newlines rejected) |
| `-q, --quiet` | Quiet mode |
| `--no-color` | Disable colored output |
| `--no-clear` | Don't clear screen in interactive menu |

Interactive mode note:

- After you choose fixed SNAT, `pfwd` can suggest a fixed MSS based on the detected source-interface MTU.
- The suggestion also tries to detect PPPoE-style links and shows the calculation logic used for the recommendation.
- The suggestion is informational; you still choose `Off`, `Clamp to PMTU`, or `Fixed MSS`.

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

# Fixed SNAT rules show `snat:<source>` in the Options column

# Traffic
pfwd doctor
pfwd stats
pfwd stats --rate
pfwd stats --interval
pfwd stats --interval 1m

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

- `pfwd export` writes the current v3 JSON schema.
- `pfwd import` requires the current v3 schema with `forward_rules`.
- Legacy backups that still contain traffic-limit fields are no longer accepted.
- Legacy traffic cache records are ignored; regenerate stats with the current collector if needed.
- `pfwd list` shows fixed SNAT rules in the `Options` column and keeps the detailed SNAT section for long addresses.
- Rule comments must be single-line text; tabs/newlines are rejected.
- `jq` must already be installed for import/export.

## Method

### nftables (with flowtable)

Kernel-level DNAT forwarding with flowtable fast path acceleration. Established connections are offloaded to the ingress hook, bypassing the entire netfilter stack.

Requires Linux kernel >= 4.16 and `nf_flow_table` module. pfwd auto-detects, loads, and persists the module, falling back gracefully if unavailable.

Best for: IP-based targets, maximum performance.

## Traffic Statistics

- Statistics are collected out of band from conntrack state, not from per-rule nft counters.
- When `conntrack` is unavailable, pfwd falls back to `/proc/net/nf_conntrack`.
- The collector stores accumulated per-rule inbound / outbound totals and a lightweight flow snapshot for delta calculation.
- Flowtable-accelerated connections remain visible through conntrack accounting, so stats keep working without putting counters back on the forwarding path.

## Performance

| Feature | Description |
|---------|-------------|
| Flowtable fast path | Established connections offloaded to ingress |
| Observer-only stats | Traffic collection avoids per-rule nft counters and helper rules |
| nft output cache | TTL-based cache avoids redundant nft list calls |
| Batch mode | Bulk add/delete defers save and reload to end |
| Batch delete | Single chain fetch for multi-port deletion |
| Protocol/IP sharding | Per-protocol and per-IP-version subchains reduce hot-path scans |
| Pure-bash format_bytes | No awk fork for human-readable byte formatting |
| BBR + TCP tuning | Optimized congestion control and buffers |

## Validation & Benchmark (root)

Use this on the target host to confirm forwarding works and compare throughput before/after changes.

```bash
# 1) Basic health
pfwd doctor

# 2) Add one test forward rule (example)
pfwd -m nft -t 127.0.0.1 --tcp 18080:8080

# 3) TCP smoke test in netns
ip netns add pfwd-test || true
ip -n pfwd-test link set lo up
nohup sh -c 'nc -lk 127.0.0.1 8080 >/tmp/pfwd-nc.log 2>&1' >/dev/null 2>&1 &
ip netns exec pfwd-test sh -c 'echo ok | nc -w2 <HOST_IP> 18080'

# 4) Optional UDP smoke test
nohup sh -c 'socat -T1 -u UDP-LISTEN:8081,fork - >/tmp/pfwd-udp.log 2>&1' >/dev/null 2>&1 &
pfwd -m nft -t 127.0.0.1 --udp 18081:8081
ip netns exec pfwd-test sh -c 'echo ok | socat -u - UDP:<HOST_IP>:18081'

# 5) Throughput benchmark (before/after)
# add benchmark forward rule first
pfwd -m nft -t 127.0.0.1 --tcp 18088:8088
# server:
iperf3 -s -p 8088
# client:
iperf3 -c <HOST_IP> -p 18088 -P 4 -t 30
```

Suggested acceptance:
- Forwarding smoke tests pass (TCP/UDP as needed).
- `pfwd doctor` reports flowtable mode/devices when fast path is active.
- In identical traffic conditions, throughput improves or CPU usage drops.

## File Locations

| File | Purpose |
|------|---------|
| `/etc/nftables.d/port_forward.nft` | nftables persistent rules |
| `/root/.pfwd_backup/nftables_*.nft` | nftables rule backups (last 5) |
| `/etc/systemd/system/pfwd-nft-restore.service` | nftables boot restore service (calls `pfwd __restore-nft`) |
| `/etc/systemd/system/pfwd-traffic-save.service` | traffic collector service |
| `/etc/systemd/system/pfwd-traffic-save.timer` | traffic collector timer |
| `/var/lib/pfwd/traffic_stats.dat` | accumulated traffic counters |
| `/var/lib/pfwd/traffic_flows.dat` | last collector flow snapshot for delta calculation |
| `/etc/sysctl.d/99-pfwd.conf` | kernel optimizations |
| `/var/lib/pfwd/` | backup files and runtime state |

## Requirements

- Linux with root access
- nftables
- Linux kernel >= 4.16 (for flowtable; older kernels fall back to standard forwarding)
- jq (required for import/export)

## Compatibility

- Old `realm` rules in backup files are skipped during import.
- Exported JSON now uses the v3 schema; older backups with legacy limit fields are intentionally rejected.
- Existing system-level `realm` files or services are not managed by this script anymore.

## License

MIT
