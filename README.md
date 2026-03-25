# pfwd - Port Forwarding Tool

A streamlined port forwarding management tool focused on **nftables** with flowtable fast path acceleration.

## Features

- **nftables forwarding** with flowtable fast path offloading for minimal CPU overhead
- **Shortcut syntax** — `pfwd 8080 1.2.3.4` just works
- **Safe conflict handling** — duplicate nft port/protocol/IP-family rules are rejected unless you pass `--replace`
- **Flexible port syntax** — single ports, ranges, mappings, mixed formats
- **Manual IPv4/IPv6 control** (`-4`, `-6`, `-46`)
- **CLI + Interactive menu** with numbered rules and color coding
- **Rule filtering and traffic stats** — `pfwd list -f <pattern>`, `pfwd stats`, `pfwd stats --rate`
- **Collector interval control** — `pfwd stats --interval [30s|1m|5m|10m|30m|1h]`
- **First-run shortcut install** — running from a persistent path as root auto-creates `/usr/local/bin/pfwd`
- **Kernel optimization profiles** — balanced / gaming / lowmem / relay, with kernel preflight and post-apply verification
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
  refresh     Re-resolve targets and rebuild nftables from saved state
  start/stop/restart  Control forwarding (nft / all)
  stats       Traffic statistics
  export      Export config to JSON
  import      Import config from JSON
  uninstall   Uninstall (nftables / all)
  optimize    Kernel optimization with preflight + verify [balanced|gaming|lowmem|relay]
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
| `--mss-clamp` / `--mss <value>` | nft only: clamp to PMTU or set a fixed TCP MSS |
| `--snat-source <addr>` / `--masquerade` | nft only: fixed SNAT source or default masquerade (`--snat-source` auto-switches `-46` to the matching family) |
| `-c, --comment` | Single-line comment (tabs/newlines rejected) |
| `-q, --quiet` | Quiet mode |
| `--no-color` | Disable colored output |
| `--no-clear` | Don't clear screen in interactive menu |

Interactive mode note:

- Fixed SNAT is single-stack; if you leave IP version at `-46`, `pfwd` auto-switches to IPv4 or IPv6 based on the SNAT source address.
- After you choose fixed SNAT, `pfwd` prefers route `advmss`, then route MTU, then link MTU when suggesting a fixed MSS from the smaller source-side/backend-side path.
- The suggestion remains informational; you still choose `Off`, `Clamp to PMTU`, or `Fixed MSS`.

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
# Add
pfwd 8080 1.2.3.4 80
pfwd -m nft -t 1.2.3.4 -4 --both 80 443 8080-8090
pfwd -m nft -t 2.2.2.2 --replace 33389:3389
pfwd -m nft -4 -t 2.2.2.2 --snat-source 192.168.1.2 9443:443

# Delete
pfwd del -m nft 3389
pfwd del -m nft 80,443,8080-8082

# List / Filter
pfwd list
pfwd list -f 8080

# Fixed SNAT rules show `snat:<source>` in the Options column

# Traffic
pfwd doctor
pfwd doctor --tcp-probe
pfwd doctor --tcp-probe --probe-timeout 5
pfwd refresh
pfwd stats
pfwd stats --rate
pfwd stats --interval
pfwd stats --interval 1m

# Kernel optimization
pfwd optimize              # balanced (default) + prints preflight/recommendation
pfwd optimize gaming       # low latency
pfwd optimize lowmem       # for small VPS
pfwd optimize relay        # relay-focused forwarding tuning

# Export/Import
pfwd export ~/backup.json
pfwd import ~/backup.json -m nft
```

Notes:

- Import/export use the current v3 JSON schema with `forward_rules`.
- `pfwd import` only accepts local JSON files; download remote backups first if needed.
- Exported rules keep SNAT/MSS/comment data in `options`, and also write flat compatibility fields such as `snat_mode` / `snat_source`.
- `pfwd` now treats `/var/lib/pfwd/rules.v1.tsv` as the source of truth; `refresh`/`start` rebuild nftables from saved state.
- `start` / `restart` / `refresh` now re-check managed iptables/UFW guard state after rebuild and fail fast if automatic repair cannot make it healthy.
- Domain targets stay in saved state as hostnames and are re-resolved on `refresh`, `start`, and each ruleset change.
- `pfwd optimize` prints kernel capability preflight, skips unsupported sysctl keys, and verifies the live result.
- `pfwd` detects newer performance kernels such as XanMod, but does not install or switch kernels for you.
- `pfwd` does not manage legacy TCP accelerator stacks such as Lotserver/ServerSpeeder.
- Legacy traffic cache records are ignored; the next collector run rewrites state in the current format if needed.
- `pfwd list` shows fixed SNAT rules in the `Options` column and keeps a detailed SNAT section for long addresses.
- `pfwd status` shows degraded runtime guard state directly, including managed FORWARD exceptions and UFW persistence.
- `pfwd doctor --tcp-probe` adds active TCP backend probes so you can distinguish `connect ok`, `connection refused`, and `timeout`.
- Rule comments must be single-line text, and `jq` is required for import/export.
- For tests, set `PFWD_ROOT_PREFIX` to redirect managed `/etc`, `/var/lib`, `/root`, and `/usr/local/bin` paths into a temporary tree.

## Method

### nftables (with flowtable)

Kernel-level DNAT forwarding with flowtable fast path acceleration. Established connections are offloaded to the ingress hook, bypassing the entire netfilter stack.

Requires Linux kernel >= 4.16 and `nf_flow_table` module. pfwd auto-detects, loads, and persists the module, falling back gracefully if unavailable.

Best for: IP-based targets, maximum performance.

## Traffic Statistics

- Statistics are collected out of band from conntrack state, not from per-rule nft counters.
- When `conntrack` is unavailable, pfwd falls back to `/proc/net/nf_conntrack`.
- The collector stores accumulated per-rule inbound / outbound totals and a lightweight flow snapshot for delta calculation.
- Traffic history is keyed by full rule identity (`proto/ipver/lport/target/tport`), so reusing a local port for a new backend does not inherit old counters.
- Flowtable-accelerated connections remain visible through conntrack accounting, so stats keep working without putting counters back on the forwarding path.

## Performance

| Feature | Description |
|---------|-------------|
| State-driven apply | `/var/lib/pfwd/rules.v1.tsv` is rendered into nftables atomically |
| Flowtable fast path | Established connections offloaded to ingress |
| Observer-only stats | Traffic collection avoids per-rule nft counters and hot-path helper rules |
| Port aggregation | Same-backend rules are grouped into nft port sets / intervals where possible |
| Atomic apply + batch mode | Saved config is replaced atomically, and bulk add/delete defers rebuild and reload to end |
| nft output cache | TTL-based cache avoids redundant `nft list` calls |
| Protocol/IP sharding | Per-protocol and per-IP-version subchains reduce hot-path scans |
| Pure-bash format_bytes | No awk fork for human-readable byte formatting |
| BBR + TCP tuning | Optimized congestion control and buffers |

## File Locations

| File | Purpose |
|------|---------|
| `/var/lib/pfwd/rules.v1.tsv` | pfwd source-of-truth state file |
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
- Core forwarding tools:
  - `nftables` (`nft`)
  - `iproute2` / `iproute` (`ip`)
- Feature-specific tool:
  - `jq` (required for import/export)
- Recommended tool:
  - `conntrack` / `conntrack-tools` (preferred traffic stats backend; otherwise pfwd falls back to `/proc/net/nf_conntrack`)
- Linux kernel >= 4.16 (for flowtable; older kernels fall back to standard forwarding)

On the first non-internal run, `pfwd` checks the tools above once and prints a distro-matched install hint if any are missing.

Common package install commands:

| Distro | Command |
|--------|---------|
| Debian / Ubuntu | `apt-get install -y nftables iproute2 jq conntrack` |
| Fedora / Rocky / Alma / Amazon Linux / Oracle Linux | `dnf install -y nftables iproute jq conntrack-tools` |
| CentOS / RHEL (legacy) | `yum install -y nftables iproute jq conntrack-tools` |
| openSUSE / SUSE | `zypper install -y nftables iproute2 jq conntrack-tools` |
| Arch Linux | `pacman -Sy --needed nftables iproute2 jq conntrack-tools` |
| Alpine | `apk add nftables iproute2 jq conntrack-tools` |

## License

MIT
