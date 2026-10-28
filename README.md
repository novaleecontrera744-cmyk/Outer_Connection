# outer-vpn

`outer.py` is a Python 3.9+ (standard-library-only) Lubuntu/Linux manager for a VLESS-to-Proton-WireGuard gateway. It uses one systemd service to supervise sing-box and Xray, with a network namespace, veth, TUN, and nftables traffic guard. It does not require pip packages.

## Read before using: behavior and limits

With the default `STRICT_MODE=false`, ordinary IPv4 traffic, DNS, and the Proton app use the outer VLESS tunnel **before** the first Proton handshake. Destinations can see the outer IP during this bootstrap period. The firewall permits this traffic only through the gateway veth; it blocks direct physical-interface egress and blocks IPv6. If the outer tunnel fails, the failure guard is retained rather than falling back to the direct connection.

After a recent handshake is observed on the configured, allowlisted Proton WireGuard interface, the supervisor removes the outer-bootstrap exception and permits ordinary traffic only through Proton. It does not automatically reopen bootstrap if Proton disconnects: traffic remains blocked unless Proton recovers. The supervisor checks the handshake periodically, so Proton's Standard kill switch must also protect the transition. Its compatibility with this setup has **not** been verified. `STRICT_MODE=true` disables outer-only bootstrap entirely, which can prevent the Proton GUI from resolving DNS or reaching its API before connecting.

`Proton WireGuard: verified` means the named link is up, is WireGuard, has allowlisted IPv4 peers, and each marked peer route uses the gateway veth. It does **not** by itself prove a handshake, working websites, or the public IP websites see. Check that `Traffic mode: Proton only` is shown and verify the exit IP before relying on it.

This repository has not been tested on your laptop. Compatibility with Proton VPN's **Standard kill switch is unproven**; this service's firewall is an additional guard, not proof that Proton's own kill switch interoperates. Do not rely on the intended privacy result until you have verified it on the target machine. Stopping or uninstalling deliberately removes this firewall protection and restores the previous regular routing/DNS state; after that, ordinary direct Internet routing can expose your normal public IP.

Use a local console/TTY and keep a recovery path available before starting: the host default route changes, which can interrupt remote access.

## Design

- Xray provides the VLESS TCP + REALITY + `xtls-rprx-vision` client and a loopback SOCKS inbound with UDP enabled. Its outbound is bound to the namespace veth. The client-only `xtls-rprx-vision-udp443` variant permits WireGuard over UDP/443; Xray removes the suffix on the wire.
- sing-box runs in the namespace with a TUN using `auto_route` and `auto_redirect`. Its SOCKS outbound is bound to `lo` and connects to Xray; the VLESS server's IPv4 `/32` is excluded from TUN routing to avoid a routing loop. The SOCKS bridge is configured for TCP and UDP. Xray handles REALITY because newer Xray servers can be incompatible with sing-box's REALITY client ([sing-box issue #4520](https://github.com/SagerNet/sing-box/issues/4520)).
- Before changing the host default route, the supervisor probes DNS over both TCP and UDP through the tunnel. This is a connectivity probe, not a test that arbitrary websites work.
- The host gets routes for the configured Proton peer IPv4 addresses through the gateway, with blackhole fallbacks in both the main and dedicated endpoint policy tables. systemd-resolved is pointed at the configured DNS server on the tunnel link during default bootstrap. When a Proton handshake is observed, that setting is reverted and the app must supply working Proton DNS. IPv6 has a blackhole default policy while the service runs.
- `outer-vpn.service` is `Type=notify`: one supervisor and both core processes stay in the same systemd cgroup. Core stdout is discarded; a bounded stderr tail is redacted and reported if a core fails. Configuration, runtime files, and transaction backups contain sensitive data and must remain private.
- Changes are journaled and file updates are atomic. Repeated install/apply/start/stop/uninstall operations are designed to be safe; failed file transactions roll back. A failed service retains its guard; an explicit `stop` attempts to remove owned guards even if another cleanup step reports an error.

## Requirements

- Lubuntu/Linux with Python 3.9 or newer, systemd, and an available `/dev/net/tun` device.
- Required tools: `ip` from `iproute2`, `nft` from `nftables`, `unshare` from `util-linux`, `systemctl`, active `systemd-resolved`/`resolvectl`, `wg` from `wireguard-tools`, and `sysctl` (normally provided by `procps`). The installer uses Python's standard-library HTTPS client; no `curl` or Python package is required.
- sing-box **1.14.4** and Xray **26.10.21** are installed by the script when needed. Release downloads support Linux x86-64 and ARM64 only.
- Root privileges for `install`, `apply`, `start`, `stop`, and `uninstall`. `preflight`, `dry-run`, and `status` do not require root; run `status` with `sudo` to inspect protected recovery state.

On Lubuntu, install missing tools and ensure resolved is running, for example:

```sh
sudo apt install python3 iproute2 nftables util-linux systemd-resolved wireguard-tools procps
sudo systemctl enable --now systemd-resolved.service
```

If `/dev/net/tun` is absent, load/enable the kernel TUN module before continuing. `preflight` checks the required commands, TUN device, and active `systemd-resolved` service.

## Configuration

Clone the repository, then copy the example and replace **all** demo values before using `preflight` or `start`:

```sh
git clone <repository-url>
cd <repository-directory>
cp .env.example .env
chmod 600 .env
${EDITOR:-nano} .env
```

`.env.example` uses reserved documentation addresses and fake credentials; it is deliberately not a working tunnel configuration. The parser treats the file as data only: **never `source` or `eval` it**. Only these keys are accepted:

- `VLESS_URL` (required): a VLESS share URL for TCP, REALITY, and Vision. Its supported query fields are `encryption=none`, `type=tcp` (default; `raw` is also accepted), `security=reality`, `flow=xtls-rprx-vision`, `sni`, `fp`, `pbk`, and optional `sid`, `spx`, or `headerType=none`. `sni`, `fp`, and `pbk` are required. Use the provider's actual values; the UUID is an authentication credential. Example shape (replace every placeholder; do not type the angle brackets):

  ```text
  vless://UUID@vless.example:443?encryption=none&type=tcp&security=reality&flow=xtls-rprx-vision&sni=reality.example&fp=chrome&pbk=BASE64URL_PUBLIC_KEY&sid=HEX_SHORT_ID&spx=%2F
  ```

  The server name must resolve to a public IPv4 address for preflight/start. Hostname resolution happens before the gateway guard is installed and may use your current network's DNS. To avoid that bootstrap DNS exposure, put the server's IPv4 literal in the URL and keep the REALITY domain in `sni`. Unsupported share-link query fields are rejected.
- `PROTON_ENDPOINTS` (required): a comma- or whitespace-separated allowlist of literal IPv4 addresses for Proton WireGuard peers. Do not use hostnames, CIDRs, ports, IPv6, or an empty list. Include every IPv4 peer address the app may use; update the list when Proton changes them.
- `PROTON_INTERFACE` (optional, default `proton0`): the exact Linux interface name created by Proton. It must be an UP WireGuard link, and all its configured peer endpoints must be IPv4 addresses in `PROTON_ENDPOINTS`. A different interface name is not auto-detected.
- `DNS_SERVER` (optional, default `1.1.1.1`): a literal unicast IPv4 DNS server reachable through the tunnel. The example's `192.0.2.53` is a documentation-only placeholder, not a working resolver.
- `STRICT_MODE` (optional, default `false`): set `true` to block normal outer-only Internet access before Proton connects. Leave `false` to let the Proton app use DNS and its API through the outer tunnel.

The installed copy of the configuration is `/etc/outer-vpn/outer.env`, owned by root with mode `0600`. Keep both it and your local `.env` private. `.gitignore` excludes `.env` and Python bytecode; verify you do not stage credentials under another filename.

## Commands

Run commands from the repository directory. `preflight` and `dry-run` read the local `.env`; `preflight` also resolves the VLESS host and validates installed binaries/configs when available. `dry-run` makes no file, network, firewall, or service changes.

```sh
# Unprivileged checks
python3 outer.py preflight --env .env
python3 outer.py dry-run --env .env
sudo python3 outer.py debug-rules --env .env

# Root-required installation and configuration
sudo python3 outer.py install --env .env
sudo python3 outer.py apply --env .env

# Start only while Proton is disconnected; then connect Proton using WireGuard UDP
sudo python3 outer.py start
python3 outer.py status
sudo python3 outer.py status   # includes protected recovery/guard details

# Stop returns the host to regular routing and removes this firewall guard
sudo python3 outer.py stop

# Uninstall the managed service and files; recovery backups are retained
sudo python3 outer.py uninstall
```

`install` reads `--env` (default `.env`) and checks the generated nftables scripts before downloading or installing files. It installs the unit and script but does not enable the service for boot or start it. If pinned binaries are absent or fail integrity checks, it asks before downloading official sing-box 1.14.4 and Xray 26.10.21 releases. It checks GitHub's official release metadata, exact asset URLs, and SHA-256 digests before installing. Answer `y`/`yes` to confirm; `sudo python3 outer.py install --yes` skips the prompt and explicitly authorizes the download. A current, verified installation does not download again. No tests download binaries.

After updating an existing checkout, stop the gateway and run `sudo python3 outer.py install --env .env` again so systemd uses the updated supervisor. Applying `.env` again is safe if it is unchanged.

`debug-rules` prints the nftables scripts and commands used by `outer.py`, including the route-selected physical interface. Dynamic Proton-peer examples use a configured endpoint and illustrative UDP port 51820; the live port is learned from WireGuard. It only performs read-only route and nftables inspection and does not install rules or change routes. Use `sudo` to inspect existing nftables tables. Review output before sharing it because interface names and network addresses are local details.

`apply` validates the generated configs with the installed real binaries and copies `.env` into the root-only configuration path. `start` launches the single supervisor, which checks the outer connection before changing the host default route. Connect Proton only after `start` succeeds. With the default mode, websites and services can see the outer IP until Proton connects. Changing `.env` requires stopping first, applying the new file, then starting again; `apply` refuses to change a running configuration.

Before installing files or changing gateway networking, `install` and `start` check the generated nftables scripts with `nft -c`, then commit inert copies in a new temporary network namespace to exercise kernel hook validation. The probe uses unique temporary tables, retains the rule expressions and hooks, makes verdicts harmless, and deletes its tables before the namespace exits. Existing host traffic and firewall tables are not touched. The check requires root and permission to create a network namespace; failure leaves the existing connection, including any direct connection, as it was. It covers `outer.py`'s rules, not rules sing-box creates internally, and is not proof of a working tunnel. System utilities, including nft and sysctl, are invoked by absolute path rather than the caller's `PATH`. External-command failures include redacted argv and stderr in the error and system journal; failures after a recovery journal is created are also recorded there. Review diagnostics for local addresses before sharing them.

## Legacy migration and backups

`preflight`/`dry-run` report known legacy items. `install` snapshots detected legacy paths but leaves them in place; `start` migrates known paths under the transition guard and reports the migration backup. Recognized locations include:

- `/etc/systemd/system/outer-gateway.service` and `/etc/systemd/system/outer-gateway.service.d/50-xray-bridge.conf`
- `/usr/local/libexec/outergw-*`, `/etc/sing-box-gateway`, and `/etc/outer-gateway`
- `/usr/local/bin/outer-vpn-toggle` and `/usr/local/sbin/outer-vpn-toggle-root`
- `Outer-Connection.desktop` in system application directories and the selected user's `~/.local/share/applications/`, `~/.config/autostart/`, or `~/Desktop/`

**Extra legacy drop-ins are not automatically discovered.** The migration recognizes only `50-xray-bridge.conf`, not arbitrary files in `/etc/systemd/system/outer-gateway.service.d/`. Before migration, inspect `systemctl cat outer-gateway.service` and that directory; preserve/review any extra overrides yourself. Do not assume a preflight count includes them, and do not delete the whole drop-in directory blindly.

Backups are stored under `/var/lib/outer-vpn/backups/` in root-only, timestamped transaction directories. Install/apply, migration, and uninstall preserve prior files there; rollback errors identify the relevant backup path. Uninstall does not automatically resurrect the old legacy gateway. Review backups before any manual restoration, and keep them private because they may contain the VLESS credential.

## Safe verification and recovery

For a local, offline inspection, close network-using apps and keep Proton disconnected before `start`. Default bootstrap permits Internet access through the outer tunnel, so do not browse while Proton is unverified if you do not want sites to see the outer IP. Check local state only:

```sh
sudo python3 outer.py status
sudo nft list table inet outer_vpn_guard
ip -4 route show default
ip -6 rule show
```

The status should say `Proton WireGuard: not verified` until the configured interface is up. Then connect the Proton app with WireGuard UDP and inspect the exact interface and peer state (replace `proton0` if configured differently):

```sh
ip -d link show dev proton0
sudo wg show proton0 endpoints
sudo wg show proton0 latest-handshakes
sudo python3 outer.py status
```

Confirm the interface is WireGuard and UP, the peer IPv4 endpoints are allowlisted, the handshake is recent, and `status` reports `Traffic mode: Proton only`. `Proton WireGuard: verified` alone does not prove a handshake. Only after that, you may make one deliberate external IP-check request and compare it with Proton's exit address. **If protection is not working, the check service can see the actual egress IP.** This test cannot prove kill-switch compatibility:

```sh
python3 -c 'import urllib.request; print(urllib.request.urlopen("https://api.ipify.org", timeout=10).read().decode())'
```

Do not send sensitive traffic during testing. If Proton disconnects after a handshake, outer-bootstrap access stays closed; the GUI may need Proton to reconnect without fresh API/DNS access. To deliberately return to bootstrap, stop and start the gateway only after securing/disconnecting ordinary network access: stopping removes the guard.

After a failure during gateway setup or operation, a traffic guard may remain until explicit cleanup; the unit does not auto-restart. Failures before nftables validation completes leave networking as it was, without installing a new guard. Inspect locally, then retry the journaled cleanup:

```sh
sudo python3 outer.py status
sudo systemctl status outer-vpn.service --no-pager
sudo journalctl -u outer-vpn.service -b --no-pager
sudo journalctl -t outer-vpn -b --no-pager
sudo python3 outer.py stop
```

`stop` is the supported recovery path and is safe to retry. If legacy migration was interrupted before the new service became ready, it restores the saved legacy files and service state before releasing the guard; completed migrations are not undone. Do not flush nftables, delete routes, or remove the namespace manually while a recovery journal remains; that can defeat the guard. `stop` attempts to remove owned guards even if another rollback operation fails, and reports any remaining error; inspect `status` and retry from a local console. A guard with no recovery journal is reported as untracked and is not deleted automatically, because ownership cannot be established. Once stop/uninstall completes, the guard is gone and ordinary host routing is restored; applications may then use the regular, non-Proton route.

After a failed `start`, run `sudo python3 outer.py status`, then `sudo python3 outer.py stop`, and inspect status again. The status reports actual nft guard tables separately from the recovery journal. Restored Internet access may use the ordinary, non-Proton route and expose the normal public IP. Runtime behavior on the reported nftables 1.1.6 laptop has not been verified. Test only from a local console or TTY—not over SSH—with network-using apps closed, Proton disconnected, and the recovery command ready.

## Tests

Run the local standard-library suite without root:

```sh
python3 -m py_compile outer.py tests/test_config.py
python3 -m unittest discover -s tests -v
```

The tests cover VLESS/environment parsing, IPv4 endpoint validation, generated core configs, checksum verification, idempotency, migration, and rollback. They do not change host networking, invoke privileged system commands, contact servers, or download release binaries.

### References

- [sing-box TUN and auto-redirect](https://sing-box.sagernet.org/configuration/inbound/tun/)
- [Xray VLESS and Vision UDP/443](https://xtls.github.io/en/config/outbounds/vless.html)
- [Proton kill switch behavior](https://protonvpn.com/support/what-is-kill-switch)
- [nftables manual and check mode](https://netfilter.org/projects/nftables/manpage.html)
