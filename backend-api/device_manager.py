"""Per-device adaptive profiles and policy routing."""
from __future__ import annotations

import os
import re
import ipaddress
import subprocess
import threading
import time
from typing import Any, Callable

import saw

# Filled by app.py after import (avoids circular imports at load)
_ctx: dict[str, Any] = {}


def bind_context(**kwargs) -> None:
    _ctx.update(kwargs)


def _log(msg: str) -> None:
    fn = _ctx.get("log_event")
    if fn:
        fn(msg)


def _run(cmd, timeout=8, input_text=None):
    return _ctx["run"](cmd, timeout=timeout, input_text=input_text)


def _sudo_ip(args, timeout=5):
    return _ctx["sudo_ip"](args, timeout=timeout)


def _mikrotik(cmd: str, timeout: int = 8) -> str:
    return _ctx["mikrotik_run"](cmd, timeout=timeout)


def _resolve_iface(rid: str, meta: dict) -> str:
    return _ctx["resolve_iface"](rid, meta)


def _iface_exists(iface: str) -> bool:
    return _ctx["iface_exists"](iface)


def _calculate_saw(metrics, sec, rel, profile_key: str, custom_weights=None):
    return _ctx["calculate_saw_for"](metrics, sec, rel, profile_key, custom_weights)


DEVICES: dict[str, dict] = {}
DEVICES_LOCK = threading.Lock()
_NEXT_MARK = 110
_NEXT_REMOTE_MARK = 112
_KIYO_PHONE_TABLES = frozenset({110, 111})
_REMOTE_MARK_MIN = 112
_GATEWAY_IP = "192.168.50.10"
_MIKROTIK_IP = "192.168.50.1"
_LAN_IFACE = "enp0s8"
_NAT_UPLINK = "enp0s3"  # VirtualBox NAT — emergency internet when MikroTik path is down
_ZT_CLOUD_NWID = "cf719fd540b50c25"
_ZT_CLOUD_IFACE = "ztdiysvwlf"
_ZT_CLOUD_IFACES = frozenset({"ztdiysvwlf", "ztnfak7ul7"})  # current + leftover name
_ZT_CLOUD_CIDR = "10.61.136.0/24"  # leftover overlay; live iface /24 is also matched
_ZT_CLOUD_NET = ipaddress.ip_network(_ZT_CLOUD_CIDR)
_ZT_CLOUD_SKIP = frozenset({
    "10.61.136.0", "10.61.136.1", "10.61.136.10", "10.61.136.255",
})
_ZT_LIVE_CACHE: tuple[float, list] = (0.0, [])


def _used_marks() -> set[int]:
    out: set[int] = set()
    for d in DEVICES.values():
        try:
            out.add(int(d["mark"]))
        except Exception:
            continue
    return out


def _alloc_mark(*, remote: bool = False) -> int:
    """fwmark == table. LAN starts at 110. Cloud ZT remotes start at 112 (never 110/111)."""
    global _NEXT_MARK, _NEXT_REMOTE_MARK
    used = _used_marks()
    if remote:
        m = max(_REMOTE_MARK_MIN, _NEXT_REMOTE_MARK)
        while m in used or m in _KIYO_PHONE_TABLES:
            m += 1
        _NEXT_REMOTE_MARK = m + 1
        return m
    m = max(110, _NEXT_MARK)
    while m in used:
        m += 1
    _NEXT_MARK = m + 1
    return m


def _sudo_run(args: list[str], timeout: int = 5):
    sudo = _ctx.get("SUDO") or "sudo"
    passwd = _ctx.get("SUDO_PASS") or "user"
    return _run([sudo, "-S", *args], input_text=passwd + "\n", timeout=timeout)


def _iptables_ensure(args: list[str], insert: bool = True) -> None:
    """Ensure an iptables rule exists. Check with -C; add with -I 1 or -A."""
    check = _sudo_run(["iptables", "-C", *args])
    if check.returncode == 0:
        return
    if insert:
        _sudo_run(["iptables", "-I", args[0], "1", *args[1:]])
    else:
        _sudo_run(["iptables", "-A", *args])


_VBOX_NAT_GW = "10.0.2.2"
# Ifaces that must never be the host default (OpenConnect/WG steal → LAN blackhole).
_VPN_DEFAULT_IFACES = (
    "tun1", "wg0", "tun0", "sstp0", "vti0", "nebula1", "tap_soft",
    "ztdiysvwlf", "ztnfak7ul7",
)
_ZT_LAB_NET = "10.66.73."


def _is_vpn_tunnel_dev(dev: str) -> bool:
    """True if this device must never be Ubuntu's main default."""
    if not dev:
        return False
    if dev in _VPN_DEFAULT_IFACES:
        return True
    return dev.startswith("zt")


def zerotier_lab_client_iface() -> str | None:
    """Host ZT iface with the lab overlay IP (exit is 10.66.73.1 in netns).

    Prefer ztfn5ujzh6. Never the cloud member (ztdiysvwlf / leftover ztnfak7ul7).
    """
    if not _ctx.get("run"):
        return None
    r = _run(["ip", "-o", "-4", "addr", "show"], timeout=3)
    found: list[str] = []
    for ln in (r.stdout or "").splitlines():
        if _ZT_LAB_NET not in ln:
            continue
        parts = ln.split()
        if len(parts) < 2:
            continue
        name = parts[1].split("@")[0]
        if not name.startswith("zt"):
            continue
        if name in _ZT_CLOUD_IFACES:
            continue
        found.append(name)
    for name in found:
        if name == "ztfn5ujzh6":
            return name
    return found[0] if found else None


# Lab / host-only / loopback / VBox NAT — not "road warrior".
_VIEWER_ON_LAN = (
    ipaddress.ip_network("192.168.50.0/24"),
    ipaddress.ip_network("192.168.56.0/24"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.2.0/24"),
    ipaddress.ip_network("::1/128"),
)
_VIEWER_ZEROTIER_LAB = ipaddress.ip_network("10.66.73.0/24")
# Hallway overlay (do not trust X-Forwarded-For; Host is the Ubuntu ZT UI IP).
_ZT_HALLWAY_NETS = (
    ipaddress.ip_network("10.71.80.0/24"),
    ipaddress.ip_network("10.61.136.0/24"),
)
_ZT_HALLWAY_HOST = "10.71.80.237"


def _live_cloud_iface_cidrs() -> list:
    """IPv4 networks on the cloud ZT iface (after Central Auth). Cached briefly."""
    global _ZT_LIVE_CACHE
    now = time.time()
    cached_ts, cached_nets = _ZT_LIVE_CACHE
    if cached_nets and (now - cached_ts) < 8.0:
        return list(cached_nets)
    nets: list = []
    if not _ctx.get("run"):
        _ZT_LIVE_CACHE = (now, nets)
        return nets
    try:
        r = _run(["ip", "-o", "-4", "addr", "show", "dev", _ZT_CLOUD_IFACE], timeout=3)
    except Exception:
        _ZT_LIVE_CACHE = (now, nets)
        return nets
    blob = (r.stdout or "") + (r.stderr or "")
    for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", blob):
        ip_s, plen_s = m.group(1), m.group(2)
        try:
            plen = int(plen_s)
            if plen == 32:
                plen = 24
            net = ipaddress.ip_network(f"{ip_s}/{plen}", strict=False)
            if net.prefixlen < 16:
                continue
            if net in (_VIEWER_ZEROTIER_LAB,):
                continue
            if str(net).startswith("192.168.50.") or str(net).startswith("192.168.56."):
                continue
            if net not in nets:
                nets.append(net)
        except ValueError:
            continue
    _ZT_LIVE_CACHE = (now, list(nets))
    return nets


def zt_cloud_networks() -> list:
    """Cloud overlay CIDRs: leftover 10.61.136.0/24 plus whatever is on ztdiysvwlf."""
    nets = [_ZT_CLOUD_NET]
    for net in _live_cloud_iface_cidrs():
        if net not in nets:
            nets.append(net)
    return nets


def _zt_cloud_skip_ips() -> set[str]:
    skip = set(_ZT_CLOUD_SKIP)
    for net in zt_cloud_networks():
        try:
            skip.add(str(net.network_address))
            skip.add(str(net.broadcast_address))
            skip.add(str(net.network_address + 1))
        except Exception:
            continue
    if not _ctx.get("run"):
        return skip
    try:
        r = _run(["ip", "-o", "-4", "addr", "show", "dev", _ZT_CLOUD_IFACE], timeout=3)
        for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", (r.stdout or "")):
            skip.add(m.group(1))
    except Exception:
        pass
    return skip


def _host_without_port(host_header: str) -> str:
    """Host header without port. Never reads X-Forwarded-*. """
    raw = (host_header or "").strip().split("%")[0]
    if not raw:
        return ""
    if raw.startswith("["):
        end = raw.find("]")
        return raw[1:end] if end > 0 else raw
    if raw.count(":") == 1:
        return raw.split(":", 1)[0].strip()
    return raw


def is_overlay_remote(remote_addr: str, host_header: str = "") -> bool:
    """True for ZeroTier hallway: overlay /24 peer, or Host is Ubuntu ZT IP.

    Uses the TCP peer (remote_addr) and Host header only — not X-Forwarded-For.
    """
    rip = (remote_addr or "").split("%")[0].strip()
    try:
        addr = ipaddress.ip_address(rip)
        if any(addr in net for net in _ZT_HALLWAY_NETS):
            return True
    except ValueError:
        pass
    return _host_without_port(host_header) == _ZT_HALLWAY_HOST


def classify_viewer(ip: str) -> dict:
    """Where the browser's TCP peer sits (quiet off-LAN UI line)."""
    raw = (ip or "").split("%")[0].strip()
    out = {"off_lan": False, "via": "unknown", "limited": False, "ip": raw}
    if not raw:
        return out
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return out
    if addr.is_loopback:
        out["via"] = "local"
        return out
    for net in _VIEWER_ON_LAN:
        if addr in net:
            n = str(net)
            if n.startswith("192.168.50."):
                out["via"] = "lan"
            elif n.startswith("192.168.56."):
                out["via"] = "hostonly"
            else:
                out["via"] = "lab"
            return out
    zt_nets = [_VIEWER_ZEROTIER_LAB, *zt_cloud_networks()]
    for net in zt_nets:
        if addr in net:
            out["off_lan"] = True
            out["via"] = "zerotier"
            out["limited"] = True
            return out
    out["off_lan"] = True
    out["via"] = "remote"
    out["limited"] = True
    return out


def is_zt_cloud_client(ip: str) -> bool:
    """True for a road-warrior on the cloud overlay (not Ubuntu / .0 / .1 / .255)."""
    raw = (ip or "").split("%")[0].strip()
    if not raw or raw in _zt_cloud_skip_ips():
        return False
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return any(addr in net for net in zt_cloud_networks())


def is_lan_client(ip: str) -> bool:
    """True for a lab DHCP/Wi-Fi client (not MikroTik .1 or Ubuntu .10)."""
    raw = (ip or "").split("%")[0].strip()
    if not raw.startswith("192.168.50."):
        return False
    return raw not in ("192.168.50.0", "192.168.50.1", "192.168.50.10", "192.168.50.255")


def is_steerable_client(ip: str) -> bool:
    """LAN client or cloud ZT remote — never Ubuntu, MikroTik, or lab overlay 10.66.73.x."""
    return is_lan_client(ip) or is_zt_cloud_client(ip)


def live_ip_for_binding(
    ip: str | None,
    mac: str | None = None,
    viewer_ip: str | None = None,
) -> str | None:
    """Follow a bound PC when DHCP hands out a new 192.168.50.x (or overlay) address.

    Prefer an online row with the same MAC. If the saved IP is dead, adopt
    this browser only when it is the same host (same MAC or same IP).
    """
    saved = (ip or "").strip() or None
    mac_u = (mac or "").strip().upper()
    viewer = (viewer_ip or "").strip() or None
    with DEVICES_LOCK:
        if not mac_u and saved and saved in DEVICES:
            mac_u = (DEVICES[saved].get("mac") or "").strip().upper()

        def _online_with_mac(want: str) -> str | None:
            for d in DEVICES.values():
                if not d.get("online"):
                    continue
                if (d.get("mac") or "").strip().upper() == want:
                    return d.get("ip")
            return None

        if mac_u:
            hit = _online_with_mac(mac_u)
            if hit:
                return hit
        if saved:
            d = DEVICES.get(saved)
            if d and d.get("online"):
                return saved
        # Adopt this browser only when it is the same host (same MAC, or same IP).
        # Never steal the only other Ethernet client on the MikroTik.
        if viewer and is_steerable_client(viewer):
            if viewer == saved:
                return viewer
            vd = DEVICES.get(viewer) or {}
            vmac = (vd.get("mac") or "").strip().upper()
            if mac_u and vmac and vmac == mac_u:
                return viewer
    return saved


def _drop_vbox_stolen_mikrotik_route() -> None:
    """Remove VBox NAT host-routes that steal lab WAN / MikroTik off enp0s8.

    VBox NAT DHCP advertises the Windows host DNS (192.168.50.1). networkd
    then installs `192.168.50.1 via 10.0.2.2 dev enp0s3`. WireGuard's
    endpoint is that same .1, so tunnel packets hairpin through Windows and
    blackhole any client whose gateway is Ubuntu .10.

    Static DNS 8.8.8.8/1.1.1.1 on enp0s3 is worse: networkd installs
    `8.8.8.8 via 10.0.2.2 proto dhcp`. forwarding_ready() then pings a
    NAT blackhole even though MikroTik WAN on enp0s8 works.
    """
    _sudo_run(["ip", "route", "del", _MIKROTIK_IP, "via", _VBOX_NAT_GW, "dev", _NAT_UPLINK])
    for host in ("8.8.8.8", "1.1.1.1"):
        _sudo_run(["ip", "route", "del", host, "via", _VBOX_NAT_GW, "dev", _NAT_UPLINK])
    # Dead leftover default on the same NIC; metric 50 would win if MikroTik's 10 is gone.
    _sudo_run(["ip", "route", "del", "default", "via", "192.168.100.1", "dev", _LAN_IFACE])


def _masquerade_out(iface: str) -> bool:
    r = _sudo_run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
    return r.returncode == 0


def _clamp_tunnel_mss(iface: str) -> None:
    """VTI/TAP MTU is under 1500; unclamped SYN MSS blackholes large HTTP."""
    if not iface:
        return
    _iptables_ensure([
        "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
        "-o", iface, "-j", "TCPMSS", "--clamp-mss-to-pmtu",
    ], insert=True)


def is_client_wan_iface(iface: str) -> bool:
    """Live WAN tunnels LAN clients (and Fast.com) actually ride."""
    name = (iface or "").strip()
    if not name or name in _NOT_TUNNEL_IFACES or name in _LAB_ONLY_IFACES:
        return False
    if _client_egress_denied(name) or _iface_is_dummy(name):
        return False
    return _is_vpn_tunnel_dev(name)


def _dev_token(stdout: str) -> str:
    parts = (stdout or "").split()
    if "dev" in parts:
        i = parts.index("dev")
        if i + 1 < len(parts):
            return parts[i + 1]
    return ""


def _route_get_dev(dst: str) -> str:
    r = _run(["ip", "route", "get", dst], timeout=3)
    return _dev_token(getattr(r, "stdout", None) or "")


def _main_default_devs() -> list[str]:
    r = _run(["ip", "route", "show", "table", "main"], timeout=3)
    out = []
    for ln in (r.stdout or "").splitlines():
        if ln.startswith("default"):
            dev = _dev_token(ln)
            if dev:
                out.append(dev)
    return out


def _restore_lab_default() -> None:
    """Keep host default on MikroTik/enp0s8, not a VPN tunnel or VBox DNS route.

    Only delete VPN defaults that `ip route show table main` actually lists.
    A bare `del default dev wg0` can also drop client table 110+ `default dev wg0`.
    """
    _drop_vbox_stolen_mikrotik_route()
    for dev in _main_default_devs():
        if _is_vpn_tunnel_dev(dev):
            _sudo_run(["ip", "route", "del", "default", "dev", dev, "table", "main"])
            _log(f"Uplink: dropped stolen main default via {dev}")
    _sudo_run(["ip", "route", "del", "default", "via", "192.168.100.1", "dev", _LAN_IFACE, "table", "main"])
    _sudo_run([
        "ip", "route", "replace", "default",
        "via", _MIKROTIK_IP, "dev", _LAN_IFACE, "metric", "10", "table", "main",
    ])
    _sudo_run([
        "ip", "route", "replace", "default",
        "via", _VBOX_NAT_GW, "dev", _NAT_UPLINK, "metric", "100", "table", "main",
    ])
    drop_leftover_host_dns_policy()


def drop_leftover_host_dns_policy() -> None:
    """Remove leftover `to 1.1.1.1 lookup 200` (demo rule that sent 1.1.1.1 via WG)."""
    for _ in range(8):
        r = _sudo_run(["ip", "rule", "del", "to", "1.1.1.1", "table", "200"])
        if getattr(r, "returncode", 1) != 0:
            break


def protect_host_default() -> None:
    """Public alias: Ubuntu default must stay via 192.168.50.1 dev enp0s8."""
    _restore_lab_default()


def ensure_forwarding() -> None:
    """Make Ubuntu able to route LAN clients toward VPNs / MikroTik / NAT uplink."""
    _sudo_run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    _sudo_run(["sysctl", "-w", "net.ipv4.conf.all.forwarding=1"])
    _sudo_run(["sysctl", "-w", "net.ipv4.conf.default.forwarding=1"])
    _sudo_run(["sysctl", "-w", f"net.ipv4.conf.{_LAN_IFACE}.forwarding=1"])
    # Loose rp_filter: WAN replies return on a tunnel while the host default
    # is still MikroTik/enp0s8. Strict (1) drops those replies (LAN blackhole).
    _sudo_run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=2"])
    _sudo_run(["sysctl", "-w", "net.ipv4.conf.default.rp_filter=2"])
    _sudo_run(["sysctl", "-w", f"net.ipv4.conf.{_LAN_IFACE}.rp_filter=2"])
    tuns = list(_VPN_DEFAULT_IFACES)
    zt_lab = zerotier_lab_client_iface()
    if zt_lab and zt_lab not in tuns:
        tuns.append(zt_lab)
    for tun in tuns:
        _sudo_run(["sysctl", "-w", f"net.ipv4.conf.{tun}.rp_filter=2"])
        _sudo_run(["sysctl", "-w", f"net.ipv4.conf.{tun}.forwarding=1"])
    _restore_lab_default()

    # NAT: MikroTik path (enp0s8) + VBox NAT uplink fallback (enp0s3)
    for out_if in (_LAN_IFACE, _NAT_UPLINK):
        check = _sudo_run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", out_if, "-j", "MASQUERADE"])
        if check.returncode != 0:
            _sudo_run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", out_if, "-j", "MASQUERADE"])

    # FORWARD accepts MUST be inserted before Docker's terminal DROP
    for rule in (
        ["FORWARD", "-i", _LAN_IFACE, "-j", "ACCEPT"],
        ["FORWARD", "-o", _LAN_IFACE, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ["FORWARD", "-i", _LAN_IFACE, "-o", _NAT_UPLINK, "-j", "ACCEPT"],
        ["FORWARD", "-i", _NAT_UPLINK, "-o", _LAN_IFACE, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        ["FORWARD", "-i", _LAN_IFACE, "-o", _LAN_IFACE, "-j", "ACCEPT"],
    ):
        _iptables_ensure(rule, insert=True)

    # Default: MikroTik when reachable (give ARP/ICMP 2s). Do not flap to
    # VBox NAT on a single 1s timeout — that is what made ping 8.8.8.8 fail.
    mikrotik_up = _run(["ping", "-c", "1", "-W", "2", _MIKROTIK_IP], timeout=5).returncode == 0
    if mikrotik_up:
        _restore_lab_default()
        _log("Uplink: MikroTik primary, VBox NAT backup")
    else:
        _sudo_run(["ip", "route", "del", "default", "via", _MIKROTIK_IP, "dev", _LAN_IFACE])
        _sudo_run(["ip", "route", "replace", "default", "via", _VBOX_NAT_GW, "dev", _NAT_UPLINK, "metric", "10"])
        _sudo_run(["ip", "route", "replace", "default", "via", _MIKROTIK_IP, "dev", _LAN_IFACE, "metric", "200"])
        _log("Uplink: MikroTik unreachable — VBox NAT primary (internet first)")


_FWD_READY_CACHE: tuple[float, bool] | None = None


def _ping_wan_via_lan() -> bool:
    """Ping 8.8.8.8 out enp0s8. Retry: lab RTT can exceed 300ms with occasional loss."""
    for _ in range(3):
        r = _run(
            ["ping", "-I", _LAN_IFACE, "-c", "1", "-W", "2", "8.8.8.8"],
            timeout=5,
        )
        if r.returncode == 0:
            return True
    return False


def ping_wan_via_lan() -> bool:
    """Public alias: Ubuntu can reach 8.8.8.8 via enp0s8 (not a VPN)."""
    return _ping_wan_via_lan()


def forwarding_ready() -> bool:
    """True when Ubuntu can hairpin LAN clients out enp0s8 to the internet.

    Enough for DHCP .10: ip_forward + MASQUERADE out enp0s8 + ping 8.8.8.8
    via the lab NIC (not via a VPN tunnel or VBox NAT DNS host-route).
    Does not require vpn_carries_internet — client tables stay on MikroTik .1.
    """
    global _FWD_READY_CACHE
    now = time.time()
    if _FWD_READY_CACHE:
        ts, ok = _FWD_READY_CACHE
        ttl = 8.0 if ok else 0.4
        if (now - ts) < ttl:
            return ok
    try:
        _restore_lab_default()
    except Exception:
        try:
            _drop_vbox_stolen_mikrotik_route()
        except Exception:
            pass
    fwd = _run(["sysctl", "-n", "net.ipv4.ip_forward"], timeout=3)
    if fwd.returncode != 0 or (fwd.stdout or "").strip() != "1":
        _log("forwarding_ready FAIL: ip_forward != 1")
        _FWD_READY_CACHE = (now, False)
        return False
    if not _masquerade_out(_LAN_IFACE):
        _log("forwarding_ready FAIL: no MASQUERADE out enp0s8")
        _FWD_READY_CACHE = (now, False)
        return False
    # Bind to enp0s8 so a stolen default via tun1/wg0 cannot fake WAN.
    if not _ping_wan_via_lan():
        _log("forwarding_ready FAIL: ping 8.8.8.8 via enp0s8")
        _FWD_READY_CACHE = (now, False)
        return False
    _FWD_READY_CACHE = (now, True)
    return True


def set_mikrotik_dhcp_gateway(*, force: bool = False) -> bool:
    """Point lab DHCP clients at Ubuntu so per-device VPN routes apply.

    Opt-in / safety: refuses unless forwarding is verified (or force=True).
    Returns True if MikroTik DHCP gateway was set to Ubuntu.
    """
    if not force and not forwarding_ready():
        _log(
            f"DHCP gateway NOT set to {_GATEWAY_IP}: "
            "forwarding/uplink not verified (internet-first safety)"
        )
        return False
    set_cmd = (
        f'/ip dhcp-server network set [find address="192.168.50.0/24"] '
        f'gateway={_GATEWAY_IP} dns-server={_MIKROTIK_IP}'
    )
    gw = None
    for _ in range(3):
        _mikrotik(set_cmd, timeout=12)
        gw = get_mikrotik_dhcp_gateway()
        if gw == _GATEWAY_IP:
            _log(f"DHCP gateway set to {_GATEWAY_IP} (per-device routing)")
            return True
        time.sleep(0.4)
    _log(f"DHCP SET WARN: wanted {_GATEWAY_IP}, MikroTik still {gw}")
    return False


def ensure_mikrotik_dns_server() -> None:
    """Point lab DHCP DNS at MikroTik so Auto can see client queries."""
    try:
        _mikrotik(
            f'/ip dhcp-server network set [find address="192.168.50.0/24"] '
            f"dns-server={_MIKROTIK_IP}"
        )
        _log(f"DHCP dns-server set to {_MIKROTIK_IP} (Auto DNS hints)")
    except Exception as e:
        _log(f"DHCP DNS WARN: {e}")


def ensure_mikrotik_dns_query_log() -> None:
    """Best-effort per-client DNS: RouterOS query-logging + a memory log rule."""
    try:
        _mikrotik("/ip dns set allow-remote-requests=yes")
    except Exception:
        pass
    try:
        # RouterOS 7 — ignored on v6
        _mikrotik("/ip dns set query-logging=yes")
    except Exception:
        pass
    try:
        out = _mikrotik("/system logging print")
        blob = (out or "").lower()
        if "autovpn-dns" not in blob:
            _mikrotik(
                '/system logging add topics=dns,!packet action=memory '
                'prefix=autovpn-dns'
            )
            _log("MikroTik DNS query log enabled (per-device Auto)")
    except Exception as e:
        _log(f"DNS LOG WARN: {e}")


def ensure_mikrotik_lab() -> None:
    """Idempotent lab DNS + hotspot off. Does not change the DHCP gateway."""
    ensure_mikrotik_dns_server()
    ensure_mikrotik_dns_query_log()
    try:
        _mikrotik("/ip dns set allow-remote-requests=yes")
        out = _mikrotik("/ip dns static print")
        wanted = ("autovpn", "autovpn.lab", "www.autovpn.lab")
        missing = [n for n in wanted if n not in (out or "")]
        for name in missing:
            _mikrotik(
                f'/ip dns static add name={name} address={_GATEWAY_IP} '
                f"ttl=1d comment=AutoVPN-UI"
            )
        _mikrotik("/ip hotspot set [find] disabled=yes")
        if missing:
            _log("MikroTik static DNS added: " + ", ".join(missing))
    except Exception as e:
        _log(f"MikroTik lab DNS WARN: {e}")


def revert_mikrotik_dhcp_gateway() -> bool:
    """Restore MikroTik as DHCP default gateway so clients get internet without Ubuntu."""
    try:
        _mikrotik(
            f'/ip dhcp-server network set [find address="192.168.50.0/24"] '
            f'gateway={_MIKROTIK_IP} dns-server={_MIKROTIK_IP}'
        )
        _log(f"DHCP gateway reverted to {_MIKROTIK_IP} (direct MikroTik internet)")
        return True
    except Exception as e:
        _log(f"DHCP REVERT FAILED: {e}")
        return False


def get_mikrotik_dhcp_gateway() -> str | None:
    """Best-effort parse of current DHCP network gateway for 192.168.50.0/24."""
    try:
        out = _mikrotik("/ip dhcp-server network print detail")
    except Exception:
        return None
    # Prefer the 192.168.50.0/24 block if present
    blocks = re.split(r"\n\s*\d+\s+", "\n" + out)
    for block in blocks:
        if "192.168.50.0/24" not in block and "address=192.168.50.0/24" not in block:
            continue
        m = re.search(r"gateway=(\d+\.\d+\.\d+\.\d+)", block)
        if m:
            return m.group(1)
    m = re.search(r"gateway=(\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


_LEASE_FAIL_MARKERS = (
    "timed out", "connection refused", "no route to host",
    "connection reset", "permission denied", "connection timed out",
    "network is unreachable",
)
_ONLINE_GRACE_SEC = 180.0


def fetch_dhcp_leases() -> tuple[list[dict], bool]:
    """Return (leases, ok). ok=False means MikroTik dump failed — do not mass-offline."""
    try:
        out = _mikrotik("/ip dhcp-server lease print detail")
    except Exception:
        return [], False
    text = out or ""
    low = text.lower()
    if not text.strip():
        return [], False
    if any(m in low for m in _LEASE_FAIL_MARKERS) and "address=" not in low:
        return [], False
    blocks = re.split(r"\n\s*\d+\s+", "\n" + text)
    leases = []
    for block in blocks:
        addr_m = re.search(r"address=(\d+\.\d+\.\d+\.\d+)", block)
        if not addr_m:
            continue
        ip = addr_m.group(1)
        if not ip.startswith("192.168.50."):
            continue
        if ip.endswith(".1") or ip == _GATEWAY_IP:
            continue
        mac_m = re.search(r"mac-address=([0-9A-Fa-f:]+)", block)
        host_m = re.search(r'host-name="([^"]+)"', block) or re.search(r"host-name=([^\s]+)", block)
        status_m = re.search(r"status=(\w+)", block)
        leases.append({
            "ip": ip,
            "mac": (mac_m.group(1) if mac_m else "").upper(),
            "name": (host_m.group(1) if host_m else "") or guess_name(ip, mac_m.group(1) if mac_m else ""),
            "status": status_m.group(1) if status_m else "unknown",
        })
    return leases, True


def parse_dhcp_leases() -> list[dict]:
    leases, _ok = fetch_dhcp_leases()
    return leases


_LAB_PING_HOSTS = (
    ("192.168.50.253", "Phone"),
    ("192.168.50.254", "kiyo"),
)
_PING_LIVE: dict[str, tuple[float, bool]] = {}
_PING_LIVE_TTL = 25.0


def lab_host_is_reachable(ip: str) -> bool:
    """ICMP to a known lab host. Cached. Fail closed. Not WAN / FORWARD proof."""
    if not ip or not _ctx.get("run"):
        return False
    now = time.time()
    cached = _PING_LIVE.get(ip)
    if cached and (now - cached[0]) < _PING_LIVE_TTL:
        return cached[1]
    try:
        r = _run(["ping", "-c", "1", "-W", "1", ip], timeout=3)
        ok = r.returncode == 0
    except Exception:
        ok = False
    _PING_LIVE[ip] = (now, ok)
    return ok


def lan_neighbors() -> dict[str, str]:
    """IP -> MAC for lab neighbors that look alive (ARP/NDISC)."""
    r = _run(["ip", "neigh", "show", "dev", _LAN_IFACE], timeout=3)
    out = (r.stdout or "") + (r.stderr or "")
    found: dict[str, str] = {}
    alive = {"REACHABLE", "DELAY", "STALE", "PROBE", "PERMANENT"}
    for ln in out.splitlines():
        # 192.168.50.253 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        m = re.search(
            r"(192\.168\.50\.\d+)\s+.*lladdr\s+([0-9a-fA-F:]+)\s+(\w+)",
            ln,
        )
        if not m:
            continue
        ip, mac, st = m.group(1), m.group(2).upper(), m.group(3).upper()
        if ip.endswith(".1") or ip == _GATEWAY_IP:
            continue
        if st in alive:
            found[ip] = mac
    return found


def _device_has_recent_traffic(ip: str) -> bool:
    try:
        return float(sample_device_lan_mbps(ip) or 0.0) >= 0.02
    except Exception:
        return False


def guess_name(ip: str, mac: str) -> str:
    if is_zt_cloud_client(ip):
        return "Remote"
    if ip.endswith(".254"):
        return "kiyo"
    if ip.endswith(".253"):
        return "Phone"
    short = mac.replace(":", "")[-4:] if mac else ip.split(".")[-1]
    return f"Device-{short or ip.split('.')[-1]}"


def _new_device_row(
    ip: str,
    *,
    name: str,
    mark: int,
    mac: str = "",
    evidence: str = "",
    egress_reason: str = "",
    online: bool = True,
    last_seen: float | None = None,
) -> dict:
    now = time.time()
    if last_seen is None:
        last_seen = now if online else 0.0
    kind = "remote" if is_zt_cloud_client(ip) else "lan"
    return {
        "ip": ip,
        "mac": mac or "",
        "name": name or guess_name(ip, mac or ""),
        "kind": kind,
        "profile": "auto",
        "auto_detected": "balanced",
        "evidence": evidence or ("ZeroTier overlay" if kind == "remote" else "New device"),
        "active_regime": "my-wireguard",
        "active_name": "WireGuard",
        "mark": mark,
        "table": mark,
        "pending": None,
        "pending_hits": 0,
        "last_switch": 0.0,
        "last_seen": last_seen,
        "online": online,
        "metrics": [],
        "custom_weights": None,
        "force_regime": None,
        "egress": "mikrotik",
        "egress_via": _MIKROTIK_IP,
        "egress_dev": _LAN_IFACE,
        "egress_reason": egress_reason or (
            "new remote — MikroTik until Gateway On" if kind == "remote"
            else "new device — MikroTik until Gateway On"
        ),
    }


def ensure_runtime_device(
    ip: str,
    *,
    name: str = "",
    mac: str = "",
    evidence: str = "",
    egress_reason: str = "",
    online: bool = True,
    rename: bool = False,
) -> dict:
    """Create or touch a device. Overlay IPs get mark/table 112+ (never 110/111)."""
    with DEVICES_LOCK:
        return _ensure_runtime_device_locked(
            ip,
            name=name,
            mac=mac,
            evidence=evidence,
            egress_reason=egress_reason,
            online=online,
            rename=rename,
        )


def _ensure_runtime_device_locked(
    ip: str,
    *,
    name: str = "",
    mac: str = "",
    evidence: str = "",
    egress_reason: str = "",
    online: bool = True,
    rename: bool = False,
) -> dict:
    now = time.time()
    if ip in DEVICES:
        d = DEVICES[ip]
        if mac:
            d["mac"] = mac
        if rename and name:
            d["name"] = name
        elif name and (not d.get("name") or str(d.get("name")).startswith("Device-")):
            d["name"] = name
        if online:
            d["online"] = True
            d["last_seen"] = now
        if not d.get("kind"):
            d["kind"] = "remote" if is_zt_cloud_client(ip) else "lan"
        return d
    mark = _alloc_mark(remote=is_zt_cloud_client(ip))
    row = _new_device_row(
        ip,
        name=name or guess_name(ip, mac),
        mark=mark,
        mac=mac,
        evidence=evidence,
        egress_reason=egress_reason,
        online=online,
        last_seen=(now if online else 0.0),
    )
    DEVICES[ip] = row
    _log(f"DEVICE ADD {row['name']} ({ip}) mark={mark}")
    return row


def zt_cloud_neighbors() -> dict[str, str]:
    """IP -> MAC on the cloud overlay iface. Not DHCP. Empty if iface/runtime missing."""
    if not _ctx.get("run"):
        return {}
    r = _run(["ip", "neigh", "show", "dev", _ZT_CLOUD_IFACE], timeout=3)
    out: dict[str, str] = {}
    alive = {"REACHABLE", "DELAY", "STALE", "PROBE", "PERMANENT"}
    skip = _zt_cloud_skip_ips()
    for ln in ((r.stdout or "") + (r.stderr or "")).splitlines():
        m = re.search(
            r"(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-fA-F:]+)\s+(\w+)",
            ln,
        )
        if not m:
            continue
        ip, mac, st = m.group(1), m.group(2).upper(), m.group(3).upper()
        if ip in skip:
            continue
        if ip.startswith(("10.66.73.", "192.168.50.", "192.168.56.", "10.0.2.", "127.")):
            continue
        if st in alive:
            out[ip] = mac
    return out


def _zt_overlay_ips_from_conntrack() -> set[str]:
    found: set[str] = set()
    try:
        blob = _conntrack_blob()
    except Exception:
        return found
    for m in re.finditer(r"\bsrc=(\d+\.\d+\.\d+\.\d+)\b", blob or ""):
        ip = m.group(1)
        if is_zt_cloud_client(ip):
            found.add(ip)
    return found


def zt_cloud_peers() -> dict[str, str]:
    """Connected cloud ZT overlay IPs -> MAC (MAC may be empty). Not DHCP."""
    out: dict[str, str] = {}
    skip = _zt_cloud_skip_ips()
    try:
        out.update(zt_cloud_neighbors())
    except Exception:
        pass
    try:
        for ip in _zt_overlay_ips_from_conntrack():
            out.setdefault(ip, "")
    except Exception:
        pass
    return {ip: mac for ip, mac in out.items() if ip not in skip}


def sync_devices_from_leases() -> None:
    leases, lease_ok = fetch_dhcp_leases()
    now = time.time()
    neigh = {}
    try:
        neigh = lan_neighbors()
    except Exception:
        neigh = {}
    zt_peers: dict[str, str] = {}
    zt_ok = True
    try:
        zt_peers = zt_cloud_peers()
    except Exception:
        zt_ok = False
        zt_peers = {}
    seen = set()
    with DEVICES_LOCK:
        for lease in leases:
            ip = lease["ip"]
            seen.add(ip)
            if ip not in DEVICES:
                mark = _alloc_mark()
                DEVICES[ip] = _new_device_row(
                    ip,
                    name=lease["name"],
                    mark=mark,
                    mac=lease["mac"],
                    evidence="New device",
                    egress_reason="new device — MikroTik until Gateway On",
                    last_seen=now,
                )
                _log(f"DEVICE ADD {lease['name']} ({ip}) mark={mark}")
            else:
                d = DEVICES[ip]
                d["mac"] = lease["mac"] or d["mac"]
                if lease["name"] and not lease["name"].startswith("Device-"):
                    d["name"] = lease["name"]
                d["last_seen"] = now
                d["online"] = True
        # ARP / recent traffic can prove a device is live even if DHCP dump missed it
        for ip, mac in neigh.items():
            seen.add(ip)
            if ip in DEVICES:
                d = DEVICES[ip]
                d["mac"] = mac or d.get("mac")
                d["last_seen"] = now
                d["online"] = True
            else:
                mark = _alloc_mark()
                DEVICES[ip] = _new_device_row(
                    ip,
                    name=guess_name(ip, mac),
                    mark=mark,
                    mac=mac,
                    evidence="ARP on lab LAN",
                    egress_reason="ARP live — MikroTik until Gateway On",
                    last_seen=now,
                )
                _log(f"DEVICE ADD {DEVICES[ip]['name']} ({ip}) via ARP mark={mark}")
        # Phone/PC on MikroTik Wi-Fi may miss Ubuntu ARP when DHCP is .1.
        # Ping them if DHCP/ARP did not already prove live.
        for ip, default_name in _LAB_PING_HOSTS:
            if ip in seen:
                continue
            if not lab_host_is_reachable(ip):
                continue
            seen.add(ip)
            mac = neigh.get(ip, "")
            if ip not in DEVICES:
                mark = _alloc_mark()
                DEVICES[ip] = _new_device_row(
                    ip,
                    name=default_name,
                    mark=mark,
                    mac=mac,
                    evidence="ICMP on lab LAN",
                    egress_reason="ICMP live — MikroTik until Gateway On",
                    last_seen=now,
                )
                _log(f"DEVICE ADD {default_name} ({ip}) via ICMP mark={mark}")
            else:
                d = DEVICES[ip]
                d["last_seen"] = now
                d["online"] = True
                if mac:
                    d["mac"] = mac or d.get("mac")
                if not d.get("name") or str(d.get("name")).startswith("Device-"):
                    d["name"] = default_name
        # Cloud ZeroTier remotes (live overlay /24, leftover 10.61.136.0/24).
        for ip, mac in zt_peers.items():
            seen.add(ip)
            if ip in DEVICES:
                d = DEVICES[ip]
                if mac:
                    d["mac"] = mac
                d["kind"] = "remote"
                d["last_seen"] = now
                d["online"] = True
                if not d.get("name") or str(d.get("name")).startswith("Device-"):
                    d["name"] = "Remote"
            else:
                mark = _alloc_mark(remote=True)
                DEVICES[ip] = _new_device_row(
                    ip,
                    name="Remote",
                    mark=mark,
                    mac=mac,
                    evidence="ZeroTier overlay",
                    egress_reason="ZT remote — MikroTik until Gateway On",
                    last_seen=now,
                )
                _log(f"DEVICE ADD Remote ({ip}) via ZT overlay mark={mark}")
        for ip, d in list(DEVICES.items()):
            if ip in seen:
                continue
            if _device_has_recent_traffic(ip):
                d["last_seen"] = now
                d["online"] = True
                continue
            last = float(d.get("last_seen") or 0.0)
            if last and (now - last) < _ONLINE_GRACE_SEC:
                d["online"] = True
                continue
            # Failed/empty MikroTik dump must not flip LAN clients offline
            if not lease_ok and not is_zt_cloud_client(ip):
                continue
            # Failed overlay scan must not flip remotes offline
            if is_zt_cloud_client(ip) and not zt_ok:
                continue
            d["online"] = False


_DEVICE_BYTE_SNAP: dict[str, tuple[int, float]] = {}


def _ensure_device_acct(ip: str) -> None:
    """Count download to this LAN IP. Must not MARK — that would steal replies."""
    if not ip or not is_lan_client(ip):
        return
    check = _sudo_run(
        ["iptables", "-t", "mangle", "-C", "FORWARD", "-d", ip, "-j", "ACCEPT"]
    )
    if check.returncode != 0:
        _sudo_run(
            ["iptables", "-t", "mangle", "-A", "FORWARD", "-d", ip, "-j", "ACCEPT"]
        )


def _mangle_bytes_for_ip(ip: str) -> int:
    """Sum mangle counters: PREROUTING -s (up) + FORWARD -d (down)."""
    total = 0
    for chain in ("PREROUTING", "FORWARD"):
        r = _sudo_run(
            ["iptables", "-t", "mangle", "-L", chain, "-n", "-v", "-x"], timeout=5,
        )
        out = (r.stdout or "") + (r.stderr or "")
        for ln in out.splitlines():
            if ip not in ln:
                continue
            nums = re.findall(r"\b(\d+)\b", ln)
            # pkts bytes ... source dest
            if len(nums) >= 2:
                try:
                    total += int(nums[1])
                except ValueError:
                    continue
    return total


def sample_device_lan_mbps(ip: str) -> float:
    """Per-device LAN→gateway throughput from iptables mangle counters (Mbps)."""
    now = time.time()
    cur = _mangle_bytes_for_ip(ip)
    prev = _DEVICE_BYTE_SNAP.get(ip)
    _DEVICE_BYTE_SNAP[ip] = (cur, now)
    if not prev:
        return 0.0
    prev_b, prev_ts = prev
    dt = now - prev_ts
    if dt <= 0.2:
        return 0.0
    # Counter reset / rule rebuild
    if cur < prev_b:
        return 0.0
    return max(0.0, (cur - prev_b) * 8.0 / dt / 1_000_000.0)


def _purge_source_marks(ip: str) -> None:
    """Remove every mangle MARK rule for this source (avoids duplicate marks)."""
    sudo = _ctx.get("SUDO") or "sudo"
    passwd = _ctx.get("SUDO_PASS") or "user"
    for chain in ("PREROUTING", "OUTPUT"):
        for _ in range(16):
            listed = _sudo_run(["iptables", "-t", "mangle", "-S", chain], timeout=5)
            victim = None
            for ln in (listed.stdout or "").splitlines():
                # -A PREROUTING -s 192.168.50.254/32 -j MARK --set-xmark 0x6f/0xffffffff
                if not ln.startswith("-A "):
                    continue
                if f"-s {ip}/32" not in ln and f"-s {ip} " not in ln:
                    continue
                if "-j MARK" not in ln:
                    continue
                victim = ln
                break
            if not victim:
                break
            delete = victim.replace("-A ", "-D ", 1)
            # delete is like: -D PREROUTING -s 192.168.50.254/32 -j MARK ...
            _run(
                [sudo, "-S", "iptables", "-t", "mangle", *delete.split()],
                input_text=passwd + "\n",
                timeout=5,
            )


# UDP/443 and UDP/80 are HTTP/3 / QUIC media — ports only, never decrypt.
_QUIC_PORTS = frozenset({443, 80})
# Dest-IP cache from DNS A records we actually saw (googlevideo / nflx / twitch).
_CDN_IP_NAME_KEYS = (
    "googlevideo", "nflxvideo", "nflxso", "nflximg", "ttvnw",
)
_CDN_IPS: dict[str, tuple[float, str]] = {}
_CDN_IP_TTL = 900.0
_CDN_RESOLVE_TS = 0.0
_CT_BLOB = ""
_CT_BLOB_TS = 0.0


def _empty_conn_stats() -> dict:
    return {
        "tcp": 0, "udp": 0, "total": 0, "udp_ratio": 0.0,
        "rx_mbps": 0.0, "tx_mbps": 0.0, "bidir": False,
        "udp_quic": 0, "udp_voice": 0, "voice_bidir": False, "cdn_hint": "",
    }


def _is_public_dst(addr: str) -> bool:
    if not addr or addr.startswith(("192.168.", "10.", "127.", "0.", "169.254.")):
        return False
    if addr.startswith("172."):
        try:
            second = int(addr.split(".")[1])
        except (ValueError, IndexError):
            return False
        if 16 <= second <= 31:
            return False
    return True


def _cdn_key_from_name(name: str) -> str:
    n = (name or "").lower().strip().strip('"')
    for k in _CDN_IP_NAME_KEYS:
        if k in n:
            return k
    return ""


def remember_video_cdn_ips(text: str) -> None:
    """Cache A records for googlevideo/nflx/twitch CDNs. Not decryption."""
    now = time.time()
    for ln in (text or "").splitlines():
        nm = re.search(r'name="?([^"\s]+)"?', ln, flags=re.I)
        ipm = re.search(
            r"\b(?:data|address)=(\d+\.\d+\.\d+\.\d+)\b", ln, flags=re.I,
        )
        if not ipm:
            ipm = re.search(
                r"\b([a-z0-9._-]+\.[a-z0-9._-]{2,})\b.*?\bA\b.*?(\d+\.\d+\.\d+\.\d+)",
                ln,
                flags=re.I,
            )
            if ipm and not nm:
                key = _cdn_key_from_name(ipm.group(1))
                if key and _is_public_dst(ipm.group(2)):
                    _CDN_IPS[ipm.group(2)] = (now + _CDN_IP_TTL, key)
                continue
        name = nm.group(1) if nm else ""
        addr = ipm.group(1) if ipm else ""
        key = _cdn_key_from_name(name)
        if key and _is_public_dst(addr):
            _CDN_IPS[addr] = (now + _CDN_IP_TTL, key)


def cdn_hint_for_ip(addr: str) -> str:
    rec = _CDN_IPS.get(addr or "")
    if not rec:
        return ""
    until, key = rec
    if until < time.time():
        _CDN_IPS.pop(addr, None)
        return ""
    return key


def resolve_video_cdn_names(names: tuple[str, ...], *, limit: int = 2) -> None:
    """Best-effort A lookups for CDN names already in cache. Never decrypts."""
    global _CDN_RESOLVE_TS
    now = time.time()
    if now - _CDN_RESOLVE_TS < 20.0:
        return
    wanted = [n for n in names if _cdn_key_from_name(n)]
    if not wanted:
        return
    try:
        import socket
    except Exception:
        return
    _CDN_RESOLVE_TS = now
    looked = 0
    for name in wanted:
        if looked >= limit:
            break
        key = _cdn_key_from_name(name)
        if not key:
            continue
        looked += 1
        try:
            infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_DGRAM)
        except OSError:
            continue
        for info in infos:
            addr = info[4][0]
            if _is_public_dst(addr):
                _CDN_IPS[addr] = (now + _CDN_IP_TTL, key)


def parse_quic_flows_conntrack(blob: str, ip: str) -> tuple[int, list[str]]:
    """Original UDP/443 or UDP/80 tuples for this LAN src from nf_conntrack."""
    if not blob or not ip:
        return 0, []
    udp_quic = 0
    dsts: list[str] = []
    seen: set[str] = set()
    src_re = re.compile(
        r"src=" + re.escape(ip) + r"\s+dst=(\d+\.\d+\.\d+\.\d+)\s+sport=\d+\s+dport=(\d+)"
    )
    for ln in blob.splitlines():
        if ip not in ln or "udp" not in ln.lower():
            continue
        m = src_re.search(ln)
        if not m:
            continue
        dst, port = m.group(1), int(m.group(2))
        if port not in _QUIC_PORTS or not _is_public_dst(dst):
            continue
        udp_quic += 1
        if dst not in seen:
            seen.add(dst)
            dsts.append(dst)
    return udp_quic, dsts


def parse_quic_flows_ros(blob: str, ip: str) -> tuple[int, list[str]]:
    """UDP/443 or UDP/80 from a RouterOS connection terse dump for this LAN IP."""
    if not blob or not ip:
        return 0, []
    udp_quic = 0
    dsts: list[str] = []
    seen: set[str] = set()
    src_ok = re.compile(rf"src-address={re.escape(ip)}(?::|\b)", re.I)
    dst_re = re.compile(r"dst-address=(\d+\.\d+\.\d+\.\d+):(\d+)", re.I)
    for ln in blob.splitlines():
        if ip not in ln or "udp" not in ln.lower():
            continue
        if not src_ok.search(ln):
            continue
        m = dst_re.search(ln)
        if not m:
            continue
        dst, port = m.group(1), int(m.group(2))
        if port not in _QUIC_PORTS or not _is_public_dst(dst):
            continue
        udp_quic += 1
        if dst not in seen:
            seen.add(dst)
            dsts.append(dst)
    return udp_quic, dsts


def _conntrack_blob() -> str:
    """One nf_conntrack read per engine tick. Empty on Windows unit tests."""
    global _CT_BLOB, _CT_BLOB_TS
    now = time.time()
    if _CT_BLOB and (now - _CT_BLOB_TS) < 2.2:
        return _CT_BLOB
    blob = ""
    try:
        with open("/proc/net/nf_conntrack", encoding="utf-8", errors="ignore") as f:
            blob = f.read()
    except OSError:
        try:
            if _ctx.get("run"):
                r = _sudo_run(["cat", "/proc/net/nf_conntrack"], timeout=3)
                blob = r.stdout or ""
        except Exception:
            blob = ""
    _CT_BLOB = blob
    _CT_BLOB_TS = now
    return blob


def parse_udp_voice_conntrack(blob: str, ip: str) -> tuple[int, bool]:
    """Non-HTTP/3 public UDP for this LAN src, plus two-way reply.

    Discord voice / Go Live uses UDP to media hosts, often not port 443.
    """
    if not blob or not ip:
        return 0, False
    src_re = re.compile(
        r"src=" + re.escape(ip)
        + r"\s+dst=(\d+\.\d+\.\d+\.\d+)\s+sport=\d+\s+dport=(\d+)"
    )
    count = 0
    bidir = False
    for ln in blob.splitlines():
        if ip not in ln or "udp" not in ln.lower():
            continue
        m = src_re.search(ln)
        if not m:
            continue
        dst, port = m.group(1), int(m.group(2))
        if not _is_public_dst(dst) or port in _QUIC_PORTS:
            continue
        count += 1
        low = ln.lower()
        if "unreplied" in low:
            continue
        reply_pkts = re.search(r"dst=" + re.escape(ip) + r".*?packets=(\d+)", ln)
        if reply_pkts and int(reply_pkts.group(1)) > 0:
            bidir = True
        elif "packets=" in low and ln.lower().count("packets=") >= 2:
            bidir = True
    return count, bidir


def forwarded_flow_signals(ip: str, ros_sample: str = "") -> dict:
    """Per-device QUIC-port + CDN dest-IP hints from forwarded flows."""
    udp_quic = 0
    udp_voice = 0
    voice_bidir = False
    dsts: list[str] = []
    try:
        n, d = parse_quic_flows_conntrack(_conntrack_blob(), ip)
        udp_quic += n
        dsts.extend(d)
    except Exception:
        pass
    try:
        n, d = parse_quic_flows_ros(ros_sample, ip)
        udp_quic += n
        for addr in d:
            if addr not in dsts:
                dsts.append(addr)
    except Exception:
        pass
    try:
        udp_voice, voice_bidir = parse_udp_voice_conntrack(_conntrack_blob(), ip)
    except Exception:
        udp_voice, voice_bidir = 0, False
    hint = ""
    for dst in dsts:
        hint = cdn_hint_for_ip(dst)
        if hint:
            break
    return {
        "udp_quic": udp_quic,
        "udp_voice": udp_voice,
        "voice_bidir": voice_bidir,
        "cdn_hint": hint,
    }


def device_connection_stats(ip: str) -> dict:
    """Fast, non-blocking connection counts for one client.

    Full `/ip firewall connection print` can hang RouterOS SSH — never dump all.
    Overlay remotes never hit MikroTik; Ubuntu conntrack only.
    """
    tcp = udp = total = 0
    sample = ""
    if is_zt_cloud_client(ip):
        out = _empty_conn_stats()
        try:
            out.update(forwarded_flow_signals(ip, ""))
        except Exception:
            out.setdefault("udp_quic", 0)
            out.setdefault("cdn_hint", "")
        return out
    try:
        # count-only is cheap; treat missing/timeout as inactive
        raw = _mikrotik(
            f'/ip firewall connection print count-only where src-address~"{ip}"'
        )
        m = re.search(r"(\d+)", (raw or "").strip())
        if m:
            total = int(m.group(1))
        if total > 0:
            sample = _mikrotik(
                f'/ip firewall connection print terse without-paging '
                f'where src-address~"{ip}"'
            )
            sample = "\n".join((sample or "").splitlines()[:80])
            tcp = len(re.findall(r"\bprotocol=tcp\b|\btcp\b", sample, flags=re.I))
            udp = len(re.findall(r"\bprotocol=udp\b|\budp\b", sample, flags=re.I))
    except Exception:
        sample = sample or ""
    if tcp + udp == 0 and total:
        # Unknown mix — assume mostly TCP streaming-like
        tcp, udp = total, 0
    mix_total = max(tcp + udp, total)
    rx_mbps, tx_mbps = _conn_sample_rates_mbps(sample)
    out = {
        "tcp": tcp,
        "udp": udp,
        "total": mix_total,
        "udp_ratio": (udp / mix_total) if mix_total else 0.0,
        "rx_mbps": rx_mbps,
        "tx_mbps": tx_mbps,
        "bidir": rx_mbps >= 0.02 and tx_mbps >= 0.02,
    }
    try:
        out.update(forwarded_flow_signals(ip, sample))
    except Exception:
        out.setdefault("udp_quic", 0)
        out.setdefault("udp_voice", 0)
        out.setdefault("voice_bidir", False)
        out.setdefault("cdn_hint", "")
    voice_n = int(out.get("udp_voice") or 0)
    if voice_n:
        udp = max(udp, voice_n)
        mix_total = max(tcp + udp, total, mix_total)
        out["udp"] = udp
        out["total"] = mix_total
        out["udp_ratio"] = (udp / mix_total) if mix_total else 0.0
    if out.get("voice_bidir"):
        out["bidir"] = True
    return out


def _ros_rate_to_mbps(num: str, unit: str) -> float:
    try:
        n = float(num)
    except ValueError:
        return 0.0
    u = (unit or "").lower()
    if u == "bps":
        return n / 1_000_000.0
    if u in ("kbps", "kbit", "kb"):
        return n / 1_000.0
    return n


def _conn_sample_rates_mbps(sample: str) -> tuple[float, float]:
    """Best-effort (download, upload) Mbps from RouterOS connection terse."""
    rx = tx = 0.0
    for m in re.finditer(
        r"repl-rate=([0-9.]+)\s*(bps|kbps|mbps|kbit|mbit)?",
        sample or "",
        flags=re.I,
    ):
        rx += _ros_rate_to_mbps(m.group(1), m.group(2) or "bps")
    for m in re.finditer(
        r"orig-rate=([0-9.]+)\s*(bps|kbps|mbps|kbit|mbit)?",
        sample or "",
        flags=re.I,
    ):
        tx += _ros_rate_to_mbps(m.group(1), m.group(2) or "bps")
    return rx, tx


def parse_dns_query_logs(out: str) -> list[tuple[str, str]]:
    """(client_ip, hostname) from RouterOS dns log lines."""
    found: list[tuple[str, str]] = []
    for ln in (out or "").splitlines():
        m = re.search(
            r"query from (192\.168\.50\.\d+)\S*.*?"
            r"([a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]{2,})",
            ln,
            flags=re.I,
        )
        if not m:
            m = re.search(
                r"(192\.168\.50\.\d+)\S*.*?(?:query|dns).*?"
                r"([a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]{2,})",
                ln,
                flags=re.I,
            )
        if not m:
            continue
        name = m.group(2).lower().rstrip(".")
        if name.count(".") < 1 or not re.search(r"[a-zA-Z]", name):
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
            continue
        found.append((m.group(1), name))
    return found


# Strong in-game / matchmaking — Steam tray/store is NOT this
_REAL_GAME_DNS = (
    "hoyoverse", "mihoyo", "yuanshen", "genshin", "honkai",
    "riotgames", "riotcdn", "roblox", "rbxcdn", "rbx.com",
    "faceit", "wargaming", "epicgames",
    "steamserver", "valve",
)
_STEAM_TRAY_DNS = (
    "steamcommunity", "store.steampowered", "api.steampowered",
    "login.steampowered", "steampowered",
)
_GAME_DOWNLOAD_DNS = (
    "steamcontent", "steamstatic", "gamedl",
)
_VIDEO_CDN_KEYS = (
    "googlevideo", "ytimg", "ggpht", "youtu.be", "youtube-nocookie",
    "youtubei", "nflxvideo", "nflxso", "nflximg", "ttvnw",
    "akamaihd.net",
)
_REAL_CALL_DNS = (
    "zoom.us", "zoomcdn", "meet.google", "teams.microsoft",
    "skype", "webex", "stun.", "turn.", "webrtc",
    "discord.media", "discord-gateway", "rtc.discord",
)
_WEAK_CALL_DNS = (
    "discord.com", "discord.gg", "discordapp.com",
)


# Never appear in evidence / TICK / Auto UI. DNS may still classify internally.
_PUBLIC_EVIDENCE_BAN = (
    "roblox", "rbxcdn", "rbx.com", "youtube", "googlevideo", "ytimg", "youtu",
    "ggpht", "netflix", "nflx", "steam", "hoyoverse", "genshin", "mihoyo",
    "twitch", "ttvnw", "discord", "zoom", "webex", "akamai", "spotify",
    "tiktok", "riot", "epicgames", "honkai", "yuanshen",
)


def _mix_label(*, udp_ratio: float, udp_count: int, quic_https: bool) -> str:
    if quic_https:
        return "UDP/443"
    if udp_count >= 3 or udp_ratio >= 0.25:
        return "UDP"
    if udp_count <= 0 and udp_ratio <= 0:
        return "TCP"
    return "TCP/UDP"


def _metric_interactive(
    rate: float,
    *,
    udp_ratio: float,
    udp_count: int,
    bidir: bool,
    idle: bool,
    quic_https: bool = False,
) -> bool:
    """Game/call-like: modest rate plus UDP mix and/or bidirectional flows."""
    if idle or rate >= 0.6:
        return False
    # YouTube HTTP/3 is many UDP/443 flows, often two-way, and the Mbps
    # sample falls to ~0 between chunks. That is not a call.
    if quic_https:
        return False
    return (
        (udp_ratio >= 0.25 and udp_count >= 3)
        or (bidir and udp_count >= 3)
        or (bidir and udp_ratio >= 0.25)
    )


def _clue_is_public(text: str) -> bool:
    low = (text or "").lower()
    return not any(b in low for b in _PUBLIC_EVIDENCE_BAN)


def _is_game_download(name: str) -> bool:
    n = (name or "").lower()
    return any(k in n for k in _GAME_DOWNLOAD_DNS)


def _is_steam_tray_name(name: str) -> bool:
    n = (name or "").lower()
    if _is_game_download(n) or any(k in n for k in ("steamserver", "valve")):
        return False
    if any(k in n for k in _STEAM_TRAY_DNS):
        return True
    return "steam" in n


def _is_real_game_name(name: str) -> bool:
    n = (name or "").lower()
    if _is_game_download(n) or _is_steam_tray_name(n):
        return False
    return any(k in n for k in _REAL_GAME_DNS)


def _is_real_call_name(name: str) -> bool:
    n = (name or "").lower()
    if any(k in n for k in _WEAK_CALL_DNS) and not any(k in n for k in _REAL_CALL_DNS):
        return False
    return any(k in n for k in _REAL_CALL_DNS)


def _names_have_discord(names: tuple[str, ...] | list[str]) -> bool:
    keys = _WEAK_CALL_DNS + (
        "discord.media", "discord-gateway", "rtc.discord", "discordapp",
    )
    for n in names or ():
        low = (n or "").lower()
        if any(k in low for k in keys):
            return True
    return False


def _call_like_traffic(
    rate: float,
    udp_ratio: float,
    udp_count: int,
    *,
    bidir: bool = False,
) -> bool:
    """VoIP/WebRTC: UDP plus two-way or a real call host. Chat HTTPS is not a call."""
    idle = rate < 0.08 and udp_count < 2 and not bidir
    if idle or rate >= 6.0:
        return False
    if bidir and (udp_count >= 2 or udp_ratio >= 0.2):
        return True
    if udp_count >= 3 and rate >= 0.08:
        return True
    return False


def filter_shared_dns_for_device(
    shared: tuple[str, ...],
    rate: float,
    *,
    udp_count: int = 0,
    sole: bool = False,
    unique_busy: bool = False,
) -> tuple[str, ...]:
    """Do not paint an idle phone with the PC's Steam/YouTube cache.

    Per-IP logs win elsewhere. This is the fallback: only hand a shared
    hint to the device whose LAN rate / flows match that hint.
    """
    if not shared:
        return ()
    if sole:
        return tuple(shared)
    stream_k = tuple(_ctx.get("STREAMING_DNS") or ()) + _VIDEO_CDN_KEYS
    game_k = tuple(_ctx.get("GAMING_DNS") or ()) + _REAL_GAME_DNS + _STEAM_TRAY_DNS
    call_k = tuple(_ctx.get("CALL_DNS") or ()) + _REAL_CALL_DNS + _WEAK_CALL_DNS
    dl_k = tuple(_ctx.get("DOWNLOAD_DNS") or ()) + _GAME_DOWNLOAD_DNS
    video_like = rate >= 0.22
    bulk_like = rate >= 1.5
    game_like = (0.08 <= rate < 0.45) or (udp_count >= 3 and rate < 1.0)
    out: list[str] = []
    seen: set[str] = set()
    for n in shared:
        keep = False
        is_video = any(k in n for k in stream_k)
        is_dl = _is_game_download(n) or any(k in n for k in dl_k)
        is_game = any(k in n for k in game_k) and not is_dl
        is_call = _is_real_call_name(n) or any(k in n for k in call_k)
        is_discord = _names_have_discord((n,))
        if is_discord:
            keep = True
        elif is_video and video_like:
            keep = True
        elif is_dl and bulk_like:
            keep = True
        elif (is_game or is_call) and (game_like or udp_count >= 2):
            keep = True
        if keep and n not in seen:
            seen.add(n)
            out.append(n)
    return tuple(out)


_DOWNLOAD_HOLD_UNTIL: dict[str, float] = {}


def _download_hold(active: bool, key: str) -> bool:
    """Keep one device's file transfer through its own chunk gaps."""
    now = time.time()
    if active:
        _DOWNLOAD_HOLD_UNTIL[key] = now + 20.0
        return True
    return now < _DOWNLOAD_HOLD_UNTIL.get(key, 0.0)


def download_hold_active() -> bool:
    return time.time() < _DOWNLOAD_HOLD_UNTIL.get("host", 0.0)


def classify_from_signals(
    rate: float,
    dns: tuple[str, ...] = (),
    *,
    udp_ratio: float = 0.0,
    udp_count: int = 0,
    extra_clues: list[str] | None = None,
    bulk_sustained: bool = False,
    bidir: bool = False,
    quic_https: bool = False,
    cdn_ip_hint: str = "",
    rx_mbps: float = 0.0,
    tx_mbps: float = 0.0,
    voice_udp: int = 0,
    hold_key: str = "host",
) -> tuple[str, str]:
    """Map live traffic shape to a profile. DNS/CDN may help; UI stays metric-only.

    Idle / light / Discord chat + tabs → Everyday browsing.
    YouTube/Netflix CDN while still pulling → Video streaming.
    Discord voice / Go Live (bidirectional call UDP or upload) → Gaming & calls.
    Sustained high rate / bulk → Big downloads.
    """
    votes = {"balanced": 1.0, "gaming": 0.0, "streaming": 0.0, "downloads": 0.0}
    clues: list[str] = []

    stream_k = tuple(_ctx.get("STREAMING_DNS") or ()) + _VIDEO_CDN_KEYS
    game_k = tuple(_ctx.get("GAMING_DNS") or ()) + _REAL_GAME_DNS
    call_k = tuple(_ctx.get("CALL_DNS") or ()) + _REAL_CALL_DNS
    dl_k = tuple(_ctx.get("DOWNLOAD_DNS") or ()) + _GAME_DOWNLOAD_DNS

    def _hit(keys, pred=None) -> str | None:
        if not keys:
            return None
        for n in dns:
            if any(k in n for k in keys) and (pred is None or pred(n)):
                return n
        return None

    video_cdn = _hit(_VIDEO_CDN_KEYS)
    if not video_cdn and cdn_ip_hint:
        video_cdn = _cdn_key_from_name(cdn_ip_hint) or cdn_ip_hint.lower()
    sticky_stream = _hit(
        stream_k,
        pred=lambda n: not any(k in n for k in _VIDEO_CDN_KEYS),
    )
    dl_hit = _hit(dl_k)
    real_game_hit = next((n for n in dns if _is_real_game_name(n)), None)
    steam_tray_hit = next((n for n in dns if _is_steam_tray_name(n)), None)
    call_hit = next((n for n in dns if _is_real_call_name(n)), None)
    if not call_hit:
        call_hit = _hit(call_k, pred=lambda n: not any(w in n for w in _WEAK_CALL_DNS))
    game_hit = _hit(game_k, pred=lambda n: not _is_game_download(n))
    discord_app = _names_have_discord(dns)

    idle = rate < 0.08 and udp_count < 2 and not bidir
    play_floor = 0.22
    rx = float(rx_mbps or 0.0)
    tx = float(tx_mbps or 0.0)
    if rx <= 0 and tx <= 0 and rate > 0:
        rx = float(rate)
    download_heavy = rx >= 0.22 and rx > max(tx, 0.01) * 2.5
    upload_heavy = tx >= 0.2 and tx >= rx * 0.35
    video_like = 0.22 <= rate < 6.0
    bulk = (rate >= 8.0 or bulk_sustained) and not video_cdn
    game_activity = (not idle) and rate < 0.6
    mix = _mix_label(udp_ratio=udp_ratio, udp_count=udp_count, quic_https=quic_https)
    metric_game = _metric_interactive(
        rate,
        udp_ratio=udp_ratio,
        udp_count=udp_count,
        bidir=bidir,
        idle=idle,
        quic_https=quic_https,
    )
    steam_live = (
        bool(steam_tray_hit)
        and rate >= 0.08
        and (udp_count >= 3 or udp_ratio >= 0.25)
    )
    if steam_live and not real_game_hit:
        real_game_hit = steam_tray_hit

    leftover_video_on_gamer = (
        bool(video_cdn)
        and game_activity
        and not video_like
        and bool(real_game_hit)
        and not quic_https
    )
    pulling_video = bool(video_cdn) or bool(cdn_ip_hint)
    leftover_site = bool(sticky_stream) and download_heavy
    # A one-way TCP file sits in the same Mbps band as a video.
    plain_tcp = (
        not discord_app
        and download_heavy
        and not quic_https
        and not video_cdn
        and not (cdn_ip_hint or "")
        and not call_hit
    )
    # Discord chat + extra tabs must not count as video. Everything else in
    # the 0.22–6 Mbps band (YouTube hairpin included) still does.
    if discord_app:
        watching = (
            rate >= 0.45
            and not leftover_video_on_gamer
            and not upload_heavy
            and (pulling_video or leftover_site or download_heavy)
        )
    else:
        watching = (
            (pulling_video or leftover_site)
            and rate >= play_floor
            and not leftover_video_on_gamer
            and not upload_heavy
        )
        if video_like and not dl_hit and not watching and not leftover_video_on_gamer and not plain_tcp:
            watching = True
    # Voice is non-443 UDP. HTTP/3 video must not satisfy the call test.
    voice_n = int(voice_udp or 0)
    live_call_udp = (
        not idle
        and rate < 6.0
        and (
            (voice_n >= 1 and (bidir or voice_n >= 2))
            or (
                not quic_https
                and (
                    (bidir and (udp_count >= 2 or udp_ratio >= 0.2))
                    or (udp_count >= 3 and rate >= 0.08)
                )
            )
        )
    )
    golive = upload_heavy and rate < 8.0 and not bool(video_cdn)
    if discord_app and (live_call_udp or golive) and not pulling_video:
        watching = False
    # Short quiet gap while the player is still pulling a little.
    # ~0 Mbps after YouTube is closed is browsing, even if CDN cache or
    # UDP/443 sockets are still sitting there. UDP/443 alone is not a call.
    if (
        0.08 <= rate < play_floor
        and not upload_heavy
        and not leftover_video_on_gamer
        and not (discord_app and (live_call_udp or golive) and not pulling_video)
        and (
            pulling_video
            or (quic_https and udp_count >= 3 and voice_n < 1 and not call_hit)
        )
    ):
        watching = True
    call_active = (
        not watching
        and not bulk
        and (
            (
                bool(call_hit)
                and _call_like_traffic(rate, udp_ratio, udp_count, bidir=bidir)
            )
            or (discord_app and (live_call_udp or golive))
            or (golive and live_call_udp)
        )
    )

    # A one-way file pull is a big download. YouTube (CDN or HTTP/3) stays video,
    # and one device's download hold does not apply to another device.
    if plain_tcp:
        watching = False
    video_now = bool(watching or video_cdn or quic_https) and not plain_tcp
    file_pull = False
    if plain_tcp and rate >= 2.0:
        file_pull = _download_hold(True, hold_key)
    elif not video_now:
        file_pull = _download_hold(
            rate >= 2.0
            and download_heavy
            and not call_hit,
            hold_key,
        )
    if watching:
        if video_cdn:
            votes["streaming"] += 8.0
        elif sticky_stream:
            votes["streaming"] += 4.0
        if quic_https:
            votes["streaming"] += 2.0
        if video_like and not dl_hit:
            votes["streaming"] += 4.0
        votes["streaming"] += 2.0
        votes["gaming"] = 0.0
        clues.append(f"steady downstream {rate:.1f} Mbps")
        if quic_https:
            clues.append("UDP/443")
        elif mix != "TCP":
            clues.append(mix)
    elif bulk or file_pull:
        votes["downloads"] += 6.0
        clues.append(f"bulk {rate:.1f} Mbps")
        if dl_hit:
            votes["downloads"] += 4.0
        if mix == "TCP":
            clues.append("TCP")
        elif mix != "TCP/UDP":
            clues.append(mix)
    else:
        gaming_ready = bool(call_active or (real_game_hit and not idle) or metric_game)
        if call_active:
            votes["gaming"] += 6.0
        if real_game_hit and not idle:
            votes["gaming"] += 6.0
        elif game_hit and 0.08 <= rate < 0.6 and not call_active:
            votes["gaming"] += 1.2
        elif metric_game:
            votes["gaming"] += 6.0
        if (
            (real_game_hit or call_active or metric_game)
            and udp_ratio >= 0.25
            and udp_count >= 3
        ):
            votes["gaming"] += 1.5
        if dl_hit and rate >= 1.5:
            votes["downloads"] += 4.0

        if gaming_ready:
            clues.append(f"interactive {mix}")
            if rate < 0.6:
                clues.append("low rate")
            clues.append(f"{rate:.2f} Mbps")
            if bidir:
                clues.append("bidir")
        elif dl_hit and rate >= 1.5:
            clues.append(f"bulk {rate:.1f} Mbps")
        elif rate >= 0.15:
            clues.append(f"light {mix}")
            clues.append(f"{rate:.1f} Mbps")
        else:
            clues.append("idle / light use")

    for extra in extra_clues or ():
        if extra and extra not in clues and "flows" not in extra and _clue_is_public(extra):
            clues.append(extra)

    best = max(votes, key=votes.get)
    if votes[best] < 2.5:
        best = "balanced"
        useful = [
            c for c in clues
            if _clue_is_public(c) and any(
                x in c for x in (
                    "Mbps", "UDP", "TCP", "interactive", "bulk", "idle",
                    "steady", "bidir", "light",
                )
            )
        ]
        clues = useful[:3] if useful else ["idle / light use"]

    seen: set[str] = set()
    ordered: list[str] = []
    for c in clues:
        if c not in seen and _clue_is_public(c):
            seen.add(c)
            ordered.append(c)
    return best, " · ".join(ordered[:4]) if ordered else "idle / light use"


def auto_hysteresis_need(current: str, guess: str, evidence: str) -> tuple[int, float]:
    """Hits + gap before Auto commits. Fast onto video and big downloads."""
    if guess == "downloads":
        return 1, 0.0
    if current == "gaming" and guess == "streaming":
        return 1, 0.0
    if guess == "streaming":
        return 1, 0.0
    if current == "streaming" and guess == "balanced":
        return 1, 0.0
    if guess == "gaming":
        return 2, 8.0
    # A file transfer pauses between chunks. Do not drop Big downloads
    # on a short quiet gap.
    if current == "downloads" and guess == "balanced":
        return 4, 15.0
    if current != "balanced" and guess == "balanced":
        return 1, 2.0
    return 2, 6.0


def _device_is_moving(rate: float, stats: dict) -> bool:
    rx = float(stats.get("rx_mbps") or 0.0)
    tx = float(stats.get("tx_mbps") or 0.0)
    udp = int(stats.get("udp") or 0)
    return (
        rate >= 0.12 or rx >= 0.12 or tx >= 0.12
        or int(stats.get("total") or 0) >= 8
        or (udp >= 3 and (rate >= 0.08 or bool(stats.get("bidir"))))
    )


def lan_clients_all_idle() -> bool:
    """True when we know LAN devices and none of them are moving.

    Empty snapshot is not idle — do not force Everyday browsing on an
    unknown lab. Used by host Auto so leftover video-CDN cache cannot
    paint streaming while kiyo/phone sit idle on stage.
    """
    try:
        snap = _snapshot_device_activity()
    except Exception:
        return False
    if not snap:
        return False
    return not any(_device_is_moving(r, st) for r, st in snap.values())


_ACTIVITY_CACHE: dict[str, tuple[float, float, dict]] = {}
_ACTIVITY_CACHE_TS = 0.0
_WAN_LAN_CACHE: tuple[float, float, float] | None = None


def _snapshot_device_activity() -> dict[str, tuple[float, dict]]:
    """One rate + flow sample per online IP per engine tick (avoids double-count)."""
    global _ACTIVITY_CACHE_TS
    now = time.time()
    with DEVICES_LOCK:
        online = [d["ip"] for d in DEVICES.values() if d.get("online")]
    if _ACTIVITY_CACHE and (now - _ACTIVITY_CACHE_TS) < 2.2:
        return {ip: (r, st) for ip, (_t, r, st) in _ACTIVITY_CACHE.items() if ip in online}
    snap: dict[str, tuple[float, dict]] = {}
    for other in online:
        try:
            r = float(sample_device_lan_mbps(other) or 0.0)
        except Exception:
            r = 0.0
        try:
            st = device_connection_stats(other)
        except Exception:
            st = {
                "tcp": 0, "udp": 0, "total": 0, "udp_ratio": 0.0,
                "rx_mbps": 0.0, "tx_mbps": 0.0, "bidir": False,
            }
        r = max(
            r,
            float(st.get("rx_mbps") or 0.0),
            float(st.get("tx_mbps") or 0.0),
        )
        snap[other] = (r, st)
        _ACTIVITY_CACHE[other] = (now, r, st)
    _ACTIVITY_CACHE_TS = now
    return snap


def _wan_lan_rates() -> tuple[float, float]:
    global _WAN_LAN_CACHE
    now = time.time()
    if _WAN_LAN_CACHE and (now - _WAN_LAN_CACHE[0]) < 2.2:
        return _WAN_LAN_CACHE[1], _WAN_LAN_CACHE[2]
    wan_fn = _ctx.get("mikrotik_wan_rx_mbps")
    lan_fn = _ctx.get("sample_local_rx_mbps")
    try:
        wan = float(wan_fn() or 0.0) if wan_fn else 0.0
    except Exception:
        wan = 0.0
    try:
        lan = float(lan_fn() or 0.0) if lan_fn else 0.0
    except Exception:
        lan = 0.0
    _WAN_LAN_CACHE = (now, wan, lan)
    return wan, lan


_OPENED: dict[str, tuple[float, list[dict]]] = {}
_OPENED_TTL = 30.0
_BROWSER_PROCS = ("chrome", "msedge", "firefox", "brave", "opera", "iexplore")
_VIDEO_TITLES = (
    "youtube", "netflix", "twitch", "disney+", "disney plus", "hulu",
    "hbo", "prime video", "crunchyroll", "youtu.be",
)
_GAME_PROCS = (
    "valorant", "leagueclient", "robloxplayerbeta", "genshinimpact",
    "yuanshen", "riotclientservices", "cs2", "fortnite", "overwatch",
)
_GAME_TITLES = ("valorant", "league of legends", "genshin", "roblox", "fortnite")
_DOWNLOAD_PROCS = ("qbittorrent", "utorrent", "transmission-qt", "transmission")
_DOWNLOAD_TITLES = ("downloading",)
_MEET_CODE = re.compile(r"\bmeet\s*-\s*[a-z0-9]{3,4}-[a-z0-9]{3,4}-[a-z0-9]{3,4}\b")
_MEET_URL = re.compile(r"meet\.google\.com/([a-z0-9]{3,4}-[a-z0-9]{3,4}-[a-z0-9]{3,4})")
_VIDEO_URLS = (
    "youtube.com/watch", "youtube.com/shorts", "youtu.be/",
    "music.youtube.com", "netflix.com/watch", "twitch.tv/",
)


def note_opened(ip: str, apps: list[dict]) -> None:
    """Remember what this LAN PC has open. Titles never go into the public UI."""
    clean: list[dict] = []
    for row in apps or []:
        if not isinstance(row, dict):
            continue
        proc = str(row.get("process") or "")[:80]
        title = str(row.get("title") or "")[:160]
        url = str(row.get("url") or "")[:240]
        call = bool(row.get("call"))
        downloading = bool(row.get("download"))
        if not proc and not title and not url:
            continue
        clean.append({
            "process": proc, "title": title, "url": url,
            "call": call, "download": downloading,
        })
        if len(clean) >= 40:
            break
    if ip:
        _OPENED[ip] = (time.time(), clean)


def _norm_open_title(title: str) -> str:
    """Drop the browser suffix so a window and its front tab count once."""
    t = (title or "").lower().strip()
    suffixes = (
        " - google chrome", " - microsoft edge", " - mozilla firefox",
        " - brave", " - opera", " - audio playing",
    )
    changed = True
    while changed:
        changed = False
        for suffix in suffixes:
            if t.endswith(suffix):
                t = t[: -len(suffix)].strip()
                changed = True
    return t


_VIDEO_HOMEPAGES = (
    "youtube", "youtube music", "netflix", "twitch", "hulu", "disney+",
    "disney plus", "hbo", "hbo max", "prime video", "crunchyroll",
)


def _is_playing_video(title: str, url: str) -> bool:
    """A video that is actually open, not the site's front page."""
    if any(k in url for k in _VIDEO_URLS):
        return True
    if not any(k in title for k in _VIDEO_TITLES):
        return False
    return _norm_open_title(title) not in _VIDEO_HOMEPAGES


def _open_row_kind(row: dict) -> str | None:
    """Which preset this open window belongs to, or None for an ordinary site."""
    proc = (row.get("process") or "").lower()
    title = (row.get("title") or "").lower()
    url = (row.get("url") or "").lower()
    browser = any(b in proc for b in _BROWSER_PROCS)
    if (
        any(k in proc for k in _DOWNLOAD_PROCS)
        or row.get("download")
        or (
            any(k in title for k in _DOWNLOAD_TITLES)
            and (proc in ("steam", "epicgameslauncher") or browser)
        )
        or "chrome://downloads" in url
        or "edge://downloads" in url
    ):
        return "downloads"
    if _is_playing_video(title, url):
        return "streaming"
    # Homepage meet.google.com has no meeting code. Discord chat is not a call.
    if (
        _MEET_CODE.search(title)
        or _MEET_URL.search(url)
        or "zoom meeting" in title
        or (proc == "discord" and row.get("call"))
    ):
        return "gaming"
    if any(k in proc for k in _GAME_PROCS) or any(k in title for k in _GAME_TITLES):
        return "gaming"
    return None


def _count_open_rows(apps: list[dict]) -> dict[str, int]:
    """How many open videos, calls/games, and downloads this PC is showing."""
    counts = {"streaming": 0, "gaming": 0, "downloads": 0}
    seen: set[tuple[str, str, str]] = set()
    for row in apps or []:
        kind = _open_row_kind(row)
        if not kind:
            continue
        proc = (row.get("process") or "").lower()
        key = (kind, proc, _norm_open_title(row.get("title") or ""))
        if key in seen:
            continue
        seen.add(key)
        counts[kind] += 1
    return counts


def _majority_mode(counts: dict[str, int]) -> str | None:
    """Preset with the most open apps. A tie is Everyday browsing.

    None means none of the three presets is open, so the caller keeps the
    traffic guess (a file transfer with no download window still counts).
    """
    ranked = [
        (name, int(counts.get(name) or 0))
        for name in ("streaming", "gaming", "downloads")
    ]
    best = max(v for _, v in ranked)
    if best <= 0:
        return None
    leaders = [name for name, v in ranked if v == best]
    if len(leaders) == 1:
        return leaders[0]
    return "balanced"


def opened_for(ip: str) -> dict | None:
    rec = _OPENED.get(ip or "")
    if not rec:
        return None
    ts, apps = rec
    age = time.time() - ts
    if age > _OPENED_TTL:
        return None
    browsers = []
    for row in apps:
        proc = (row.get("process") or "").lower()
        if any(b in proc for b in _BROWSER_PROCS) and proc not in browsers:
            browsers.append(proc)
    counts = _count_open_rows(apps)
    activities = [name for name, n in counts.items() if n > 0]
    return {
        "age": round(age, 1),
        "apps": apps,
        "browsers": browsers,
        "video": counts["streaming"] > 0,
        "game": counts["gaming"] > 0,
        "call_room": counts["gaming"] > 0,
        "call": counts["gaming"] > 0,
        "download": counts["downloads"] > 0,
        "counts": counts,
        "activities": activities,
    }


def _opened_media(ip: str) -> bool:
    """Two-way non-web UDP. A Meet tab with no media is not a call."""
    rec = _ACTIVITY_CACHE.get(ip or "")
    if not rec or len(rec) < 3:
        return False
    st = rec[2] or {}
    return int(st.get("udp_voice") or 0) >= 1 or bool(st.get("voice_bidir"))


def _wifi_activities(dns: tuple[str, ...] | list[str], moving: bool) -> set[str]:
    """Apps and sites this device is using on Wi-Fi right now.

    A phone has no desktop window list. Its own recent DNS is the app.
    Names only count while the device is actually passing traffic.
    """
    if not moving:
        return set()
    blob = " ".join((n or "").lower() for n in dns)
    if not blob:
        return set()
    acts: set[str] = set()
    video_keys = _VIDEO_CDN_KEYS + (
        "youtube", "netflix", "nflx", "twitch", "tiktok", "disney",
        "hulu", "hbomax", "crunchyroll", "primevideo", "vimeo",
    )
    call_keys = _REAL_CALL_DNS
    if any(k in blob for k in video_keys):
        acts.add("streaming")
    if any(k in blob for k in call_keys):
        acts.add("gaming")
    elif any(k in blob for k in _REAL_GAME_DNS):
        acts.add("gaming")
    if any(k in blob for k in _GAME_DOWNLOAD_DNS):
        acts.add("downloads")
    return acts


def _counts_with_transfer(counts: dict[str, int], guess: str) -> dict[str, int]:
    """A measured file transfer counts as one download when no download app is open."""
    out = {
        "streaming": int(counts.get("streaming") or 0),
        "gaming": int(counts.get("gaming") or 0),
        "downloads": int(counts.get("downloads") or 0),
    }
    if out["downloads"] == 0 and guess == "downloads":
        out["downloads"] = 1
    return out


def apply_opened_bias(
    ip: str,
    guess: str,
    evidence: str,
    *,
    media: bool | None = None,
    dns: tuple[str, ...] | list[str] = (),
    moving: bool = False,
    file_transfer: bool = False,
) -> tuple[str, str]:
    """PC: majority of open videos, calls/games, and downloads.

    One YouTube video → Video streaming. A call or an open game → Gaming & calls.
    A big download → Big downloads. Whichever kind is open more often wins.
    An even split → Everyday browsing. A file transfer with no video open is a
    download, even when its speed looks like a stream. A phone has no window
    list, so it still follows the apps using its Wi-Fi. Evidence stays metric-only.
    """
    opened = opened_for(ip)
    if opened is not None:
        counts_in = opened.get("counts") or {}
        use_guess = guess
        if (
            use_guess == "downloads"
            and not file_transfer
            and int(counts_in.get("downloads") or 0) == 0
        ):
            use_guess = "balanced"
        counts = _counts_with_transfer(counts_in, use_guess)
        # No video is open, so this one-way pull is the file, not a stream.
        if file_transfer and int(counts.get("streaming") or 0) == 0:
            counts["downloads"] = max(int(counts.get("downloads") or 0), 1)
        mode = _majority_mode(counts)
        if mode:
            return mode, evidence
        if use_guess == "downloads":
            return "downloads", evidence
        return "balanced", evidence
    wifi = _wifi_activities(dns, moving)
    if not wifi:
        return guess, evidence
    return _mode_from_activities(wifi, guess, evidence)


def _mode_from_activities(activities: set[str], guess: str, evidence: str) -> tuple[str, str]:
    if len(activities) == 1:
        return next(iter(activities)), evidence
    if len(activities) > 1:
        return "balanced", evidence
    # Ordinary websites do not cancel a measured file transfer.
    # Leftover video or call traffic still falls back to browsing.
    if guess == "downloads":
        return "downloads", evidence
    if guess in ("streaming", "gaming"):
        return "balanced", evidence
    return guess, evidence


def _combined_open_counts() -> dict[str, int] | None:
    totals = {"streaming": 0, "gaming": 0, "downloads": 0}
    found = False
    for ip in list(_OPENED):
        opened = opened_for(ip)
        if opened is None:
            continue
        found = True
        for name in totals:
            totals[name] += int((opened.get("counts") or {}).get(name) or 0)
    return totals if found else None


def pc_open_counts() -> dict[str, int] | None:
    """Combined open-app counts from PCs that are reporting, or None."""
    return _combined_open_counts()


def opened_commit_mode() -> str | None:
    """Mode the fresh window reports require, or None when no PC is reporting."""
    totals = _combined_open_counts()
    if totals is None:
        return None
    return _majority_mode(totals)


def opened_commit_for(ip: str) -> str | None:
    opened = opened_for(ip or "")
    if not opened:
        return None
    return _majority_mode(opened.get("counts") or {})


def commit_download_devices() -> None:
    """Show Big downloads now on the devices that are online. Do not wait for the engine."""
    now = time.time()
    with DEVICES_LOCK:
        for d in DEVICES.values():
            if d.get("profile") != "auto" or not d.get("online"):
                continue
            if d.get("auto_detected") == "downloads":
                d["pending"] = None
                d["pending_hits"] = 0
                continue
            d["auto_detected"] = "downloads"
            d["pending"] = None
            d["pending_hits"] = 0
            d["last_switch"] = now


def device_auto_mode(ip: str) -> str | None:
    with DEVICES_LOCK:
        d = DEVICES.get(ip or "")
        if not d:
            return None
        return d.get("auto_detected")


def commit_detected(ip: str, mode: str) -> None:
    """Write the mode the Test slide is already showing."""
    if mode not in ("balanced", "gaming", "streaming", "downloads"):
        return
    now = time.time()
    with DEVICES_LOCK:
        d = DEVICES.get(ip)
        if not d or d.get("profile") != "auto":
            return
        if d.get("auto_detected") == mode:
            d["pending"] = None
            d["pending_hits"] = 0
            return
        d["auto_detected"] = mode
        d["pending"] = None
        d["pending_hits"] = 0
        d["last_switch"] = now


def commit_opened_device(ip: str) -> None:
    """Apply this PC's open-app mode now. Do not wait for the engine tick."""
    forced = opened_commit_for(ip)
    if not forced:
        return
    with DEVICES_LOCK:
        d = DEVICES.get(ip)
        if not d or d.get("profile") != "auto":
            return
        if d.get("auto_detected") == forced:
            d["pending"] = None
            d["pending_hits"] = 0
            return
        prev = d.get("auto_detected")
        d["auto_detected"] = forced
        d["pending"] = None
        d["pending_hits"] = 0
        d["last_switch"] = time.time()
        name = d.get("name") or ip
    _log(f"DEVICE AUTO {name} {prev} -> {forced}")


def apply_opened_bias_all(
    guess: str,
    evidence: str,
    *,
    file_transfer: bool = False,
) -> tuple[str, str]:
    """Fold every fresh PC report into the host Right now label.

    Each open video, call, game, and download is counted. The kind with the
    most windows wins. A tie is Everyday browsing. A file transfer counts
    when no video is open.
    """
    totals = _combined_open_counts()
    if totals is None:
        return guess, evidence
    counts = _counts_with_transfer(totals, guess)
    if file_transfer and int(counts.get("streaming") or 0) == 0:
        counts["downloads"] = max(int(counts.get("downloads") or 0), 1)
    mode = _majority_mode(counts)
    if mode:
        return mode, evidence
    if guess == "downloads":
        return "downloads", evidence
    return "balanced", evidence


def commit_reported_pcs(mode: str) -> None:
    """Apply a mode only to the PC that is actually in that activity.

    A download on one account must not mark every other quiet PC. Phones are
    never in this list. Everyday browsing is written only when that PC has
    none of the three activities open.
    """
    if mode not in ("balanced", "downloads"):
        return
    quiet: list[str] = []
    for ip in list(_OPENED):
        opened = opened_for(ip)
        if not opened:
            continue
        counts = opened.get("counts") or {}
        streaming = int(counts.get("streaming") or 0)
        gaming = int(counts.get("gaming") or 0)
        downloads = int(counts.get("downloads") or 0)
        if mode == "balanced":
            if streaming or gaming or downloads:
                continue
            commit_detected(ip, "balanced")
            continue
        if streaming or gaming:
            continue
        quiet.append(ip)
    if mode != "downloads":
        return
    for ip in quiet:
        # One reporting PC is that account's laptop. Several accounts reporting
        # at once: only the address that is actually pulling the file.
        if len(quiet) == 1 or _ip_is_pulling(ip):
            commit_detected(ip, "downloads")


def release_finished_downloads() -> None:
    """Leave Big downloads on a PC once that PC is not transferring a file."""
    for ip in list(_OPENED):
        opened = opened_for(ip)
        if not opened:
            continue
        if device_auto_mode(ip) != "downloads":
            continue
        counts = opened.get("counts") or {}
        if int(counts.get("downloads") or 0) > 0:
            continue
        if _ip_is_pulling(ip):
            continue
        mode = _majority_mode(counts) or "balanced"
        commit_detected(ip, mode)


def _ip_is_pulling(ip: str) -> bool:
    rec = _ACTIVITY_CACHE.get(ip or "")
    if not rec or len(rec) < 3:
        return False
    ts, rate, st = rec[0], rec[1], rec[2] or {}
    if time.time() - float(ts or 0) > 30:
        return False
    rx = float(st.get("rx_mbps") or 0.0)
    tx = float(st.get("tx_mbps") or 0.0)
    rate = max(float(rate or 0.0), rx, tx)
    if str(st.get("cdn_hint") or ""):
        return False
    return rate >= 2.0 and rx > max(tx, 0.01) * 2.5


def classify_device(ip: str) -> tuple[str, str]:
    """Per-device guess: this IP's rate/flows + its DNS, never a sibling's."""
    snap = _snapshot_device_activity()
    rate, stats = snap.get(ip, (0.0, {"tcp": 0, "udp": 0, "total": 0, "udp_ratio": 0.0}))
    online_ips = list(snap.keys())
    busy_ips = [o for o, (r, st) in snap.items() if _device_is_moving(r, st)]
    sole = len(online_ips) <= 1
    unique_busy = len(busy_ips) == 1 and busy_ips[0] == ip
    rx = float(stats.get("rx_mbps") or 0.0)
    tx = float(stats.get("tx_mbps") or 0.0)
    rate = max(rate, rx, tx)
    wan, lan = _wan_lan_rates()
    agg = max(wan, lan)
    cdn_hint = str(stats.get("cdn_hint") or "")
    bidir = bool(stats.get("bidir")) or (rx >= 0.02 and tx >= 0.02)

    per_ip_fn = _ctx.get("mikrotik_dns_hints_for_ip")
    dns_fn: Callable = _ctx.get("mikrotik_dns_hints")
    per_ip: tuple[str, ...] = ()
    shared: tuple[str, ...] = ()
    # Cafe DNS never hits MikroTik. Do not paint a ZT remote with LAN DNS.
    if not is_zt_cloud_client(ip):
        if per_ip_fn:
            try:
                per_ip = tuple(per_ip_fn(ip) or ())
            except Exception:
                per_ip = ()
        if dns_fn:
            try:
                shared = tuple(dns_fn() or ())
            except Exception:
                shared = ()

    def _classifiable(names: tuple[str, ...]) -> bool:
        keys = (
            tuple(_ctx.get("STREAMING_DNS") or ())
            + tuple(_ctx.get("GAMING_DNS") or ())
            + tuple(_ctx.get("CALL_DNS") or ())
            + _VIDEO_CDN_KEYS
            + _REAL_GAME_DNS
            + _STEAM_TRAY_DNS
            + _REAL_CALL_DNS
            + _WEAK_CALL_DNS
        )
        return any(any(k in n for k in keys) for n in names)

    attributed = filter_shared_dns_for_device(
        shared,
        rate,
        udp_count=int(stats.get("udp") or 0),
        sole=sole,
        unique_busy=unique_busy,
    )
    if per_ip and _classifiable(per_ip):
        # This IP's queries win. Sole device may also keep shared cache hints
        # (there is no sibling to steal from).
        dns = tuple(dict.fromkeys(per_ip + attributed)) if sole else per_ip
    else:
        dns = attributed

    # VPN hairpin: mangle looks idle while WAN is YouTube. Copy house rate
    # onto this PC when WAN is actually pulling. Discord chat is not video
    # unless WAN is already in the play band with CDN evidence.
    house_pull = 0.22 <= agg < 6.0
    quic = int(stats.get("udp_quic") or 0) >= 1
    discordish = _names_have_discord(dns)
    videoish = bool(cdn_hint) or any(
        any(k in (n or "").lower() for k in _VIDEO_CDN_KEYS) for n in dns
    )
    own_rate, own_rx, own_tx = rate, rx, tx
    if house_pull and discordish and not videoish and agg < 0.45:
        pass
    elif house_pull and (sole or unique_busy or quic or cdn_hint or videoish or not busy_ips):
        rate = max(rate, agg)
        rx = max(rx, agg)

    guess, evidence = classify_from_signals(
        rate,
        dns,
        udp_ratio=float(stats.get("udp_ratio") or 0.0),
        udp_count=int(stats.get("udp") or 0),
        bidir=bidir,
        quic_https=int(stats.get("udp_quic") or 0) >= 1,
        cdn_ip_hint=cdn_hint,
        rx_mbps=rx,
        tx_mbps=tx,
        voice_udp=int(stats.get("udp_voice") or 0),
        hold_key=ip,
    )
    media = int(stats.get("udp_voice") or 0) >= 1 or bool(stats.get("voice_bidir"))
    moving = _device_is_moving(rate, stats)
    own_dns = per_ip if per_ip else (dns if (sole or unique_busy) else ())
    # House WAN is not this laptop's file. Only its own pull, or a download
    # hold that has not expired yet, counts.
    file_transfer = (not videoish) and (
        (
            own_rate >= 2.0
            and own_rx >= 0.22
            and own_rx > max(own_tx, 0.01) * 2.5
        )
        or download_hold_active()
    )
    return apply_opened_bias(
        ip, guess, evidence, media=media, dns=own_dns, moving=moving,
        file_transfer=file_transfer,
    )


def lan_forwarded_video_signals() -> tuple[bool, str]:
    """UDP/443 or CDN dest while the house WAN is actually pulling."""
    try:
        snap = _snapshot_device_activity()
    except Exception:
        return False, ""
    try:
        wan, lan = _wan_lan_rates()
    except Exception:
        wan, lan = 0.0, 0.0
    pulling = max(wan, lan) >= 0.22
    quic = False
    hint = ""
    for _ip, (rate, st) in snap.items():
        has_quic = int(st.get("udp_quic") or 0) >= 1
        h = str(st.get("cdn_hint") or "")
        if not pulling and not _device_is_moving(rate, st):
            continue
        if h and not hint:
            hint = h
        if has_quic and pulling:
            quic = True
    if not pulling:
        return False, ""
    return quic, hint


def effective_device_profile(d: dict) -> str:
    if d["profile"] == "auto":
        return d.get("auto_detected") or "balanced"
    if d["profile"] == "custom":
        return "custom"
    return d["profile"]


def score_regimes_for_profile(profile_key: str, custom_weights=None, failed_ids=None) -> tuple[dict, list]:
    """Same live-first rank as host evaluate_once (shared cache + formula)."""
    rank = _ctx.get("rank_regimes_live")
    if rank:
        return rank(profile_key, custom_weights, failed_ids=failed_ids)
    return {}, []


# Hardcoded leftovers only. Runtime dummy-type ifaces are also blocked.
_LAB_ONLY_IFACES: set[str] = set()
# Overlay/mesh that can ping -I (or even pass LAN-proof) but must never be
# a LAN client's default. SAW may still rank them. nebula1 blackholed
# Windows when SAW swapped onto it (unsafe_routes ≠ forwarded internet).
# wg0 here is MikroTik wg-server → the same ether1 WAN; encrypting LAN
# clients through it capped Fast.com (~70 Mbps vs ~400 off the hEX).
_CLIENT_EGRESS_DENY = frozenset({"nebula1"})
_NOT_TUNNEL_IFACES = {"", "lo", "enp0s3", "enp0s8", "enp0s9"}
_VPN_INET_CACHE: dict[str, tuple[float, bool]] = {}
# Consecutive ping -I misses before LAN-proof is dropped / client table pinned.
# One blink used to yank table 110+ back to MikroTik while the UI still said tunnel.
_PING_I_MISS: dict[str, int] = {}
_PING_I_MISS_LIMIT = 3
# Global kill-switch leftover. Do NOT set True — that would allow every
# tunnel. Client egress is per-iface via lan_forward_proven() only.
_ALLOW_VPN_CLIENT_EGRESS = False
_LAN_SUBNET = "192.168.50.0/24"
_LAN_PROOF_TTL = 30.0
_LAN_PROOF_CACHE: dict[str, tuple[float, bool, str]] = {}
_LAN_PROOF_LOCK = threading.Lock()
_LAN_PROOF_STAMP_DIR = "/run/autovpn-lan-proof"
_CLIENT_TABLE_MIN = 110
_CLIENT_TABLE_MAX = 125
_PROOF_NS = "agproof"
_PROOF_VETH_H = "agph"
_PROOF_VETH_N = "agpn"
_PROOF_HOST_IP = "10.99.50.1"
_PROOF_NS_IP = "10.99.50.2"
_PROOF_TABLE = 250
_PROOF_RULE_PREF = 49
_PROOF_DSTS = ("8.8.8.8", "1.1.1.1")
# Prove in this order. Dummy SSTP / cloud ZT / nebula overlay are skipped.
_PROOF_ORDER = ("wg0", "tun0", "tun1", "vti0", "tap_soft", "sstp0")


def _iface_is_dummy(iface: str) -> bool:
    """True when the kernel iface is a dummy (10.66 loop), not a real tunnel."""
    if not iface:
        return False
    run = _ctx.get("run")
    if not run:
        return False
    try:
        r = run(["ip", "-details", "link", "show", "dev", iface], timeout=3)
    except Exception:
        return False
    blob = ((r.stdout or "") + (r.stderr or "")).lower()
    return "dummy" in blob


# Leftover dummy peers on lo — never a WAN next-hop.
_DUMMY_NEXTHOPS = {"10.66.70.1", "10.66.71.1"}
# vpn-stack-up.sh policy tables (never device marks 110+).
_POLICY_TABLE = {
    "tap_soft": 30,
    "tun0": 68,
    "vti0": 67,
    "tun1": 71,
    "nebula1": 72,
    "sstp0": 70,
    "ppp0": 70,
    "ppp1": 70,
}


def _policy_table_id(iface: str) -> int | None:
    if not iface:
        return None
    if iface in _POLICY_TABLE:
        return _POLICY_TABLE[iface]
    if iface.startswith("zt"):
        ip_s = _iface_ipv4(iface)
        if ip_s and ip_s.startswith(_ZT_LAB_NET):
            return 74
    return None


def _iface_ipv4(iface: str) -> str | None:
    r = _run(["ip", "-o", "-4", "addr", "show", "dev", iface], timeout=3)
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", r.stdout or "")
    return m.group(1) if m else None


def _tunnel_nexthop(iface: str) -> str | None:
    """On-link gateway for TAP /24 or GRE/OpenVPN p-t-p. Never dummy/lo.

    SoftEther TAP needs via 192.168.30.1 (SecureNAT). `default dev tap_soft`
    ARPs for 8.8.8.8 on L2 and LAN proof fails. WireGuard /32 is cryptokey
    routed — return None so callers use `default dev iface`.
    """
    if not iface or _iface_is_dummy(iface):
        return None
    r = _run(["ip", "-o", "-4", "addr", "show", "dev", iface], timeout=3)
    blob = r.stdout or ""
    peer = re.search(
        r"inet\s+\d+\.\d+\.\d+\.\d+(?:/\d+)?\s+peer\s+(\d+\.\d+\.\d+\.\d+)",
        blob,
    )
    if peer:
        hop = peer.group(1)
        return None if hop in _DUMMY_NEXTHOPS else hop
    cidr = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", blob)
    if not cidr:
        return None
    ip_s, plen = cidr.group(1), int(cidr.group(2))
    if plen >= 32 or plen != 24:
        return None
    a, b, c, _d = (int(x) for x in ip_s.split("."))
    gw = f"{a}.{b}.{c}.1"
    if gw == ip_s or gw in _DUMMY_NEXTHOPS:
        return None
    return gw


def _ensure_tunnel_policy(iface: str) -> None:
    """oif/from policy so TAP/subnet tunnels use their on-link gw, not main.

    Never installs 8.8.8.8/32 on main. Never touches device mark tables 110+.
    """
    table = _policy_table_id(iface)
    via = _tunnel_nexthop(iface)
    src = _iface_ipv4(iface)
    if not table or not src:
        return
    if via:
        _sudo_ip(["route", "replace", f"{via}/32", "dev", iface, "table", str(table)])
        _sudo_ip(["route", "replace", "default", "via", via, "dev", iface, "table", str(table)])
    else:
        _sudo_ip(["route", "replace", "default", "dev", iface, "table", str(table)])
    for _ in range(8):
        if _sudo_ip(["rule", "del", "table", str(table)]).returncode != 0:
            break
    _sudo_ip(["rule", "add", "oif", iface, "table", str(table), "priority", str(table)])
    _sudo_ip(["rule", "add", "from", src, "table", str(table), "priority", str(table + 1)])


def _ping_i_misses(iface: str) -> int:
    return int(_PING_I_MISS.get(iface) or 0)


def _record_ping_i(iface: str, ok: bool) -> None:
    """Update ping -I cache. Drop LAN-proof only after consecutive misses."""
    if not iface:
        return
    now = time.time()
    if ok:
        _PING_I_MISS[iface] = 0
        _VPN_INET_CACHE[iface] = (now, True)
        return
    _PING_I_MISS[iface] = _ping_i_misses(iface) + 1
    _VPN_INET_CACHE[iface] = (now, False)
    if _ping_i_misses(iface) >= _PING_I_MISS_LIMIT:
        invalidate_lan_proof(
            iface,
            f"{iface} ping -I 8.8.8.8 failed ×{_ping_i_misses(iface)}",
        )


def _vpn_carries_internet(iface: str) -> bool:
    """True only if this tunnel can actually reach the public internet."""
    if not iface or not _iface_exists(iface):
        return False
    if iface in _LAB_ONLY_IFACES or iface in _NOT_TUNNEL_IFACES:
        return False
    if _iface_is_dummy(iface):
        return False
    now = time.time()
    cached = _VPN_INET_CACHE.get(iface)
    # Keep PASS longer; do not lock FAIL for 15s (that pinned LAN clients on MikroTik).
    if cached:
        age = now - cached[0]
        if cached[1] and age < 15.0:
            return True
        if (not cached[1]) and age < 2.0:
            return False
    try:
        _ensure_tunnel_policy(iface)
    except Exception:
        pass
    ok = False
    for _ in range(3):
        r = _run(["ping", "-I", iface, "-c", "1", "-W", "2", "8.8.8.8"], timeout=5)
        if r.returncode == 0:
            ok = True
            break
    _record_ping_i(iface, ok)
    return ok


def vpn_carries_internet(iface: str) -> bool:
    """Public alias: tunnel may carry WAN only if 8.8.8.8 answers on that iface."""
    return _vpn_carries_internet(iface)


def _host_default_safe() -> bool:
    """True when Ubuntu's own default is not a VPN tunnel."""
    dev = _route_get_dev("8.8.8.8")
    if not dev:
        return False
    return not _is_vpn_tunnel_dev(dev)


def _persist_lan_proof_stamp(iface: str, ok: bool, reason: str) -> None:
    """Stamp file so the bash watchdog can see LAN-proof FAIL without Python."""
    try:
        os.makedirs(_LAN_PROOF_STAMP_DIR, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", iface)
        path = os.path.join(_LAN_PROOF_STAMP_DIR, safe)
        with open(path, "w", encoding="utf-8") as f:
            f.write(("PASS" if ok else "FAIL") + "\n" + (reason or "") + "\n")
    except Exception:
        pass


def _cache_lan_proof(iface: str, ok: bool, reason: str) -> tuple[bool, str]:
    _LAN_PROOF_CACHE[iface] = (time.time(), ok, reason)
    _persist_lan_proof_stamp(iface, ok, reason)
    return ok, reason


def invalidate_lan_proof(iface: str, reason: str) -> None:
    """Drop a PASS cache immediately — never keep LAN clients on a dead ping -I.

    Does not refresh _VPN_INET_CACHE (that TTL must be allowed to expire so a
    recovered tunnel can be probed again).
    """
    if not iface:
        return
    _LAN_PROOF_CACHE[iface] = (time.time(), False, reason)
    _persist_lan_proof_stamp(iface, False, reason)


def _forward_pkts(in_if: str, out_if: str) -> int:
    """FORWARD packet counter for -i in_if -o out_if (0 if missing)."""
    r = _sudo_run(["iptables", "-L", "FORWARD", "-n", "-v", "-x"], timeout=5)
    total = 0
    for ln in (r.stdout or "").splitlines():
        if in_if not in ln or out_if not in ln:
            continue
        nums = re.findall(r"\b(\d+)\b", ln)
        if nums:
            try:
                total += int(nums[0])
            except ValueError:
                continue
    return total


def _ensure_lan_probe_ns() -> str | None:
    """Idempotent veth netns that looks like a LAN client. None on failure."""
    if not _ctx.get("run"):
        return "no runtime"
    listed = _sudo_run(["ip", "netns", "list"], timeout=5)
    if _PROOF_NS not in (listed.stdout or ""):
        add = _sudo_run(["ip", "netns", "add", _PROOF_NS], timeout=5)
        if add.returncode != 0:
            return f"netns add failed: {(add.stderr or add.stdout or '').strip()}"
    link = _run(["ip", "link", "show", "dev", _PROOF_VETH_H], timeout=3)
    if link.returncode != 0:
        _sudo_run(["ip", "link", "add", _PROOF_VETH_H, "type", "veth", "peer", "name", _PROOF_VETH_N])
        _sudo_run(["ip", "link", "set", _PROOF_VETH_N, "netns", _PROOF_NS])
    _sudo_run(["ip", "addr", "replace", f"{_PROOF_HOST_IP}/24", "dev", _PROOF_VETH_H])
    _sudo_run(["ip", "link", "set", _PROOF_VETH_H, "up"])
    _sudo_run(["ip", "netns", "exec", _PROOF_NS, "ip", "addr", "replace",
               f"{_PROOF_NS_IP}/24", "dev", _PROOF_VETH_N], timeout=8)
    _sudo_run(["ip", "netns", "exec", _PROOF_NS, "ip", "link", "set", _PROOF_VETH_N, "up"], timeout=8)
    _sudo_run(["ip", "netns", "exec", _PROOF_NS, "ip", "link", "set", "lo", "up"], timeout=8)
    _sudo_run(["ip", "netns", "exec", _PROOF_NS, "ip", "route", "replace",
               "default", "via", _PROOF_HOST_IP], timeout=8)
    # ip netns exec does not see systemd-resolved on 127.0.0.53 — curls to
    # hostnames otherwise fail and the gauge shows "Could not measure".
    _sudo_run(["mkdir", "-p", f"/etc/netns/{_PROOF_NS}"], timeout=5)
    _sudo_run([
        "bash", "-c",
        f"printf 'nameserver 8.8.8.8\\nnameserver 1.1.1.1\\n' > /etc/netns/{_PROOF_NS}/resolv.conf",
    ], timeout=5)
    _sudo_run(["sysctl", "-w", f"net.ipv4.conf.{_PROOF_VETH_H}.rp_filter=2"])
    _sudo_run(["sysctl", "-w", f"net.ipv4.conf.{_PROOF_VETH_H}.forwarding=1"])
    _iptables_ensure(["FORWARD", "-i", _PROOF_VETH_H, "-j", "ACCEPT"], insert=True)
    _iptables_ensure(
        ["FORWARD", "-o", _PROOF_VETH_H,
         "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        insert=True,
    )
    # Policy table used only by the probe source — never table 110 / main.
    _sudo_ip(["rule", "del", "from", f"{_PROOF_NS_IP}/32", "table", str(_PROOF_TABLE)])
    _sudo_ip([
        "rule", "add", "from", f"{_PROOF_NS_IP}/32",
        "table", str(_PROOF_TABLE), "priority", str(_PROOF_RULE_PREF),
    ])
    return None


def _probe_lan_forward(iface: str) -> tuple[bool, str]:
    """Simulate a LAN client and require FORWARD+NAT out *this* iface.

    ping -I is not used. Fail closed. Must not steal Ubuntu's default.
    """
    if not iface or iface in _NOT_TUNNEL_IFACES or iface in _LAB_ONLY_IFACES:
        return False, f"{iface} is not a VPN tunnel"
    if not _iface_exists(iface):
        return False, f"{iface} missing"
    if _iface_is_dummy(iface):
        return False, f"{iface} is dummy (never WAN)"
    fwd = _run(["sysctl", "-n", "net.ipv4.ip_forward"], timeout=3)
    if fwd.returncode != 0 or (fwd.stdout or "").strip() != "1":
        return False, "ip_forward != 1"
    _sudo_run(["sysctl", "-w", f"net.ipv4.conf.{iface}.rp_filter=2"])
    _sudo_run(["sysctl", "-w", f"net.ipv4.conf.{iface}.forwarding=1"])
    _ensure_egress_nat(iface)
    if not _masquerade_out(iface):
        return False, f"no MASQUERADE out {iface}"
    _clamp_tunnel_mss(iface)
    err = _ensure_lan_probe_ns()
    if err:
        return False, err
    _sudo_ip(["route", "replace", f"{_PROOF_NS_IP}/32", "dev", _PROOF_VETH_H,
              "table", str(_PROOF_TABLE)])
    _sudo_ip(["route", "replace", "10.99.50.0/24", "dev", _PROOF_VETH_H,
              "table", str(_PROOF_TABLE)])
    try:
        _ensure_tunnel_policy(iface)
    except Exception:
        pass
    _flush_table_defaults(_PROOF_TABLE)
    via = _tunnel_nexthop(iface)
    # TAP/subnet tunnels need an on-link gw (SecureNAT .1). Never dummy 10.66.70.1.
    if via:
        _sudo_ip(["route", "replace", f"{via}/32", "dev", iface, "table", str(_PROOF_TABLE)])
        rdef = _sudo_ip([
            "route", "replace", "default", "via", via, "dev", iface,
            "table", str(_PROOF_TABLE),
        ])
    else:
        rdef = _sudo_ip(["route", "replace", "default", "dev", iface, "table", str(_PROOF_TABLE)])
    if rdef.returncode != 0:
        return False, f"proof table default dev {iface} failed"
    _iptables_ensure(["FORWARD", "-i", _PROOF_VETH_H, "-o", iface, "-j", "ACCEPT"], insert=True)
    _iptables_ensure(
        ["FORWARD", "-i", iface, "-o", _PROOF_VETH_H,
         "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        insert=True,
    )
    check = _sudo_run([
        "iptables", "-t", "nat", "-C", "POSTROUTING",
        "-s", f"{_PROOF_NS_IP}/32", "-o", iface, "-j", "MASQUERADE",
    ])
    if check.returncode != 0:
        _sudo_run([
            "iptables", "-t", "nat", "-I", "POSTROUTING", "1",
            "-s", f"{_PROOF_NS_IP}/32", "-o", iface, "-j", "MASQUERADE",
        ])
    if not _host_default_safe():
        _restore_lab_default()
        if not _host_default_safe():
            return False, "host default unsafe before probe — abort"

    last_why = "no dest answered"
    for dst in _PROOF_DSTS:
        got = _sudo_run(
            ["ip", "route", "get", dst, "from", _PROOF_NS_IP, "iif", _PROOF_VETH_H],
            timeout=5,
        )
        via = _dev_token((got.stdout or "") + (got.stderr or ""))
        if via != iface:
            last_why = f"route get {dst} via {via or '?'} not {iface}"
            continue
        before = _forward_pkts(_PROOF_VETH_H, iface)
        ping = _sudo_run(
            ["ip", "netns", "exec", _PROOF_NS, "ping", "-c", "1", "-W", "2", dst],
            timeout=10,
        )
        if ping.returncode != 0:
            curl = _sudo_run(
                ["ip", "netns", "exec", _PROOF_NS, "curl", "-4", "-sS", "-m", "3",
                 "-o", "/dev/null", f"http://{dst}/"],
                timeout=10,
            )
            if curl.returncode != 0:
                last_why = f"forwarded ping/HTTP {dst} via {iface} failed"
                continue
        after = _forward_pkts(_PROOF_VETH_H, iface)
        if after < before:
            after = before
        if not _host_default_safe():
            _restore_lab_default()
            return False, f"{iface} probe stole host default — restored, fail closed"
        why = f"forwarded ping {dst} via {iface} (netns {_PROOF_NS_IP})"
        if after > before:
            why += f" FORWARD pkts {before}->{after}"
        return True, why
    return False, last_why


def lan_forward_proven(iface: str) -> bool:
    """True when a LAN-source packet was FORWARDED+NATed out this iface."""
    ok, _reason = lan_proof_state(iface)
    return ok


_LAN_SPEED_URLS = (
    "https://speed.cloudflare.com/__down?bytes=1000000",
    "http://cachefly.cachefly.net/5mb.test",
    "http://ipv4.download.thinkbroadband.com/1MB.zip",
    "https://speed.cloudflare.com/__down?bytes=5000000",
)


def _curl_resolve_args(url: str) -> list[str]:
    """Pin hostname to a host-resolved IPv4 so netns curl does not need DNS."""
    try:
        from urllib.parse import urlparse
        import socket
    except Exception:
        return []
    u = urlparse(url)
    host = u.hostname or ""
    if not host:
        return []
    port = u.port or (443 if (u.scheme or "") == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        ip = infos[0][4][0]
    except OSError:
        return []
    if not ip:
        return []
    return ["--resolve", f"{host}:{port}:{ip}"]


def measure_lan_client_mbps(iface: str) -> float | None:
    """Download as a LAN client FORWARDED+NATed out this tunnel.

    Same hop as Fast.com on a lab PC (LAN → Ubuntu → wg0/vti0/tap_soft).
    Never changes Ubuntu's main default. None if the path is not a real WAN.
    """
    name = (iface or "").strip()
    if not is_client_wan_iface(name):
        return None
    got_lock = False
    for _wait in range(3):
        if _LAN_PROOF_LOCK.acquire(timeout=12.0):
            got_lock = True
            break
        _log(f"SPEED {name} waiting for lan-proof lock")
    if not got_lock:
        _log(f"SPEED {name} busy")
        return None
    try:
        ok, why = _probe_lan_forward(name)
        if not ok:
            _log(f"SPEED {name} probe: {why} — trying download anyway")

        def _one(url: str) -> float:
            host = url.split("/")[2] if "://" in url else url
            extra = _curl_resolve_args(url)
            r = _sudo_run(
                [
                    "ip", "netns", "exec", _PROOF_NS,
                    "curl", "-4", "--http1.1", "-sS", "-o", "/dev/null",
                    "--max-time", "16", "--connect-timeout", "6",
                    "--retry", "0", "-L", "--max-redirs", "3",
                    *extra,
                    "-w", "%{speed_download}",
                    "--", url,
                ],
                timeout=22,
            )
            raw = (r.stdout or "").strip().split()[-1] if (r.stdout or "").strip() else "0"
            try:
                bps = float(raw)
            except ValueError:
                bps = 0.0
            # Timed-out transfers still count if some payload arrived.
            if bps < 1500:
                err = ((r.stderr or "").strip().replace("\n", " "))[:160]
                _log(f"SPEED {name} curl {host} rc={r.returncode} bps={bps:.0f} {err}")
                return 0.0
            if r.returncode not in (0, 28) and bps < 80_000:
                err = ((r.stderr or "").strip().replace("\n", " "))[:160]
                _log(f"SPEED {name} curl {host} rc={r.returncode} bps={bps:.0f} {err}")
                return 0.0
            return bps * 8.0 / 1_000_000.0

        speeds: list[float] = []
        for url in _LAN_SPEED_URLS:
            try:
                v = float(_one(url) or 0.0)
            except Exception as e:
                _log(f"SPEED {name} curl error: {e}")
                v = 0.0
            if v > 0:
                speeds.append(v)
                break
        if not _host_default_safe():
            _restore_lab_default()
        if not speeds:
            return None
        total = round(sum(speeds), 1)
        _log(f"SPEED lan-client via {name} {total} Mbps n={len(speeds)}")
        return total
    finally:
        _LAN_PROOF_LOCK.release()


def lan_proof_state(iface: str) -> tuple[bool, str]:
    """Cached per-iface LAN FORWARD+NAT proof. Fail closed. TTL ~30s."""
    name = (iface or "").strip()
    if not name:
        return False, "no iface"
    now = time.time()
    inet = _VPN_INET_CACHE.get(name)
    if inet and not inet[1] and _ping_i_misses(name) >= _PING_I_MISS_LIMIT:
        reason = f"{name} ping -I 8.8.8.8 failed ×{_ping_i_misses(name)} — ignore stale LAN-proof"
        cached = _LAN_PROOF_CACHE.get(name)
        if not cached or cached[1]:
            invalidate_lan_proof(name, reason)
        return False, reason
    cached = _LAN_PROOF_CACHE.get(name)
    if cached and (now - cached[0]) < _LAN_PROOF_TTL:
        return cached[1], cached[2]
    if not _ctx.get("run"):
        return False, "no runtime (fail closed)"
    # Non-blocking: a request/watchdog must not sit behind a multi-iface probe.
    if not _LAN_PROOF_LOCK.acquire(timeout=0.25):
        cached = _LAN_PROOF_CACHE.get(name)
        if cached:
            return cached[1], cached[2]
        return False, "lan-proof busy"
    try:
        inet = _VPN_INET_CACHE.get(name)
        if inet and not inet[1] and _ping_i_misses(name) >= _PING_I_MISS_LIMIT:
            reason = f"{name} ping -I 8.8.8.8 failed ×{_ping_i_misses(name)} — ignore stale LAN-proof"
            cached = _LAN_PROOF_CACHE.get(name)
            if not cached or cached[1]:
                invalidate_lan_proof(name, reason)
            return False, reason
        cached = _LAN_PROOF_CACHE.get(name)
        if cached and (time.time() - cached[0]) < _LAN_PROOF_TTL:
            return cached[1], cached[2]
        try:
            ok, reason = _probe_lan_forward(name)
        except Exception as e:
            ok, reason = False, f"probe error: {e}"
        _cache_lan_proof(name, ok, reason)
        _log(f"LAN-PROOF {name} {'PASS' if ok else 'FAIL'}: {reason}")
        if not _host_default_safe():
            _restore_lab_default()
            _log("LAN-PROOF restored host default via MikroTik .1")
        return ok, reason
    finally:
        _LAN_PROOF_LOCK.release()


def refresh_lan_client_proofs() -> dict[str, bool]:
    """Prove wg0 first, then other real tunnels independently. Never dummy."""
    out: dict[str, bool] = {}
    seen: set[str] = set()
    candidates = list(_PROOF_ORDER)
    for extra in ("sstp0",):
        if extra not in candidates:
            candidates.append(extra)
    zt_lab = zerotier_lab_client_iface()
    if zt_lab and zt_lab not in candidates:
        candidates.append(zt_lab)
    for iface in candidates:
        if iface in seen:
            continue
        seen.add(iface)
        if not _iface_exists(iface):
            continue
        if _iface_is_dummy(iface):
            _cache_lan_proof(iface, False, f"{iface} is dummy (never WAN)")
            out[iface] = False
            _log(f"LAN-PROOF {iface} SKIP: dummy")
            continue
        if _client_egress_denied(iface):
            _cache_lan_proof(iface, False, f"{iface} overlay — not a client WAN")
            out[iface] = False
            _log(f"LAN-PROOF {iface} SKIP: client-egress deny")
            continue
        out[iface] = lan_forward_proven(iface)
    return out


def _client_egress_denied(iface: str) -> bool:
    """True when SAW may rank this iface but LAN clients must not use it."""
    return bool(iface) and iface in _CLIENT_EGRESS_DENY


def vpn_client_egress_allowed(iface: str) -> bool:
    """LAN clients may use a tunnel only when FORWARD+NAT is proven for it.

    Scoring still uses vpn_carries_internet (ping -I). Client policy tables
    do not: ping -I never proves FORWARD+NAT of a LAN source.
    Per-iface only — _ALLOW_VPN_CLIENT_EGRESS stays False on purpose.
    A single ping -I miss does not disallow while the LAN-proof stamp is PASS.
    Overlay deny (nebula1) never becomes a client default.
    """
    if not iface:
        return False
    if iface in _LAB_ONLY_IFACES or iface in _NOT_TUNNEL_IFACES:
        return False
    if _client_egress_denied(iface):
        return False
    if _iface_is_dummy(iface):
        return False
    inet = _VPN_INET_CACHE.get(iface)
    if inet and not inet[1] and not _lan_proof_stamp_pass(iface):
        return False
    if _lan_proof_stamp_pass(iface):
        return True
    return lan_forward_proven(iface)



def _lan_proof_stamp_pass(iface: str) -> bool:
    """Trust /run stamp written by lan-proof (bash watchdog + Python)."""
    if not iface:
        return False
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", iface)
    path = os.path.join(_LAN_PROOF_STAMP_DIR, safe)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return (f.readline() or "").strip() == "PASS"
    except Exception:
        return False


def choose_device_egress(iface: str | None, carries_internet: bool) -> dict:
    """Decide this device's default without touching the host table.

    Scoring/UI may still pick a tunnel. Client tables stay MikroTik .1 unless
    FORWARD+NAT of a LAN source is proven for that iface (not ping -I).
    Dummy ifaces and lo/LAN NICs never become WAN.
    """
    name = (iface or "").strip()
    if not name:
        return {
            "kind": "mikrotik",
            "via": _MIKROTIK_IP,
            "dev": _LAN_IFACE,
            "reason": "no iface for this pick",
        }
    if name in _LAB_ONLY_IFACES or _iface_is_dummy(name):
        return {
            "kind": "mikrotik",
            "via": _MIKROTIK_IP,
            "dev": _LAN_IFACE,
            "reason": f"{name} is lab-only dummy (never WAN)",
        }
    if name in _NOT_TUNNEL_IFACES:
        return {
            "kind": "mikrotik",
            "via": _MIKROTIK_IP,
            "dev": _LAN_IFACE,
            "reason": f"{name} is not a VPN tunnel",
        }
    if _client_egress_denied(name):
        return {
            "kind": "mikrotik",
            "via": _MIKROTIK_IP,
            "dev": _LAN_IFACE,
            "reason": (
                f"{name} is overlay-only — SAW may rank it, "
                "LAN clients stay MikroTik"
            ),
        }
    if not carries_internet and not _lan_proof_stamp_pass(name):
        return {
            "kind": "mikrotik",
            "via": _MIKROTIK_IP,
            "dev": _LAN_IFACE,
            "reason": f"{name} cannot reach 8.8.8.8 — stay MikroTik",
        }
    if not carries_internet and _lan_proof_stamp_pass(name):
        carries_internet = True
    if not vpn_client_egress_allowed(name) and not _lan_proof_stamp_pass(name):
        _ok, why = lan_proof_state(name) if _ctx.get("run") else (False, "not proven")
        detail = why if not _ok else "not proven"
        return {
            "kind": "mikrotik",
            "via": _MIKROTIK_IP,
            "dev": _LAN_IFACE,
            "reason": (
                f"{name} scores as WAN (ping -I) but LAN clients stay MikroTik "
                f"until FORWARD+NAT from a LAN source is proven ({detail})"
            ),
        }
    return {
        "kind": "tunnel",
        "via": None,
        "dev": name,
        "reason": f"{name} LAN FORWARD+NAT proven — client table via {name}",
    }


def _store_egress(ip: str, egress: dict) -> None:
    with DEVICES_LOCK:
        if ip not in DEVICES:
            return
        DEVICES[ip]["egress"] = egress.get("kind") or "mikrotik"
        DEVICES[ip]["egress_via"] = egress.get("via") or egress.get("dev")
        DEVICES[ip]["egress_dev"] = egress.get("dev")
        DEVICES[ip]["egress_reason"] = egress.get("reason") or ""


def _ensure_egress_nat(iface: str) -> None:
    """MASQUERADE + FORWARD on the iface this device actually exits.

    Overlay sources are ACCEPTed inside AUTOVPN-RL (hashlimit).
    Never INSERT `-i ztdiysvwlf ACCEPT` here — that would skip house-LAN REJECT.
    """
    if not iface:
        return
    check = _sudo_run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
    if check.returncode != 0:
        _sudo_run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"])
    _clamp_tunnel_mss(iface)
    _iptables_ensure(["FORWARD", "-i", _LAN_IFACE, "-o", iface, "-j", "ACCEPT"], insert=True)
    _iptables_ensure(
        ["FORWARD", "-i", iface, "-o", _LAN_IFACE,
         "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        insert=True,
    )


def _install_connected_routes(table: int) -> None:
    """Keep lab LAN (and overlay, for remote tables) on-link in the client table."""
    _sudo_ip([
        "route", "replace", _LAN_SUBNET,
        "dev", _LAN_IFACE, "table", str(table),
    ])
    if table >= _REMOTE_MARK_MIN:
        for net in zt_cloud_networks():
            _sudo_ip([
                "route", "replace", str(net),
                "dev", _ZT_CLOUD_IFACE, "table", str(table),
            ])


def _flush_table_defaults(table: int) -> None:
    """Drop every default in a client table. via-.1 and dev-wg0 can coexist."""
    for _ in range(8):
        r = _sudo_ip(["route", "del", "default", "table", str(int(table))])
        if r.returncode != 0:
            break


def _install_mikrotik_default(table: int):
    _install_connected_routes(table)
    _flush_table_defaults(table)
    return _sudo_ip([
        "route", "replace", "default",
        "via", _MIKROTIK_IP, "dev", _LAN_IFACE, "table", str(table),
    ])


def _install_tunnel_default(table: int, tun: str):
    """Device table: keep LAN on enp0s8, default out the proven tunnel."""
    _install_connected_routes(table)
    _flush_table_defaults(table)
    via = _tunnel_nexthop(tun)
    if via:
        _sudo_ip(["route", "replace", f"{via}/32", "dev", tun, "table", str(table)])
        return _sudo_ip([
            "route", "replace", "default", "via", via, "dev", tun, "table", str(table),
        ])
    return _sudo_ip(["route", "replace", "default", "dev", tun, "table", str(table)])


def _table_default_mentions(table: int, token: str) -> bool:
    r = _run(["ip", "route", "show", "table", str(table)], timeout=3)
    out = (r.stdout or "") + (r.stderr or "")
    for ln in out.splitlines():
        if ln.startswith("default") and token in ln:
            return True
    return False


def _table_default_dev(table: int) -> str:
    r = _run(["ip", "route", "show", "table", str(table)], timeout=3)
    first = ""
    for ln in (r.stdout or "").splitlines():
        if not ln.startswith("default"):
            continue
        dev = _dev_token(ln)
        if not first:
            first = dev
        if _is_vpn_tunnel_dev(dev) and not _client_egress_denied(dev):
            return dev
    return first


def _client_fib_dev(mark: int, table: int) -> str:
    """Client-table default (not host `ip route get`, which uses Ubuntu's src)."""
    return _table_default_dev(int(table))


def _egress_from_fib(mark: int, table: int, reason: str = "") -> dict:
    """Honest client exit from the kernel lookup, not the SAW label."""
    dev = _client_fib_dev(mark, table)
    tunnel_ok = (
        _is_vpn_tunnel_dev(dev)
        and not _client_egress_denied(dev)
        and not _iface_is_dummy(dev)
        and dev not in _NOT_TUNNEL_IFACES
        and dev not in _LAB_ONLY_IFACES
    )
    if tunnel_ok:
        return {
            "kind": "tunnel",
            "via": None,
            "dev": dev,
            "reason": reason or f"packets via {dev}",
        }
    return {
        "kind": "mikrotik",
        "via": _MIKROTIK_IP,
        "dev": _LAN_IFACE,
        "reason": reason or f"packets via MikroTik ({dev or 'main'})",
    }


def _sync_device_egress_from_fib(ip: str, reason: str = "") -> dict | None:
    with DEVICES_LOCK:
        d = DEVICES.get(ip)
        if not d:
            return None
        try:
            mark = int(d["mark"])
            table = int(d["table"])
        except Exception:
            return None
    egress = _egress_from_fib(mark, table, reason)
    _store_egress(ip, egress)
    return egress


def _iface_is_down(iface: str) -> bool:
    """True when missing or kernel operstate DOWN. WG UNKNOWN counts as up."""
    if not iface:
        return True
    try:
        if not _iface_exists(iface):
            return True
    except Exception:
        return True
    r = _run(["ip", "-br", "link", "show", "dev", iface], timeout=3)
    parts = (r.stdout or "").split()
    if len(parts) < 2:
        return True
    return parts[1].upper() == "DOWN"


def _mark_tunnel_dead(tun: str, reason: str) -> None:
    """Iface DOWN (or proven dead): drop LAN-proof immediately."""
    if tun:
        _PING_I_MISS[tun] = _PING_I_MISS_LIMIT
    _VPN_INET_CACHE[tun] = (time.time(), False)
    invalidate_lan_proof(tun, reason)


def _ping_i_uncached(iface: str) -> bool:
    r = _run(["ping", "-I", iface, "-c", "1", "-W", "2", "8.8.8.8"], timeout=5)
    ok = r.returncode == 0
    _record_ping_i(iface, ok)
    return ok


def _live_client_tunnel_ok(tun: str) -> bool:
    """Clients already on this tunnel: fail closed on down / ping -I miss.

    True cache is short (8s) so a flap is not held for the full inet TTL.
    """
    if not tun:
        return False
    now = time.time()
    cached = _VPN_INET_CACHE.get(tun)
    if cached and not cached[1] and (now - cached[0]) < 15.0:
        return False
    if _iface_is_down(tun):
        _mark_tunnel_dead(tun, f"{tun} is DOWN")
        return False
    if cached and cached[1] and (now - cached[0]) < 8.0:
        return True
    return _ping_i_uncached(tun)


def trigger_crash_log(reason: str, *, force: bool = False) -> None:
    """Write a crash snapshot. Shared 120s cooldown with the bash watchdog."""
    stamp = "/run/autovpn-crash-log.ts"
    try:
        cooldown = int(os.environ.get("AUTOVPN_CRASH_LOG_COOLDOWN", "120"))
    except ValueError:
        cooldown = 120
    now = time.time()
    if not force:
        try:
            last = int(open(stamp, encoding="utf-8").read().strip() or "0")
        except Exception:
            last = 0
        if now - last < cooldown:
            _log(f"crash-log skipped (cooldown {cooldown}s) reason={reason}")
            return
    try:
        with open(stamp, "w", encoding="utf-8") as f:
            f.write(str(int(now)))
    except Exception:
        pass
    script = ""
    for candidate in (
        "/usr/local/sbin/crash-log.sh",
        "/home/user/adaptive-gateway/scripts/crash-log.sh",
    ):
        if os.path.isfile(candidate):
            script = candidate
            break
    if not script:
        _log(f"crash-log missing reason={reason}")
        return
    _log(f"crash-log reason={reason}")
    env = os.environ.copy()
    env["AUTOVPN_CRASH_REASON"] = reason

    def _go() -> None:
        try:
            subprocess.run(
                ["timeout", "15", "/bin/bash", script],
                env=env,
                timeout=18,
                capture_output=True,
            )
        except Exception as e:
            _log(f"crash-log run warn: {e}")

    threading.Thread(target=_go, daemon=True, name="crash-log").start()


def guard_client_vpn_tables() -> list[str]:
    """If a device table default is a dead VPN, pin it to MikroTik .1 now.

    Independent of Ubuntu's own ping 8.8.8.8 on main. Does not change DHCP.
    """
    reverted: list[str] = []
    tables: set[int] = set(range(_CLIENT_TABLE_MIN, _CLIENT_TABLE_MAX + 1))
    with DEVICES_LOCK:
        for d in DEVICES.values():
            try:
                tables.add(int(d["table"]))
            except Exception:
                continue
    for table in sorted(tables):
        if table < _CLIENT_TABLE_MIN or table >= 200:
            continue
        try:
            dev = _table_default_dev(table)
        except Exception:
            continue
        if not dev or not _is_vpn_tunnel_dev(dev):
            continue
        why = ""
        if _client_egress_denied(dev):
            why = f"{dev} overlay — not a client WAN"
        elif _iface_is_down(dev):
            why = f"{dev} down"
            _mark_tunnel_dead(dev, why)
        else:
            alive = _ping_i_uncached(dev)
            stamp_ok = _lan_proof_stamp_pass(dev)
            # One ping blink must not steal a proven client VPN back to MikroTik.
            if (not alive) and (not stamp_ok) and _ping_i_misses(dev) >= _PING_I_MISS_LIMIT:
                why = f"ping -I {dev} 8.8.8.8 failed ×{_ping_i_misses(dev)}"
            elif not stamp_ok:
                ok, proof_why = lan_proof_state(dev)
                if not ok and _ping_i_misses(dev) >= _PING_I_MISS_LIMIT:
                    why = f"LAN-proof fail: {proof_why}"
        if not why:
            continue
        try:
            _install_mikrotik_default(table)
        except Exception as e:
            _log(f"WATCHDOG client table {table} pin failed: {e}")
            continue
        _log(
            f"WATCHDOG client table {table} default {dev} -> via {_MIKROTIK_IP} "
            f"({why}) — DHCP unchanged"
        )
        reverted.append(f"table-{table}:{dev}:{why}")
        with DEVICES_LOCK:
            for d in DEVICES.values():
                if int(d.get("table") or 0) != table:
                    continue
                d["egress"] = "mikrotik"
                d["egress_via"] = _MIKROTIK_IP
                d["egress_dev"] = _LAN_IFACE
                d["egress_reason"] = f"watchdog pinned table {table}: {why}"
    # Fail-close the table immediately. Do not crash-log VPN ping-I blinks.
    return reverted


def apply_device_route(device: dict, regime_id: str) -> bool:
    """Mark packets from device IP and send them via a working uplink.

    Client table default is MikroTik .1 unless choose_device_egress returns
    tunnel (FORWARD+NAT proven for a LAN source — not merely ping -I).
    Lab dummy tunnels must never become WAN — that blackholed clients.
    Host default table is never changed here.
    """
    regimes = _ctx["REGIMES"]
    meta = regimes.get(regime_id)
    if not meta:
        return False
    iface = _resolve_iface(regime_id, meta)
    mark = int(device["mark"])
    table = int(device["table"])
    ip = device["ip"]
    name = device.get("name") or ip

    if not GATEWAY_ENABLED():
        return False

    carries = bool(iface) and _vpn_carries_internet(iface)
    egress = choose_device_egress(iface, carries)
    # Extra belt: never steal a client onto a VPN if Ubuntu cannot forward.
    try:
        fwd_ok = forwarding_ready()
    except Exception:
        fwd_ok = False
    if egress["kind"] == "tunnel" and not fwd_ok:
        egress = {
            "kind": "mikrotik",
            "via": _MIKROTIK_IP,
            "dev": _LAN_IFACE,
            "reason": f"{iface} would be WAN but forwarding not ready — stay MikroTik",
        }
        _log(f"DEVICE {name} ({ip}) skip VPN default via {iface}: forwarding not ready")

    _purge_source_marks(ip)
    # Insert at 1 so overlay/LAN MARK happens before any later mangle RETURN.
    _sudo_run([
        "iptables", "-t", "mangle", "-I", "PREROUTING", "1",
        "-s", ip, "-j", "MARK", "--set-mark", str(mark),
    ])
    _ensure_device_acct(ip)

    _sudo_ip(["rule", "del", "fwmark", str(mark), "table", str(table)])
    _sudo_ip(["rule", "add", "fwmark", str(mark), "table", str(table), "priority", str(100 + mark)])

    used_tunnel = False
    if egress["kind"] == "tunnel" and egress.get("dev"):
        tun = egress["dev"]
        _ensure_egress_nat(tun)
        # Never `via 10.66.x` — that is the dummy overlay, not a WAN next-hop.
        r = _install_tunnel_default(table, tun)
        still_ok = r.returncode == 0 and vpn_client_egress_allowed(tun)
        table_ok = _table_default_mentions(table, tun)
        host_ok = _host_default_safe()
        if not host_ok:
            _restore_lab_default()
            host_ok = _host_default_safe()
        if still_ok and table_ok and host_ok:
            used_tunnel = True
            _ensure_egress_nat(tun)
            _log(
                f"DEVICE {name} ({ip}) SAW pick {iface} has LAN proof "
                f"→ table {table} default dev {tun} (host default unchanged)"
            )
        else:
            why = []
            if r.returncode != 0:
                why.append("route replace failed")
            if not still_ok:
                why.append(f"{tun} LAN FORWARD+NAT not proven")
            if not table_ok:
                why.append("table default missing iface")
            if not host_ok:
                why.append("host default would be stolen")
            reason = "; ".join(why) or "unsafe VPN default"
            _log(f"DEVICE {name} ({ip}) would blackhole via {tun} ({reason}) — MikroTik")
            _install_mikrotik_default(table)
            egress = {
                "kind": "mikrotik",
                "via": _MIKROTIK_IP,
                "dev": _LAN_IFACE,
                "reason": f"{tun} would blackhole ({reason})",
            }
    if not used_tunnel:
        r = _install_mikrotik_default(table)
        _ensure_egress_nat(_LAN_IFACE)

    ok = r.returncode == 0
    fib = _egress_from_fib(mark, table)
    if egress["kind"] == "tunnel" and fib["kind"] != "tunnel":
        _log(
            f"DEVICE {name} ({ip}) wanted {egress.get('dev')} but FIB is MikroTik "
            f"— storing actual exit"
        )
        egress = dict(fib)
        egress["reason"] = (
            f"wanted {tun if used_tunnel else iface} but packets still via MikroTik"
        )
    elif fib["kind"] == "tunnel":
        keep_reason = egress.get("reason") or fib["reason"]
        egress = dict(fib)
        egress["reason"] = keep_reason
    else:
        egress = dict(fib)
        if not used_tunnel and not egress.get("reason"):
            egress["reason"] = "MikroTik default"
    _store_egress(ip, egress)
    via = egress["dev"] if egress["kind"] == "tunnel" else f"MikroTik {_MIKROTIK_IP}"
    _log(
        f"DEVICE {name} ({ip}) pick={meta['name']} "
        f"iface={iface or '-'} exit={via} ({egress['reason']})"
    )
    _log(f"DEVICE {name} ({ip}) -> {meta['name']} mark={mark} ({'ok' if ok else 'partial'})")
    return ok


def revert_device_table(ip: str) -> bool:
    """Put one device table back on MikroTik (no DHCP change)."""
    with DEVICES_LOCK:
        d = DEVICES.get(ip)
        if not d:
            return False
        table = int(d["table"])
        mark = int(d["mark"])
        name = d.get("name") or ip
    r = _install_mikrotik_default(table)
    _store_egress(ip, {
        "kind": "mikrotik",
        "via": _MIKROTIK_IP,
        "dev": _LAN_IFACE,
        "reason": "reverted to MikroTik (safety)",
    })
    _log(f"DEVICE {name} ({ip}) table={table} mark={mark} reverted to MikroTik")
    return r.returncode == 0


def GATEWAY_ENABLED() -> bool:
    fn = _ctx.get("is_gateway_enabled")
    if callable(fn):
        return bool(fn())
    return bool(_ctx.get("GATEWAY_ENABLED", False))


def clear_device_routes() -> None:
    """Drop marks/rules/tables when Gateway Off so DHCP can go back to .1."""
    with DEVICES_LOCK:
        items = list(DEVICES.values())
    for d in items:
        ip = d["ip"]
        mark = str(d["mark"])
        table = str(d["table"])
        _purge_source_marks(ip)
        _sudo_ip(["rule", "del", "fwmark", mark, "table", table])
        _sudo_ip(["route", "flush", "table", table])
    with DEVICES_LOCK:
        for d in DEVICES.values():
            d["routed"] = False
            d["egress"] = "mikrotik"
            d["egress_via"] = _MIKROTIK_IP
            d["egress_dev"] = _LAN_IFACE
            d["egress_reason"] = "Gateway Off — DHCP back to .1"


def evaluate_device(ip: str) -> dict | None:
    with DEVICES_LOCK:
        d = DEVICES.get(ip)
        if not d:
            return None
        device = dict(d)

    # Auto hysteresis per device (runs even when Gateway is Off so the site updates)
    if device["profile"] == "auto":
        guess, evidence = classify_device(ip)
        if guess != device["auto_detected"]:
            evidence = f"leaning {_ctx['AUTO_LABELS'].get(guess, guess)} · {evidence}"
            pending = device.get("pending")
            hits = device.get("pending_hits", 0)
            if guess == pending:
                hits += 1
            else:
                pending = guess
                hits = 1
            with DEVICES_LOCK:
                if ip in DEVICES:
                    DEVICES[ip]["evidence"] = evidence
                    DEVICES[ip]["pending"] = pending
                    DEVICES[ip]["pending_hits"] = hits
            forced = opened_commit_for(ip)
            if forced is not None and guess == forced:
                need_hits, need_gap = 1, 0.0
            else:
                need_hits, need_gap = auto_hysteresis_need(
                    device["auto_detected"], guess, evidence
                )
            if hits >= need_hits and time.time() - device.get("last_switch", 0) >= need_gap:
                with DEVICES_LOCK:
                    if ip in DEVICES:
                        prev = DEVICES[ip]["auto_detected"]
                        DEVICES[ip]["auto_detected"] = guess
                        DEVICES[ip]["evidence"] = evidence.replace("leaning ", "").split(" · ", 1)[-1]
                        DEVICES[ip]["pending"] = None
                        DEVICES[ip]["pending_hits"] = 0
                        DEVICES[ip]["last_switch"] = time.time()
                        _log(f"DEVICE AUTO {device['name']} {prev} -> {guess}")
                        device = dict(DEVICES[ip])
        else:
            with DEVICES_LOCK:
                if ip in DEVICES:
                    DEVICES[ip]["evidence"] = evidence
                    DEVICES[ip]["pending"] = None
                    DEVICES[ip]["pending_hits"] = 0
            device["evidence"] = evidence

    eff = effective_device_profile(device)
    failed_ids = set()
    fail_fn = _ctx.get("fail_ids_for_ip")
    if fail_fn:
        try:
            failed_ids = set(fail_fn(ip) or ())
        except Exception:
            failed_ids = set()
    scores, rows = score_regimes_for_profile(eff, device.get("custom_weights"), failed_ids=failed_ids)
    force = device.get("force_regime")
    if force and force in scores:
        best = force
    else:
        best = max(scores, key=scores.get) if scores else device["active_regime"]

    switched = best != device.get("active_regime")
    regimes = _ctx["REGIMES"]
    prev_name = device.get("active_name") or regimes.get(
        device.get("active_regime"), {}
    ).get("name", device.get("active_regime"))
    steer = _ctx.get("device_should_steer")
    account_on = True
    if callable(steer):
        try:
            account_on = bool(steer(ip))
        except Exception:
            account_on = True
    if GATEWAY_ENABLED() and not account_on:
        try:
            revert_device_table(ip)
        except Exception as e:
            _log(f"DEVICE {ip} disconnect pin failed: {e}")
    elif GATEWAY_ENABLED():
        iface = _resolve_iface(best, regimes.get(best) or {})
        try:
            _sync_device_egress_from_fib(ip)
            with DEVICES_LOCK:
                if ip in DEVICES:
                    device["egress"] = DEVICES[ip].get("egress")
                    device["egress_dev"] = DEVICES[ip].get("egress_dev")
                    device["routed"] = DEVICES[ip].get("routed")
        except Exception:
            pass
        tun_now = ""
        if device.get("egress") == "tunnel":
            tun_now = (device.get("egress_dev") or "").strip()
        if tun_now and _iface_is_down(tun_now):
            carries = False
        else:
            carries = bool(iface) and (
                _vpn_carries_internet(iface) or _lan_proof_stamp_pass(iface)
            )
        want = choose_device_egress(iface, carries)
        have_kind = device.get("egress")
        have_dev = (device.get("egress_dev") or "").strip()
        want_dev = (want.get("dev") or "").strip() if want.get("kind") == "tunnel" else _LAN_IFACE
        try:
            fib_dev = _client_fib_dev(int(device["mark"]), int(device["table"]))
        except Exception:
            fib_dev = have_dev
        if want.get("kind") == "tunnel":
            table_drift = fib_dev != want_dev
        else:
            table_drift = _is_vpn_tunnel_dev(fib_dev)
        need = (
            switched
            or not device.get("routed")
            or have_kind != want["kind"]
            or (want["kind"] == "tunnel" and have_dev != want_dev)
            or (have_kind == "tunnel" and not carries)
            or table_drift
        )
        if need:
            apply_device_route(device, best)
        else:
            try:
                _sync_device_egress_from_fib(ip)
            except Exception:
                pass
    with DEVICES_LOCK:
        if ip in DEVICES:
            DEVICES[ip]["active_regime"] = best
            DEVICES[ip]["active_name"] = regimes.get(best, {}).get("name", best)
            if GATEWAY_ENABLED() and account_on:
                DEVICES[ip]["routed"] = True
            elif not account_on:
                DEVICES[ip]["routed"] = False
            device = dict(DEVICES[ip])

    for row in rows:
        row["is_active"] = row["id"] == best
    rows.sort(key=lambda r: r["score"], reverse=True)
    weights = saw.resolve_weights(eff, _ctx["PROFILES"], device.get("custom_weights"))
    reason = saw.explain_choice(
        rows,
        weights,
        profile_key=eff,
        device=device.get("name") or ip,
        from_name=prev_name,
        to_id=best,
        auto=device.get("profile") == "auto",
        still=not switched,
        labels=_ctx.get("AUTO_LABELS"),
    )
    now = time.time()
    last_still = float(device.get("last_still_log") or 0)
    if switched:
        _log(reason)
        last_still = now
    elif now - last_still >= saw.STILL_LOG_INTERVAL:
        _log(reason)
        last_still = now
    with DEVICES_LOCK:
        if ip in DEVICES:
            DEVICES[ip]["metrics"] = rows
            DEVICES[ip]["switch_reason"] = reason
            DEVICES[ip]["switch_reason_at"] = now
            DEVICES[ip]["last_still_log"] = last_still
            device = dict(DEVICES[ip])
    _log(
        f"TICK {device.get('name') or ip} {ip} "
        f"mode={eff} "
        f"{device.get('evidence') or 'no-evidence'} "
        f"vpn={device.get('active_name') or best} "
        f"exit={device.get('egress') or 'mikrotik'}"
    )
    return device


def evaluate_all_devices() -> None:
    sync_devices_from_leases()
    # Prove FORWARD+NAT even when Gateway is Off (DHCP stays .1).
    # Routing still fail-closed: clients only use a tunnel after Gateway On
    # AND lan_forward_proven(). Proofs must not wait on the opt-in toggle.
    try:
        refresh_lan_client_proofs()
    except Exception as e:
        _log(f"LAN-PROOF refresh error: {e}")
    now = time.time()
    with DEVICES_LOCK:
        ips = [
            ip for ip, d in DEVICES.items()
            if d.get("online")
            or (
                not d.get("metrics")
                and float(d.get("last_seen") or 0) > 0
                and (now - float(d.get("last_seen") or 0)) < 45
            )
        ]
    if GATEWAY_ENABLED():
        for ip in ips:
            try:
                _ensure_device_acct(ip)
            except Exception:
                pass
    for ip in ips:
        try:
            evaluate_device(ip)
        except Exception as e:
            _log(f"DEVICE ERROR {ip}: {e}")


def list_devices() -> list[dict]:
    labels = _ctx.get("AUTO_LABELS", {})
    if GATEWAY_ENABLED():
        with DEVICES_LOCK:
            ips = list(DEVICES.keys())
        for ip in ips:
            try:
                _sync_device_egress_from_fib(ip)
            except Exception:
                pass
    with DEVICES_LOCK:
        out = []
        for d in DEVICES.values():
            eff = effective_device_profile(d)
            out.append({
                "ip": d["ip"],
                "mac": d["mac"],
                "name": d["name"],
                "kind": d.get("kind") or ("remote" if is_zt_cloud_client(d["ip"]) else "lan"),
                "online": d.get("online", False),
                "profile": d["profile"],
                "effective_profile": eff,
                "effective_label": labels.get(eff, eff),
                "auto_detected": d.get("auto_detected"),
                "evidence": d.get("evidence"),
                "active_regime": d.get("active_regime"),
                "active_name": d.get("active_name"),
                "switch_reason": d.get("switch_reason") or "",
                "switch_reason_at": d.get("switch_reason_at") or 0,
                "last_seen": d.get("last_seen"),
                "egress": d.get("egress") or "mikrotik",
                "egress_via": d.get("egress_via") or _MIKROTIK_IP,
                "egress_dev": d.get("egress_dev") or _LAN_IFACE,
                "egress_reason": d.get("egress_reason") or "",
                "mark": d.get("mark"),
                "table": d.get("table"),
            })
        out.sort(key=lambda x: (not x["online"], x["name"].lower(), x["ip"]))
        return out


def ensure_device_scores(ip: str) -> list:
    """Fill SAW rows for a device that has never been ranked.

    Display-only: uses the shared ping cache. Does not apply client routes
    (that still happens on the engine tick). Phones opening the UI often
    hit /api/status before the first evaluate_device, which used to paint
    Connected with None.
    """
    with DEVICES_LOCK:
        d = DEVICES.get(ip)
        if not d:
            return []
        have = list(d.get("metrics") or [])
        if have:
            return have
        device = dict(d)
    eff = effective_device_profile(device)
    failed_ids = set()
    fail_fn = _ctx.get("fail_ids_for_ip")
    if fail_fn:
        try:
            failed_ids = set(fail_fn(ip) or ())
        except Exception:
            failed_ids = set()
    scores, rows = score_regimes_for_profile(
        eff, device.get("custom_weights"), failed_ids=failed_ids,
    )
    if not scores or not rows:
        return []
    best = device.get("active_regime")
    if best not in scores:
        best = max(scores, key=scores.get)
    for row in rows:
        row["is_active"] = row.get("id") == best
    rows.sort(key=lambda r: r.get("score") or 0, reverse=True)
    name = (_ctx.get("REGIMES") or {}).get(best, {}).get("name", best)
    with DEVICES_LOCK:
        if ip in DEVICES:
            DEVICES[ip]["metrics"] = rows
            DEVICES[ip]["active_regime"] = best
            DEVICES[ip]["active_name"] = name
    return rows


def get_device(ip: str) -> dict | None:
    labels = _ctx.get("AUTO_LABELS", {})
    info = _ctx.get("PROFILE_INFO", {})
    with DEVICES_LOCK:
        d = DEVICES.get(ip)
        if not d:
            return None
    if GATEWAY_ENABLED():
        try:
            _sync_device_egress_from_fib(ip)
        except Exception:
            pass
    with DEVICES_LOCK:
        d = DEVICES.get(ip)
        if not d:
            return None
        d = dict(d)
    eff = effective_device_profile(d)
    return {
        "ip": d["ip"],
        "mac": d["mac"],
        "name": d["name"],
        "kind": d.get("kind") or ("remote" if is_zt_cloud_client(d["ip"]) else "lan"),
        "online": d.get("online", False),
        "profile": d["profile"],
        "effective_profile": eff,
        "effective_label": labels.get(eff, eff),
        "profile_info": info.get(d["profile"], info.get("balanced")),
        "auto": {
            "active": d["profile"] == "auto",
            "detected": d.get("auto_detected"),
            "label": labels.get(d.get("auto_detected", "balanced"), d.get("auto_detected")),
            "evidence": d.get("evidence"),
        },
        "evidence": d.get("evidence"),
        "active_regime": d.get("active_regime"),
        "active_name": d.get("active_name"),
        "switch_reason": d.get("switch_reason") or "",
        "switch_reason_at": d.get("switch_reason_at") or 0,
        "metrics": d.get("metrics") or [],
        "custom_weights": d.get("custom_weights"),
        "mark": d.get("mark"),
        "table": d.get("table"),
        "egress": d.get("egress") or "mikrotik",
        "egress_via": d.get("egress_via") or _MIKROTIK_IP,
        "egress_dev": d.get("egress_dev") or _LAN_IFACE,
        "egress_reason": d.get("egress_reason") or "",
    }


def set_device_profile(ip: str, profile: str, custom_weights=None) -> dict | None:
    allowed = set(_ctx["PROFILES"]) | {"custom", "auto"}
    if profile not in allowed:
        raise ValueError("unknown profile")
    with DEVICES_LOCK:
        if ip not in DEVICES:
            return None
        DEVICES[ip]["profile"] = profile
        DEVICES[ip]["force_regime"] = None
        if custom_weights is not None:
            DEVICES[ip]["custom_weights"] = custom_weights
        name = DEVICES[ip]["name"]
    # classify_device takes DEVICES_LOCK — never call it while holding the lock.
    if profile == "auto":
        guess, evidence = classify_device(ip)
        with DEVICES_LOCK:
            if ip in DEVICES:
                DEVICES[ip]["auto_detected"] = guess
                DEVICES[ip]["evidence"] = evidence
                DEVICES[ip]["pending"] = None
                DEVICES[ip]["pending_hits"] = 0
                DEVICES[ip]["last_switch"] = time.time()
    _log(f"DEVICE PROFILE {name} ({ip}) -> {profile}")
    return evaluate_device(ip)


def set_device_force(ip: str, regime_id: str | None) -> dict | None:
    with DEVICES_LOCK:
        if ip not in DEVICES:
            return None
        DEVICES[ip]["force_regime"] = regime_id or None
    return evaluate_device(ip)


def clear_all_force_regimes() -> int:
    """Drop leftover Force VPN pins so Auto/SAW pick naturally."""
    n = 0
    with DEVICES_LOCK:
        for d in DEVICES.values():
            if d.get("force_regime"):
                d["force_regime"] = None
                n += 1
    return n


def rename_device(ip: str, name: str) -> dict | None:
    with DEVICES_LOCK:
        if ip not in DEVICES:
            return None
        DEVICES[ip]["name"] = name.strip() or DEVICES[ip]["name"]
    return get_device(ip)
