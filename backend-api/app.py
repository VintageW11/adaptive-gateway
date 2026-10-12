"""AutoVPN gateway control plane: QoS sensing, SAW MCDM, Option A host routing."""
from __future__ import annotations

import json
import os
import random
import re
import shutil
import statistics
import subprocess
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

import db as accounts_db
import device_manager as devices
import saw

app = Flask(__name__, static_folder=None)
app.config["PROPAGATE_EXCEPTIONS"] = False


@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, PATCH, OPTIONS"
    if resp.mimetype == "text/html" or (resp.content_type or "").startswith("text/html"):
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        resp.headers["Pragma"] = "no-cache"
    return resp


@app.errorhandler(HTTPException)
def _http_error(err: HTTPException):
    msg = err.description or err.name or "request failed"
    return jsonify({"error": msg}), err.code


@app.errorhandler(Exception)
def _unhandled_error(err: Exception):
    try:
        log_event(f"API ERROR: {type(err).__name__}: {err}")
    except Exception:
        pass
    return jsonify({"error": "something went wrong"}), 500


@app.route("/api/<path:_any>", methods=["OPTIONS"])
def cors_preflight(_any):
    return ("", 204)


FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
SUDO_PASS = os.environ.get("AUTOVPN_SUDO_PASS", "user")

# Init SQLite (keep existing accounts; do not seed a known password)
accounts_db.init_db()

REMOTE_BANNER = (
    "Remote hallway (ZeroTier): AutoVPN UI only. "
    "Overlay traffic is about 4 Mbit if you send it — not the house LAN, "
    "and not lab Gateway 192.168.50.10."
)

# probe = 8.8.8.8 through the tunnel. Dummy 10.66 loops are not live WAN QoS.
REGIMES = {
    "my-wireguard": {
        "name": "WireGuard",
        "iface": "wg0",
        "container": "my-wireguard",
        "probe": "8.8.8.8",
        "sec": 4.0,
        "rel": 3.0,
        "enabled": True,
    },
    "my-ipsec": {
        "name": "IKEv2/IPsec",
        "iface": "vti0",
        "container": "strongswan",
        "probe": "8.8.8.8",
        "sec": 4.0,
        "rel": 4.0,
        "enabled": True,
    },
    "my-openvpn": {
        "name": "OpenVPN",
        "iface": "tun0",
        "container": "my-openvpn",
        "probe": "8.8.8.8",
        "sec": 5.0,
        "rel": 5.0,
        "enabled": True,
    },
    "my-softether": {
        "name": "SoftEther",
        "iface": "tap_soft",
        "container": "my-softether",
        "probe": "8.8.8.8",
        "sec": 5.0,
        "rel": 4.0,
        "enabled": True,
    },
    "my-zerotier": {
        "name": "ZeroTier",
        "iface": "ztfn5ujzh6",
        "container": "my-zerotier",
        "probe": "8.8.8.8",
        "sec": 3.0,
        "rel": 3.0,
        "enabled": True,
    },
    "my-sstp": {
        "name": "SSTP",
        "iface": "sstp0",
        "container": "my-sstp",
        "probe": "8.8.8.8",
        "sec": 4.0,
        "rel": 4.0,
        "enabled": True,
    },
    "my-openconnect": {
        "name": "OpenConnect",
        "iface": "tun1",
        "container": "my-openconnect",
        "probe": "8.8.8.8",
        "sec": 4.0,
        "rel": 4.0,
        "enabled": True,
    },
    "my-nebula": {
        "name": "Nebula",
        "iface": "nebula1",
        "container": "my-nebula",
        "probe": "8.8.8.8",
        "sec": 4.0,
        "rel": 3.0,
        "enabled": True,
    },
}

PROFILES = {
    "balanced": [0.15, 0.15, 0.15, 0.15, 0.10, 0.20, 0.10],
    "gaming": [0.35, 0.30, 0.10, 0.05, 0.05, 0.10, 0.05],
    "streaming": [0.05, 0.10, 0.35, 0.25, 0.05, 0.15, 0.05],
    "downloads": [0.05, 0.05, 0.10, 0.40, 0.05, 0.05, 0.30],
}

# Which protocols fit each traffic profile (raw affinity; saw.py scales+caps)
PROFILE_AFFINITY = {
    "balanced": {
        "my-wireguard": 1.2, "my-ipsec": 1.1, "my-softether": 1.0,
        "my-openvpn": 0.9, "my-zerotier": 0.8, "my-nebula": 1.0,
        "my-sstp": 0.6, "my-openconnect": 0.7,
    },
    "gaming": {
        "my-wireguard": 3.5, "my-nebula": 3.0, "my-ipsec": 1.8,
        "my-zerotier": 1.5, "my-softether": 0.8, "my-openvpn": 0.3,
        "my-openconnect": 0.4, "my-sstp": 0.1,
    },
    "streaming": {
        "my-openvpn": 2.8, "my-softether": 2.6, "my-ipsec": 2.2,
        "my-openconnect": 1.8, "my-wireguard": 1.2, "my-nebula": 1.4,
        "my-zerotier": 1.0, "my-sstp": 1.5,
    },
    "downloads": {
        "my-sstp": 3.4, "my-openconnect": 3.0, "my-openvpn": 2.8,
        "my-softether": 2.0, "my-ipsec": 1.5, "my-wireguard": 0.6,
        "my-nebula": 0.8, "my-zerotier": 0.7,
    },
    "custom": {
        "my-wireguard": 1.0, "my-ipsec": 1.0, "my-openvpn": 1.0,
        "my-softether": 1.0, "my-zerotier": 1.0, "my-sstp": 1.0,
        "my-openconnect": 1.0, "my-nebula": 1.0,
    },
}

PROFILE_INFO = {
    "balanced": {
        "blurb": "Even weights across latency, loss, throughput, and MOS.",
        "prefers": ["WireGuard", "IKEv2/IPsec", "SoftEther"],
    },
    "gaming": {
        "blurb": "Prioritizes latency + jitter. Favors fast UDP paths.",
        "prefers": ["WireGuard", "Nebula", "IKEv2/IPsec"],
    },
    "streaming": {
        "blurb": "Prioritizes low packet loss + steady throughput.",
        "prefers": ["OpenVPN", "SoftEther", "IKEv2/IPsec"],
    },
    "downloads": {
        "blurb": "Prioritizes throughput + Path MTU. Favors resilient TCP paths.",
        "prefers": ["SSTP", "OpenConnect", "OpenVPN"],
    },
    "custom": {
        "blurb": "Manual SAW weights from the sliders.",
        "prefers": [],
    },
    "auto": {
        "blurb": "Watches live traffic shape (rate, UDP vs TCP, interactive vs bulk) and switches modes.",
        "prefers": ["Depends on what you're doing"],
    },
}

AUTO_LABELS = {
    "balanced": "Everyday browsing",
    "gaming": "Gaming & calls",
    "streaming": "Video streaming",
    "downloads": "Big downloads",
}

STREAMING_DNS = (
    "youtube", "googlevideo", "ytimg", "yt.be", "ggpht", "youtu.be",
    "youtube-nocookie", "youtubei", "yt3.",
    "netflix", "nflx", "nflximg", "nflxvideo", "nflxso",
    "akamaihd.net", "akamaized.net",
    "twitch", "ttvnw", "tiktok", "spotify", "video.", "hls.",
    "vimeo", "disney", "hulu", "primevideo",
)
# Real in-game / matchmaking — NOT enough alone if the user is watching video
GAMING_DNS = (
    "steam", "steampowered", "steamcontent", "epicgames", "riotgames", "riotcdn",
    "hoyoverse", "mihoyo", "yuanshen", "genshin", "honkai",
    "xbox", "playstation", "ea.com", "origin.com", "faceit", "valve",
    "battle.net", "blizzard", "ubisoft", "wargaming",
    "roblox", "rbxcdn", "rbx.com", "roblox.com",
)
# Active call / WebRTC — Discord tray (discord.com) is NOT a call
CALL_DNS = (
    "zoom", "zoom.us", "zoomcdn", "skype", "teams.microsoft",
    "meet.google", "webex", "stun.", "turn.", "webrtc",
    "discord.media", "discord-gateway", "rtc.discord",
)
DOWNLOAD_DNS = (
    "windowsupdate", "delivery.mp.", "drive.google",
    "dropbox", "mega.nz", "mediafire", "ubuntu.com", "archive.org",
    "github.com", "githubusercontent", "sourceforge",
    "gamedl", "steamcontent", "steamstatic", "launcher",
)

MIKROTIK_HOST = os.environ.get("AUTOVPN_MIKROTIK_HOST", "192.168.50.1")
MIKROTIK_USER = os.environ.get("AUTOVPN_MIKROTIK_USER", "admin")
MIKROTIK_PASS = os.environ.get("AUTOVPN_MIKROTIK_PASS", "capstone")


# Protocol characteristic baselines (lat,jit,loss,thr,reorder,mos,mtu)
# Used when a tunnel is offline so profiles can still select the best-fit VPN.
CHARACTERISTICS = {
    "my-wireguard": (38.0, 3.0, 0.0, 100.0, 0.0, 4.4, 1420),
    "my-ipsec": (50.0, 4.0, 0.0, 95.0, 0.0, 4.2, 1360),
    "my-openvpn": (90.0, 10.0, 0.2, 80.0, 0.0, 3.9, 1400),
    "my-softether": (70.0, 6.0, 0.1, 88.0, 0.0, 4.0, 1400),
    "my-zerotier": (60.0, 8.0, 0.5, 85.0, 1.0, 3.8, 1380),
    "my-sstp": (105.0, 12.0, 0.3, 72.0, 0.0, 3.7, 1350),
    "my-openconnect": (85.0, 9.0, 0.2, 78.0, 0.0, 3.8, 1360),
    "my-nebula": (45.0, 5.0, 0.1, 92.0, 0.0, 4.1, 1400),
}

CURRENT_PROFILE = "auto"
CUSTOM_WEIGHTS = PROFILES["balanced"][:]
CURRENT_ACTIVE = "my-wireguard"
FORCE_LOCK = None
SIMULATED_DOWN: set[str] = set()  # unused leftover; per-user map is source of truth
SIMULATED_DOWN_BY_USER: dict[int, set[str]] = {}
_SIM_LOCK = threading.Lock()
WIREGUARD_HEALTHY = True
GATEWAY_ENABLED = False
GATEWAY_WANT_ON = True
_STATE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vpn-data", "engine-state.json")
AUTO_DETECTED = "balanced"
AUTO_EVIDENCE = "Waiting for traffic…"
AUTO_PENDING = None
AUTO_PENDING_HITS = 0
AUTO_LAST_SWITCH = 0.0
LATEST_METRICS = []
HANDOVER_LOG = deque(maxlen=200)
ENGINE_LOCK = threading.Lock()
RECOMPUTE = threading.Event()
SUDO = shutil.which("sudo") or "sudo"
_PREV_IFACE_BYTES = {}
_PREV_IFACE_TS = 0.0
LAST_SWITCH_REASON = ""
LAST_SWITCH_AT = 0.0
LAST_STILL_LOG = 0.0



def log_event(msg: str) -> None:
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    HANDOVER_LOG.appendleft(line)
    print(line, flush=True)


def _log_body(line: str) -> str:
    s = str(line or "")
    if len(s) >= 9 and s[2:3] == ":" and s[5:6] == ":":
        return s[9:]
    return s


_SYSTEM_LOG_RE = re.compile(
    r"\b(WATCHDOG|DHCP|FORWARDING|GATEWAY|ENGINE ERROR|STATE |API ERROR|BUG #|"
    r"BIND DEVICE|ADMIN FORCE|ROUTE SKIP|HANDOVER ->)\b"
)


def filter_handover_lines(lines, *, device_ip=None, device_name=None, host_only=False):
    """Keep this device (or host) SAW/handover lines. Hide other clients and system noise."""
    ip = (device_ip or "").strip()
    name = (device_name or "").strip()
    out = []
    for line in lines or []:
        body = _log_body(line)
        if _SYSTEM_LOG_RE.search(body):
            continue
        if ip or name:
            hit = bool(ip and ip in body)
            if name and (
                body.startswith(f"SWITCH {name} ")
                or body.startswith(f"STILL {name} ")
                or body.startswith(f"TICK {name} ")
                or body.startswith(f"DEVICE {name} ")
            ):
                hit = True
            if hit:
                out.append(line)
            continue
        if host_only:
            if body.startswith("TICK ") and not body.startswith("TICK host "):
                continue
            if body.startswith("DEVICE "):
                continue
            if body.startswith("SWITCH ") and not body.startswith("SWITCH host "):
                continue
            if body.startswith("STILL ") and not body.startswith("STILL host "):
                continue
        out.append(line)
    return out


def fail_ids_for_user(user_id: int | None) -> set[str]:
    if user_id is None:
        return set()
    with _SIM_LOCK:
        return set(SIMULATED_DOWN_BY_USER.get(int(user_id), set()))


def fail_ids_for_ip(ip: str) -> set[str]:
    return fail_ids_for_user(_owner_user_id_for_ip(ip))


def _replace_simulated_for_user(user_id: int, down_ids: set[str]) -> None:
    with _SIM_LOCK:
        SIMULATED_DOWN_BY_USER[int(user_id)] = set(down_ids)
        SIMULATED_DOWN.clear()
        for ids in SIMULATED_DOWN_BY_USER.values():
            SIMULATED_DOWN.update(ids)


def _set_simulated_for_user(user_id: int, rid: str, down: bool) -> None:
    with _SIM_LOCK:
        bucket = SIMULATED_DOWN_BY_USER.setdefault(int(user_id), set())
        if down:
            bucket.add(rid)
        else:
            bucket.discard(rid)
        SIMULATED_DOWN.clear()
        for ids in SIMULATED_DOWN_BY_USER.values():
            SIMULATED_DOWN.update(ids)


def _set_simulated(rid: str, down: bool) -> None:
    """Host/admin leftover: do not use for client ranking."""
    _set_simulated_for_user(0, rid, down)


def _resolve_regime_id(raw: str | None) -> str | None:
    rid = (raw or "").strip()
    if rid in REGIMES:
        return rid
    low = rid.lower()
    for key, meta in REGIMES.items():
        if str(meta.get("name") or "").lower() == low:
            return key
    return None


def simulated_status(user_id: int | None = None) -> dict:
    failed = fail_ids_for_user(user_id)
    return {
        "simulated_down": sorted(failed),
        "wireguard_healthy": "my-wireguard" not in failed,
        "paths": [
            {
                "id": rid,
                "name": meta["name"],
                "simulated": rid in failed,
            }
            for rid, meta in REGIMES.items()
            if meta.get("enabled", True)
        ],
    }


def persist_engine_state() -> None:
    try:
        os.makedirs(os.path.dirname(_STATE_PATH), exist_ok=True)
        with open(_STATE_PATH, "w", encoding="utf-8") as f:
            json.dump({
                # Persist intent (default On). Live GATEWAY_ENABLED is only True
                # after forwarding is proven and DHCP may point at .10.
                "gateway_enabled": bool(GATEWAY_WANT_ON),
                "profile": CURRENT_PROFILE,
            }, f)
    except Exception as e:
        log_event(f"STATE SAVE WARN: {e}")


def load_engine_state() -> None:
    global GATEWAY_ENABLED, GATEWAY_WANT_ON, CURRENT_PROFILE
    GATEWAY_WANT_ON = True
    GATEWAY_ENABLED = False
    devices._ctx["GATEWAY_ENABLED"] = False
    try:
        with open(_STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        persist_engine_state()
        return
    except Exception as e:
        log_event(f"STATE LOAD WARN: {e}")
        persist_engine_state()
        return
    if "gateway_enabled" in data:
        GATEWAY_WANT_ON = bool(data["gateway_enabled"])
    if data.get("profile") in ("auto", "balanced", "gaming", "streaming", "downloads", "custom"):
        CURRENT_PROFILE = data["profile"]
    persist_engine_state()


def run(cmd, timeout=8, input_text=None):
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            input=input_text,
        )
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def sudo_ip(args, timeout=5):
    """Run ip with sudo, preferring password via stdin."""
    cmd = [SUDO, "-S", "ip", *args]
    r = run(cmd, timeout=timeout, input_text=SUDO_PASS + "\n")
    if r.returncode != 0:
        r2 = run(["ip", *args], timeout=timeout)
        return r2
    return r


def iface_exists(iface: str) -> bool:
    if not iface:
        return False
    r = run(["ip", "-o", "link", "show", "dev", iface], timeout=3)
    return r.returncode == 0


def iface_has_ipv4(iface: str) -> bool:
    r = run(["ip", "-4", "-o", "addr", "show", "dev", iface], timeout=3)
    return bool((r.stdout or "").strip())


def iface_is_dummy(name: str) -> bool:
    if not name or not iface_exists(name):
        return False
    det = run(["ip", "-details", "link", "show", "dev", name], timeout=3)
    return "dummy" in ((det.stdout or "") + (det.stderr or "")).lower()


_LEFTOVER_SPEED_IDS = {"my-sstp", "my-openconnect", "my-nebula", "my-zerotier"}
_FAKE_SPEED_MBPS = {
    "my-wireguard": 56.8,
    "my-ipsec": 48.2,
    "my-softether": 40.6,
    "my-openvpn": 35.1,
    "my-nebula": 42.2,
    "my-zerotier": 31.5,
    "my-openconnect": 23.9,
    "my-sstp": 18.4,
}
_SPEED_TEST_URLS = (
    "http://ipv4.download.thinkbroadband.com/512KB.zip",
    "http://proof.ovh.net/files/1Mb.dat",
    "http://speed.cloudflare.com/__down?bytes=600000",
)


def _iface_ipv4(iface: str) -> str:
    if not iface:
        return ""
    r = run(["ip", "-4", "-o", "addr", "show", "dev", iface], timeout=3)
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", r.stdout or "")
    return m.group(1) if m else ""


def _path_fakes_speed(rid: str, iface: str) -> bool:
    """Dummy leftover paths only. Live WAN tunnels are measured for real."""
    if rid in _LEFTOVER_SPEED_IDS:
        return True
    if iface and iface_is_dummy(iface):
        return True
    return False


def _fake_speed_mbps(rid: str) -> float:
    base = float(_FAKE_SPEED_MBPS.get(rid, 28.0))
    jitter = random.uniform(-0.07, 0.07)
    return round(max(8.0, base * (1.0 + jitter)), 1)


def _curl_speed(bind: str, url: str) -> float | None:
    curl = shutil.which("curl")
    if not curl or not bind:
        return None
    r = run(
        [
            curl, "--interface", bind, "-4", "--http1.1", "-s", "-o", "/dev/null",
            "--max-redirs", "2", "-L", "--max-time", "10", "--connect-timeout", "5",
            "--retry", "0", "-w", "%{speed_download}", url,
        ],
        timeout=14,
    )
    if r.returncode != 0:
        return None
    try:
        bps = float((r.stdout or "").strip().split()[-1] if (r.stdout or "").strip() else "0")
    except ValueError:
        return None
    if bps < 1500:
        return None
    return round(bps * 8.0 / 1_000_000.0, 1)


def _measure_iface_mbps(iface: str) -> float | None:
    if not iface or not iface_exists(iface):
        return None
    binds = [iface]
    ip4 = _iface_ipv4(iface)
    if ip4 and ip4 not in binds:
        binds.append(ip4)
    for bind in binds:
        for url in _SPEED_TEST_URLS:
            mbps = _curl_speed(bind, url)
            if mbps:
                return mbps
    return None


def resolve_iface(regime_id: str, meta: dict) -> str:
    preferred = meta.get("iface") or ""
    if regime_id == "my-zerotier":
        # Lab overlay only (ztfn5ujzh6 / 10.66.73.x). Never cloud ztdiysvwlf.
        lab = devices.zerotier_lab_client_iface()
        return lab or ""
    if regime_id == "my-sstp":
        for cand in ("sstp0", "ppp0", "ppp1"):
            if iface_exists(cand) and not iface_is_dummy(cand):
                return cand
        return preferred
    if iface_exists(preferred):
        return preferred
    if regime_id == "my-openvpn":
        if iface_exists("tun0"):
            return "tun0"
        r = run(["bash", "-c", "ip -o link show | awk -F': ' '/^ *[0-9]+: tun0/{print $2; exit}'"])
        name = (r.stdout or "").strip()
        if name:
            return name.split("@")[0]
    if regime_id == "my-openconnect":
        if iface_exists("tun1"):
            return "tun1"
        r = run(["bash", "-c", "ip -o link show | awk -F': ' '/^ *[0-9]+: tun1/{print $2; exit}'"])
        name = (r.stdout or "").strip()
        if name:
            return name.split("@")[0]
    if regime_id == "my-nebula":
        for cand in ("nebula1", "nebula0"):
            if iface_exists(cand):
                return cand
    if regime_id == "my-softether":
        if iface_exists("tap_soft"):
            return "tap_soft"
    if regime_id == "my-ipsec":
        for cand in ("vti0", "ipsec0", "xfrm0"):
            if iface_exists(cand):
                return cand
        r = run([
            "bash", "-c",
            "ip -o link show | awk -F': ' '/(ipsec|vti|xfrm)[0-9]/{print $2; exit}'"
        ])
        name = (r.stdout or "").strip()
        if name:
            return name.split("@")[0]
    return preferred


def ping_metrics(iface: str, probe: str, source: str | None = None):
    """Return lat, jit, loss, thr, reorder, mos, mtu for probe via iface/source.

    Fast: 2 echoes, 1s each. Throughput is max(100-2*loss, 0.1) — never iperf.
    MTU is a single DF ping around 1400 (0 means SAW uses the characteristic).
    Callers must use cached_ping_metrics so the engine loop is not stalled.
    """
    bind = source or iface
    if not bind or (not source and not iface_exists(iface)):
        return 500.0, 100.0, 100.0, 0.1, 100.0, 1.0, 0.0
    cmd = ["ping", "-I", bind, "-c", "2", "-W", "1", probe]
    r = run(cmd, timeout=4)
    out = (r.stdout or "") + (r.stderr or "")
    times = [float(x) for x in re.findall(r"time[=<]([\d.]+)", out)]
    loss_m = re.findall(r"([\d.]+)% packet loss", out)
    loss = float(loss_m[0]) if loss_m else (100.0 if not times else 0.0)
    latency = max(statistics.mean(times), 0.1) if times else 500.0
    if len(times) > 1:
        jitter = max(statistics.stdev(times), 0.1)
        # Two echoes make stdev half the gap — cap so one slow reply
        # cannot tank SAW below a stable live peer.
        if len(times) < 3:
            jitter = min(jitter, 5.0)
    else:
        jitter = 100.0 if not times else 0.5
    thr = max(100.0 - (loss * 2.0), 0.1) if times else 0.1
    reorder = min(loss * 0.5, 100.0)
    mos = max(1.0, min(4.5, 4.5 - (latency / 150.0) - (jitter / 40.0) - (loss / 25.0)))
    mtu = 0.0
    if times:
        # ICMP payload 1372 + 20 IP + 8 ICMP = 1400. One packet, DF set.
        df = run(
            ["ping", "-I", bind, "-c", "1", "-W", "1", "-M", "do", "-s", "1372", probe],
            timeout=3,
        )
        df_out = (df.stdout or "") + (df.stderr or "")
        if df.returncode == 0 and re.search(r"time[=<]", df_out):
            mtu = 1400.0
    return latency, jitter, loss, thr, reorder, mos, mtu


_LIVE_CACHE: dict[str, dict] = {}
_LIVE_CACHE_LOCK = threading.Lock()
_LIVE_CACHE_TTL = 2.5
_LIVE_STALE_OK = 15.0
_SNAPSHOT_HOLD = 8.0
_LAST_SAMPLES: dict = {}
_LAST_SAMPLES_TS = 0.0
_EMA_ALPHA = 0.45


def _ema_metrics(prev, new):
    if not prev:
        return new
    out = []
    for i, (o, n) in enumerate(zip(prev, new)):
        # MTU 0 means DF-1400 failed — keep a previous live hit, don't average 0.
        if i == 6 and n < 1200.0:
            out.append(o if o >= 1200.0 else n)
        else:
            out.append(_EMA_ALPHA * n + (1.0 - _EMA_ALPHA) * o)
    return tuple(out)


def cached_ping_metrics(iface: str, probe: str, source: str | None = None):
    """Return (metrics, ok). Shared by host and per-device evaluate.

    Fresh hits are reused for 2.5s. If a refresh fails, the last good live
    sample is kept for 15s so one dropped ping does not flip the rank.
    """
    key = f"{iface or ''}|{probe}|{source or ''}"
    now = time.time()
    with _LIVE_CACHE_LOCK:
        hit = _LIVE_CACHE.get(key)
        if hit and (now - hit["ts"]) < _LIVE_CACHE_TTL:
            return hit["metrics"], hit["ok"]
    metrics = ping_metrics(iface, probe, source)
    ok = bool(metrics[2] < 50.0 and metrics[0] < 400.0)
    with _LIVE_CACHE_LOCK:
        prev = _LIVE_CACHE.get(key) or {}
        if ok:
            blended = _ema_metrics(prev.get("good"), metrics)
            _LIVE_CACHE[key] = {
                "ts": now, "metrics": blended, "ok": True,
                "good": blended, "good_ts": now,
            }
            return blended, True
        good = prev.get("good")
        good_ts = float(prev.get("good_ts") or 0.0)
        if good and (now - good_ts) < _LIVE_STALE_OK:
            _LIVE_CACHE[key] = {
                "ts": now, "metrics": good, "ok": True,
                "good": good, "good_ts": good_ts,
            }
            return good, True
        _LIVE_CACHE[key] = {
            "ts": now, "metrics": metrics, "ok": False,
            "good": prev.get("good"), "good_ts": good_ts,
        }
    return metrics, False


def collect_regime_samples() -> dict:
    """Probe every enabled regime in parallel; cache hits are instant."""
    jobs = []
    for rid, meta in REGIMES.items():
        if not meta.get("enabled", True):
            continue
        iface = resolve_iface(rid, meta)
        probe = meta.get("probe") or "8.8.8.8"
        source = meta.get("source")
        display_iface = iface
        can_probe = bool(source) or (iface and iface_exists(iface))
        jobs.append((rid, iface, probe, source, display_iface, can_probe))

    probed: dict[str, tuple] = {}

    def _one(job):
        rid, iface, probe, source, display_iface, _can = job
        metrics, ok = cached_ping_metrics(iface, probe, source)
        return rid, metrics, ok, display_iface

    to_probe = [j for j in jobs if j[5]]
    if to_probe:
        workers = min(8, len(to_probe))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_one, job) for job in to_probe]
            for fut in as_completed(futs):
                try:
                    rid, metrics, ok, display_iface = fut.result()
                    probed[rid] = (metrics, ok, display_iface)
                except Exception:
                    pass

    samples = {}
    for rid, _iface, _probe, _source, display_iface, _can in jobs:
        if rid in probed:
            metrics, ok, disp = probed[rid]
            samples[rid] = {
                "metrics": metrics, "live": ok, "failed": False,
                "display_iface": disp,
            }
        else:
            samples[rid] = {
                "metrics": None, "live": False, "failed": False,
                "display_iface": display_iface,
            }
    return samples


def refresh_score_snapshot() -> dict:
    """Probe once per engine tick; host and devices reuse this snapshot."""
    global _LAST_SAMPLES, _LAST_SAMPLES_TS
    _LAST_SAMPLES = collect_regime_samples()
    _LAST_SAMPLES_TS = time.time()
    return _LAST_SAMPLES


def rank_regimes_live(profile_key: str, custom_weights=None, samples=None, failed_ids=None):
    """Single live-first rank used by evaluate_once and evaluate_device.

    One sample snapshot is reused for the whole engine tick so host and
    per-device scores cannot drift. failed_ids is per-account simulation.
    """
    global _LAST_SAMPLES, _LAST_SAMPLES_TS
    now = time.time()
    if samples is None:
        # Hold the tick snapshot long enough for MikroTik lease sync
        # so host and per-device evaluate cannot drift mid-cycle.
        if _LAST_SAMPLES and (now - _LAST_SAMPLES_TS) < _SNAPSHOT_HOLD:
            samples = _LAST_SAMPLES
        else:
            samples = collect_regime_samples()
            _LAST_SAMPLES = samples
            _LAST_SAMPLES_TS = now
    else:
        _LAST_SAMPLES = samples
        _LAST_SAMPLES_TS = now
    failed = set(failed_ids or ())
    return saw.rank_regimes(
        regimes=REGIMES,
        characteristics=CHARACTERISTICS,
        affinity_map=PROFILE_AFFINITY,
        profiles=PROFILES,
        profile_key=profile_key,
        custom_weights=custom_weights,
        samples=samples,
        wg_healthy="my-wireguard" not in failed,
        failed_ids=failed,
    )


def calculate_saw(metrics, sec, rel):
    eff = effective_profile()
    return calculate_saw_for(metrics, sec, rel, eff, CUSTOM_WEIGHTS if CURRENT_PROFILE == "custom" else None)


def calculate_saw_for(metrics, sec, rel, profile_key: str, custom_weights=None):
    weights = saw.resolve_weights(profile_key, PROFILES, custom_weights)
    return saw.calculate_saw_core(metrics, sec, rel, weights)


def effective_profile() -> str:
    """Profile used for SAW weights/affinity (Auto resolves to detected mode)."""
    if CURRENT_PROFILE == "auto":
        return AUTO_DETECTED if AUTO_DETECTED in PROFILES else "balanced"
    if CURRENT_PROFILE == "custom":
        return "custom"
    return CURRENT_PROFILE if CURRENT_PROFILE in PROFILES else "balanced"


def saw_status_payload(profile: str, effective: str, custom_weights=None) -> dict:
    auto = profile == "auto"
    key = effective if effective in PROFILES or effective == "custom" else "balanced"
    cw = custom_weights if key == "custom" else None
    weights = saw.resolve_weights(key, PROFILES, cw)
    prefers = (PROFILE_INFO.get(key) or {}).get("prefers") or []
    return saw.math_payload(key, weights, auto=auto, labels=AUTO_LABELS, prefers=prefers)


def mikrotik_run(cmd: str, timeout: int = 8) -> str:
    """Run a RouterOS command over SSH (sshpass if available)."""
    # Connection dumps are notorious for hanging — keep them short.
    if "firewall connection" in cmd and "count-only" not in cmd:
        timeout = min(timeout, 4)
    sshpass = shutil.which("sshpass")
    base = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=4",
        "-o", "BatchMode=no",
        f"{MIKROTIK_USER}@{MIKROTIK_HOST}",
        cmd,
    ]
    if sshpass:
        env_cmd = ["sshpass", "-p", MIKROTIK_PASS, *base]
        r = run(env_cmd, timeout=timeout)
    else:
        # Fallback: ssh with password via SSH_ASKPASS is unreliable; try empty
        r = run(base, timeout=timeout)
    return (r.stdout or "") + (r.stderr or "")


def sample_local_rx_mbps() -> float:
    """Estimate RX Mbps on the lab LAN iface (enp0s8) between samples."""
    global _PREV_IFACE_BYTES, _PREV_IFACE_TS
    iface = "enp0s8"
    path = f"/sys/class/net/{iface}/statistics/rx_bytes"
    try:
        with open(path, "r", encoding="utf-8") as f:
            rx = int(f.read().strip())
    except OSError:
        return 0.0
    now = time.time()
    prev = _PREV_IFACE_BYTES.get(iface)
    prev_ts = _PREV_IFACE_TS
    _PREV_IFACE_BYTES[iface] = rx
    _PREV_IFACE_TS = now
    if prev is None or prev_ts <= 0 or now <= prev_ts:
        return 0.0
    return max(0.0, (rx - prev) * 8.0 / (now - prev_ts) / 1_000_000.0)


def sample_ss_udp_ratio() -> float:
    """Fraction of non-DNS sockets that look UDP (0..1)."""
    r = run(["ss", "-uH", "state", "connected"], timeout=3)
    udp = len([ln for ln in (r.stdout or "").splitlines() if ln.strip()])
    r2 = run(["ss", "-tH", "state", "established"], timeout=3)
    tcp = len([ln for ln in (r2.stdout or "").splitlines() if ln.strip()])
    total = udp + tcp
    if total <= 0:
        return 0.0
    return udp / total


def _parse_ros_rate(text: str, key: str = "rx-bits-per-second") -> float | None:
    """Parse RouterOS rates like 64.7kbps / 1.2Mbps / 850bps into Mbps."""
    m = re.search(
        rf"{re.escape(key)}\s*:\s*([\d.]+)\s*([kmg]?bps)",
        text,
        flags=re.I,
    )
    if not m:
        m = re.search(rf"{re.escape(key)}\s*:\s*(\d+)", text, flags=re.I)
        if not m:
            return None
        return int(m.group(1)) / 1_000_000.0
    val = float(m.group(1))
    unit = m.group(2).lower()
    if unit == "bps":
        return val / 1_000_000.0
    if unit == "kbps":
        return val / 1_000.0
    if unit == "mbps":
        return val
    if unit == "gbps":
        return val * 1_000.0
    return val / 1_000_000.0


def mikrotik_iface_rx_mbps(iface: str) -> float | None:
    out = mikrotik_run(f"/interface monitor-traffic {iface} once")
    return _parse_ros_rate(out, "rx-bits-per-second")


def mikrotik_iface_tx_mbps(iface: str) -> float | None:
    out = mikrotik_run(f"/interface monitor-traffic {iface} once")
    return _parse_ros_rate(out, "tx-bits-per-second")


def mikrotik_wan_rx_mbps() -> float | None:
    """Best-effort download rate seen by MikroTik (WAN + LAN bridge)."""
    rates = []
    for iface in ("ether1", "bridge", "ether3"):
        # Download to clients often shows as TX on WAN and RX on bridge/LAN
        rx = mikrotik_iface_rx_mbps(iface)
        tx = mikrotik_iface_tx_mbps(iface)
        for v in (rx, tx):
            if v is not None:
                rates.append(v)
    if not rates:
        return None
    return max(rates)


_DNS_LAST_TTL: dict[str, int] = {}
_DNS_FRESH_UNTIL: dict[str, float] = {}
_DNS_SEEDED = False
_DNS_FRESH_WINDOW = 75.0  # seconds a refreshed DNS name stays "active"


def _ros_ttl_to_seconds(text: str) -> int | None:
    """Parse RouterOS TTL like 2m28s / 1h / 30s into seconds."""
    if not text:
        return None
    total = 0
    parts = re.findall(r"(\d+)([smhdw]?)", text.strip().lower())
    if not parts:
        return None
    mult = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    for num, unit in parts:
        total += int(num) * mult.get(unit, 1)
    return total


def _parse_dns_cache_entries(out: str) -> list[tuple[str, int | None]]:
    """Return (name, ttl_seconds|None) from detail or table DNS cache print."""
    entries: list[tuple[str, int | None]] = []
    # detail: name=www.youtube.com ... ttl=2m28s
    for m in re.finditer(
        r"name=([^\s]+).*?ttl=([0-9smhdw]+)",
        out,
        flags=re.I | re.S,
    ):
        entries.append((m.group(1).lower().strip('"'), _ros_ttl_to_seconds(m.group(2))))
    if entries:
        return entries
    # table: "2 www.youtube.com  A  142…  2m28s" or without TTL
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("Flags") or ln.startswith("Columns") or ln.startswith("#"):
            continue
        m = re.match(
            r"^\d+\s+[A-Z]*\s*([a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)\b(.*)$",
            ln,
        ) or re.match(r"^\d+\s+([a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)\b(.*)$", ln)
        if not m:
            continue
        name = m.group(1).lower()
        rest = m.group(2)
        ttl_m = re.search(r"(\d+[smhdw](?:\d+[smhdw])*)\s*$", rest.strip(), flags=re.I)
        ttl = _ros_ttl_to_seconds(ttl_m.group(1)) if ttl_m else None
        entries.append((name, ttl))
    return entries


# Ephemeral video CDNs — if they are in cache, someone is watching
_VIDEO_CDN_ALWAYS = (
    "googlevideo", "ytimg", "ggpht", "youtu.be", "youtube-nocookie",
    "youtubei", "nflxvideo", "nflxso", "nflximg", "ttvnw",
    "akamaihd.net",
)


def mikrotik_dns_hints() -> tuple[str, ...]:
    """DNS names from MikroTik cache that were freshly queried (TTL bump / new).

    Leftover googlevideo still sitting in cache is not returned — host Auto
    must not show 'watching' from stale CDN entries on an idle stage.
    """
    global _DNS_SEEDED
    filt = (
        "youtube|googlevideo|ytimg|ggpht|youtu|youtubei|netflix|nflx|twitch|ttvnw|"
        "akamaihd|akamaized|tiktok|spotify|steam|riot|epicgames|hoyoverse|genshin|"
        "roblox|rbxcdn|zoom|skype|webex|teams.microsoft|meet.google|webrtc|stun|"
        "discord.media|windowsupdate|dropbox"
    )
    out = mikrotik_run(
        f'/ip dns cache print detail without-paging where name~"{filt}"'
    )
    entries = _parse_dns_cache_entries(out)
    try:
        devices.remember_video_cdn_ips(out)
        devices.resolve_video_cdn_names(tuple(n for n, _ in entries))
    except Exception:
        pass
    if len(entries) < 2:
        out = mikrotik_run("/ip dns cache print detail without-paging")
        entries = _parse_dns_cache_entries(out)[:250]
        try:
            devices.remember_video_cdn_ips(out)
            devices.resolve_video_cdn_names(tuple(n for n, _ in entries))
        except Exception:
            pass

    now = time.time()
    current: dict[str, int | None] = {}
    for name, ttl in entries:
        if name not in current or (ttl is not None and (current[name] is None or ttl > current[name])):
            current[name] = ttl

    if not _DNS_SEEDED:
        for name, ttl in current.items():
            _DNS_LAST_TTL[name] = ttl if ttl is not None else -1
        _DNS_SEEDED = True
        # Seed only. Leftover googlevideo in MikroTik cache is not "watching".
        # Active video still flips Auto via video-like rate or a later TTL bump.
        return ()

    for name, ttl in current.items():
        prev = _DNS_LAST_TTL.get(name)
        if prev is None:
            _DNS_FRESH_UNTIL[name] = now + _DNS_FRESH_WINDOW
        elif ttl is not None and prev >= 0 and ttl > prev + 5:
            _DNS_FRESH_UNTIL[name] = now + _DNS_FRESH_WINDOW
        if ttl is not None:
            _DNS_LAST_TTL[name] = ttl
        elif name not in _DNS_LAST_TTL:
            _DNS_LAST_TTL[name] = -1

    for name in list(_DNS_LAST_TTL):
        if name not in current:
            _DNS_LAST_TTL.pop(name, None)
            _DNS_FRESH_UNTIL.pop(name, None)

    fresh = [n for n, until in _DNS_FRESH_UNTIL.items() if until > now and n in current]
    seen: set[str] = set()
    ordered: list[str] = []
    for n in fresh:
        if n not in seen:
            seen.add(n)
            ordered.append(n)
    return tuple(ordered)


def mikrotik_dhcp_clients() -> list[str]:
    out = mikrotik_run("/ip dhcp-server lease print")
    addrs = re.findall(r"(\d+\.\d+\.\d+\.\d+)", out)
    return [a for a in addrs if a.startswith("192.168.50.")]


_RATE_HIST: deque[float] = deque(maxlen=5)
_DNS_BY_IP: dict[str, dict[str, float]] = {}
_DNS_BY_IP_TTL = 45.0
_DNS_LOG_TS = 0.0
_LAST_HOST_TICK = ""


def _parse_dns_query_logs(out: str) -> list[tuple[str, str]]:
    """(client_ip, hostname) from RouterOS dns log lines."""
    return devices.parse_dns_query_logs(out)


def refresh_dns_by_ip() -> None:
    """Pull recent per-client DNS queries if RouterOS is logging them."""
    global _DNS_LOG_TS
    now = time.time()
    if now - _DNS_LOG_TS < 2.5:
        return
    _DNS_LOG_TS = now
    try:
        out = mikrotik_run('/log print without-paging where topics~"dns"', timeout=4)
    except Exception:
        return
    lines = "\n".join((out or "").splitlines()[-80:])
    for ip, name in _parse_dns_query_logs(lines):
        bucket = _DNS_BY_IP.setdefault(ip, {})
        bucket[name] = now + _DNS_BY_IP_TTL
    for ip in list(_DNS_BY_IP):
        live = {n: exp for n, exp in _DNS_BY_IP[ip].items() if exp > now}
        if live:
            _DNS_BY_IP[ip] = live
        else:
            _DNS_BY_IP.pop(ip, None)


def mikrotik_dns_hints_for_ip(ip: str) -> tuple[str, ...]:
    """DNS names this LAN IP actually queried (empty if RouterOS has no per-IP log)."""
    if not ip or not ip.startswith("192.168.50."):
        return ()
    refresh_dns_by_ip()
    names = list(_DNS_BY_IP.get(ip, {}))
    return tuple(names)


def classify_activity() -> tuple[str, str]:
    """Host-wide guess from WAN/LAN rate + MikroTik DNS (not Ubuntu VPN UDP)."""
    local_mbps = sample_local_rx_mbps()
    wan_mbps = mikrotik_wan_rx_mbps()
    rate = max(local_mbps, wan_mbps or 0.0)
    try:
        # Per-IP samples look idle when traffic is hairpinned through a VPN.
        # Only force browsing when the house WAN is quiet too.
        if devices.lan_clients_all_idle() and rate < 0.22 and not devices.download_hold_active():
            return devices.apply_opened_bias_all("balanced", "idle / light use")
    except Exception:
        pass
    _RATE_HIST.append(rate)
    bulk_sustained = sum(1 for r in _RATE_HIST if r >= 6.0) >= 2

    try:
        dns = mikrotik_dns_hints()
    except Exception:
        dns = ()

    # Do NOT use sample_ss_udp_ratio() — that is Ubuntu's own WG/ZT sockets,
    # which look like "calls/gaming" while the PC is just watching video.
    quic_https = False
    cdn_ip_hint = ""
    try:
        quic_https, cdn_ip_hint = devices.lan_forwarded_video_signals()
    except Exception:
        pass
    guess, evidence = devices.classify_from_signals(
        rate,
        tuple(dns or ()),
        bulk_sustained=bulk_sustained,
        quic_https=quic_https,
        cdn_ip_hint=cdn_ip_hint,
    )
    # A file download on this PC is not a video just because the Mbps matches.
    # Leave a phone alone: this only applies when a PC reported no open video.
    totals = devices.pc_open_counts()
    no_video = totals is not None and int((totals or {}).get("streaming") or 0) == 0
    # A closed video must not stay on Video streaming. Rate alone is not a download.
    if no_video and guess == "streaming":
        guess = "balanced"
    return devices.apply_opened_bias_all(guess, evidence, file_transfer=False)


def _maybe_log_host_auto_tick(mode: str, evidence: str) -> None:
    global _LAST_HOST_TICK
    fp = f"{mode}|{evidence}"
    if fp == _LAST_HOST_TICK:
        return
    _LAST_HOST_TICK = fp
    log_event(f"TICK host mode={mode} {evidence}")


def _commit_host_opened() -> None:
    """Right now follows the Test slide as soon as a window report arrives."""
    global AUTO_DETECTED, AUTO_PENDING, AUTO_PENDING_HITS, AUTO_LAST_SWITCH
    if CURRENT_PROFILE != "auto":
        return
    forced = devices.opened_commit_mode()
    if not forced or forced == AUTO_DETECTED:
        return
    prev = AUTO_DETECTED
    AUTO_DETECTED = forced
    AUTO_PENDING = None
    AUTO_PENDING_HITS = 0
    AUTO_LAST_SWITCH = time.time()
    log_event(f"AUTO DETECT {prev} -> {forced}")


def update_auto_detection() -> bool:
    """Update AUTO_DETECTED with hysteresis. Returns True if mode changed."""
    global AUTO_DETECTED, AUTO_EVIDENCE, AUTO_PENDING, AUTO_PENDING_HITS, AUTO_LAST_SWITCH
    if CURRENT_PROFILE != "auto":
        return False

    guess, evidence = classify_activity()
    shown = evidence
    if guess != AUTO_DETECTED:
        shown = f"leaning {AUTO_LABELS.get(guess, guess)} · {evidence}"
    AUTO_EVIDENCE = shown
    _maybe_log_host_auto_tick(AUTO_DETECTED if guess == AUTO_DETECTED else guess, shown)

    if guess == AUTO_DETECTED:
        AUTO_PENDING = None
        AUTO_PENDING_HITS = 0
        return False

    if guess == AUTO_PENDING:
        AUTO_PENDING_HITS += 1
    else:
        AUTO_PENDING = guess
        AUTO_PENDING_HITS = 1

    if devices.opened_commit_mode() is not None and guess == devices.opened_commit_mode():
        need_hits, need_gap = 1, 0.0
    else:
        need_hits, need_gap = devices.auto_hysteresis_need(AUTO_DETECTED, guess, evidence)
    if AUTO_PENDING_HITS < need_hits:
        return False
    if time.time() - AUTO_LAST_SWITCH < need_gap:
        return False

    prev = AUTO_DETECTED
    AUTO_DETECTED = guess
    AUTO_EVIDENCE = evidence
    AUTO_PENDING = None
    AUTO_PENDING_HITS = 0
    AUTO_LAST_SWITCH = time.time()
    log_event(f"AUTO DETECT {prev} -> {guess} ({evidence})")
    _maybe_log_host_auto_tick(guess, evidence)
    return True


def apply_host_route(iface: str, regime_name: str, gateway: str | None = None) -> bool:
    """Record SAW handover. Never steal Ubuntu default or send 1.1.1.1 via table 200.

    Client tables 110+ handle LAN devices. Table 200 + `to 1.1.1.1` was leftover
    harm (1.1.1.1 followed WG while the host default stayed MikroTik).
    """
    if not GATEWAY_ENABLED:
        log_event(f"ROUTE SKIP {regime_name}: gateway off")
        return False

    # 10.66.x is the lab dummy overlay — never a default gateway.
    if gateway and str(gateway).startswith("10.66."):
        gateway = None

    use_tunnel = bool(iface) and iface_exists(iface) and devices.vpn_carries_internet(iface)
    via = iface if use_tunnel else "192.168.50.1"

    try:
        devices.drop_leftover_host_dns_policy()
    except Exception:
        for _ in range(8):
            if sudo_ip(["rule", "del", "to", "1.1.1.1", "table", "200"]).returncode != 0:
                break
    sudo_ip(["route", "flush", "table", "200"])

    log_event(
        f"HANDOVER -> {regime_name} via {via} "
        f"({'tunnel' if use_tunnel else 'MikroTik'} ok)"
    )
    return True


def clear_host_route() -> None:
    """Remove leftover demo policy routing. Ubuntu default stays MikroTik/enp0s8."""
    try:
        devices.drop_leftover_host_dns_policy()
    except Exception:
        for _ in range(8):
            if sudo_ip(["rule", "del", "to", "1.1.1.1", "table", "200"]).returncode != 0:
                break
    sudo_ip(["route", "flush", "table", "200"])
    log_event("GATEWAY OFF — policy routes cleared")


def container_running(name: str) -> bool:
    if name == "vpnserver":
        r = run(["pgrep", "-f", "vpnserver execsvc"], timeout=3)
        return r.returncode == 0
    if name == "strongswan":
        r = run(["ipsec", "status"], timeout=5)
        return "ESTABLISHED" in ((r.stdout or "") + (r.stderr or ""))
    r = run(["docker", "inspect", "-f", "{{.State.Running}}", name], timeout=5)
    return (r.stdout or "").strip().lower() == "true"


def build_status_payload(device_ip: str | None = None, user_id: int | None = None):
    eff = effective_profile()
    info = dict(PROFILE_INFO.get(CURRENT_PROFILE, PROFILE_INFO["balanced"]))
    if CURRENT_PROFILE == "auto":
        sub = PROFILE_INFO.get(AUTO_DETECTED, PROFILE_INFO["balanced"])
        info = {
            "blurb": f"Auto → {AUTO_LABELS.get(AUTO_DETECTED, AUTO_DETECTED)}. {AUTO_EVIDENCE}",
            "prefers": sub.get("prefers", []),
        }
    with ENGINE_LOCK:
        host_metrics = list(LATEST_METRICS)
        events = list(HANDOVER_LOG)
        switch_reason = LAST_SWITCH_REASON
    # Never hold ENGINE_LOCK across DEVICES_LOCK (list_devices) — that deadlocks Flask.
    switch_reasons = _collect_switch_reasons()
    sim_uid = user_id
    if device_ip:
        sim_uid = _owner_user_id_for_ip(device_ip) or user_id
    sim = simulated_status(sim_uid)
    payload = {
        "view": "host",
        "metrics": host_metrics,
        "active_path": next((m["name"] for m in host_metrics if m.get("is_active")), None),
        "profile": CURRENT_PROFILE,
        "effective_profile": eff,
        "profile_info": info,
        "gateway_enabled": (
            accounts_db.is_gateway_connected(user_id)
            if user_id is not None else GATEWAY_ENABLED
        ),
        "auto": {
            "detected": AUTO_DETECTED,
            "label": AUTO_LABELS.get(AUTO_DETECTED, AUTO_DETECTED),
            "evidence": AUTO_EVIDENCE,
            "active": CURRENT_PROFILE == "auto",
        },
        "devices": devices.list_devices(),
        "updated_at": time.time(),
        "events": filter_handover_lines(events, host_only=True),
        "switch_reason": switch_reason,
        "switch_reasons": switch_reasons,
        "device_ready": True,
        "simulated_down": sim["simulated_down"],
        "wireguard_healthy": sim["wireguard_healthy"],
        "fail_paths": sim["paths"],
        "saw": saw_status_payload(
            CURRENT_PROFILE,
            eff,
            CUSTOM_WEIGHTS if CURRENT_PROFILE == "custom" else None,
        ),
    }
    if device_ip:
        # Device view must never paint host pick / evidence / ranked list.
        payload["view"] = "device"
        payload["device_ip"] = device_ip
        payload["controlling"] = True
        dev = devices.get_device(device_ip)
        if not dev:
            payload["device"] = None
            payload["metrics"] = []
            payload["active_path"] = None
            payload["events"] = []
            payload["auto"] = {
                "detected": None, "label": None, "evidence": "device not on LAN", "active": False,
            }
            payload["device_ready"] = False
            payload.update(_qos_fields([], sim.get("simulated_down")))
            try:
                payload["remote"] = viewer_payload()
            except Exception:
                payload["remote"] = devices.classify_viewer("")
            return payload
        payload["device"] = dev
        payload["profile"] = dev["profile"]
        payload["effective_profile"] = dev["effective_profile"]
        payload["profile_info"] = dev.get("profile_info") or info
        payload["auto"] = dev.get("auto") or {
            "detected": None, "label": None, "evidence": "", "active": False,
        }
        rows = list(dev.get("metrics") or [])
        if not rows:
            try:
                rows = list(devices.ensure_device_scores(device_ip) or [])
                dev = devices.get_device(device_ip) or dev
                payload["device"] = dev
            except Exception:
                rows = []
        payload["metrics"] = rows
        payload["active_path"] = dev.get("active_name")
        payload["switch_reason"] = dev.get("switch_reason") or ""
        payload["device_ready"] = bool(payload["metrics"])
        payload["events"] = filter_handover_lines(
            events,
            device_ip=device_ip,
            device_name=dev.get("name"),
        )
        payload["saw"] = saw_status_payload(
            dev.get("profile") or "balanced",
            dev.get("effective_profile") or "balanced",
            dev.get("custom_weights"),
        )
    payload.update(_qos_fields(payload.get("metrics") or [], sim.get("simulated_down")))
    try:
        payload["remote"] = viewer_payload()
    except Exception:
        payload["remote"] = devices.classify_viewer("")
    return payload


def _collect_switch_reasons() -> list:
    """Newest-first SWITCH/STILL lines for the UI (host + each device)."""
    out = []
    if LAST_SWITCH_REASON:
        out.append({
            "who": "host",
            "device": "host",
            "text": LAST_SWITCH_REASON,
            "at": LAST_SWITCH_AT,
        })
    try:
        for d in devices.list_devices():
            text = d.get("switch_reason")
            if not text:
                continue
            out.append({
                "who": d.get("name") or d.get("ip"),
                "device": d.get("ip"),
                "text": text,
                "at": d.get("switch_reason_at") or 0,
            })
    except Exception:
        pass
    out.sort(key=lambda x: float(x.get("at") or 0), reverse=True)
    return out


def evaluate_once():
    """One SAW decision cycle under the current traffic profile.

    Live probe QoS (latency, jitter, loss, MOS) drives the 7-metric score
    when a probe succeeds. Characteristics are fallback only. Affinity is
    a small capped tie-breaker. Host and per-device share rank_regimes_live.
    """
    global CURRENT_ACTIVE, LATEST_METRICS
    eff = effective_profile()
    custom = CUSTOM_WEIGHTS if CURRENT_PROFILE == "custom" else None
    scores, rows = rank_regimes_live(eff, custom)

    if FORCE_LOCK and FORCE_LOCK in scores:
        best = FORCE_LOCK
    else:
        best = max(scores, key=scores.get) if scores else CURRENT_ACTIVE

    prev_name = REGIMES.get(CURRENT_ACTIVE, {}).get("name", CURRENT_ACTIVE)
    switched = False
    if best != CURRENT_ACTIVE and best in REGIMES:
        if GATEWAY_ENABLED:
            iface = resolve_iface(best, REGIMES[best])
            apply_host_route(iface, REGIMES[best]["name"])
        CURRENT_ACTIVE = best
        switched = True

    for row in rows:
        row["is_active"] = row["id"] == CURRENT_ACTIVE
    rows.sort(key=lambda r: r["score"], reverse=True)
    _emit_switch_reason(
        rows,
        profile_key=eff,
        custom_weights=custom,
        device="host",
        from_name=prev_name,
        to_id=best,
        auto=CURRENT_PROFILE == "auto",
        switched=switched,
    )
    _maybe_log_saw(rows, eff)

    with ENGINE_LOCK:
        LATEST_METRICS = rows
    return switched, best


_LAST_SAW_FP = ""


def _emit_switch_reason(
    rows: list,
    *,
    profile_key: str,
    custom_weights,
    device: str,
    from_name: str,
    to_id: str,
    auto: bool,
    switched: bool,
) -> str:
    """Log SWITCH on change; STILL at most every ~30s. Store for /api/status."""
    global LAST_SWITCH_REASON, LAST_SWITCH_AT, LAST_STILL_LOG
    weights = saw.resolve_weights(profile_key, PROFILES, custom_weights)
    reason = saw.explain_choice(
        rows,
        weights,
        profile_key=profile_key,
        device=device,
        from_name=from_name,
        to_id=to_id,
        auto=auto,
        still=not switched,
        labels=AUTO_LABELS,
    )
    now = time.time()
    if switched:
        log_event(reason)
        LAST_STILL_LOG = now
    elif now - LAST_STILL_LOG >= saw.STILL_LOG_INTERVAL:
        log_event(reason)
        LAST_STILL_LOG = now
    LAST_SWITCH_REASON = reason
    LAST_SWITCH_AT = now
    return reason


def _maybe_log_saw(rows: list, profile_key: str) -> None:
    """Emit live-vs-baseline numbers when the ranked list actually changes."""
    global _LAST_SAW_FP
    fp = "|".join(
        f"{r.get('id')}:{r.get('source')}:{r.get('score')}:{r.get('latency')}:{r.get('loss')}"
        for r in rows
    )
    if fp == _LAST_SAW_FP:
        return
    _LAST_SAW_FP = fp
    bits = [
        f"{r['name']}[{r.get('source','?')} lat={r.get('latency')} "
        f"loss={r.get('loss')} vsBase={r.get('char_latency')}]={r.get('score')}"
        for r in rows[:4]
    ]
    log_event(f"SAW {profile_key} " + " | ".join(bits))


# True only after a verified DHCP hijack to Ubuntu (.10).
UBUNTU_DHCP_OPTED_IN = False


def try_apply_gateway_on() -> bool:
    """Enable Gateway + DHCP .10 only when Ubuntu can forward. Else stay .1."""
    global GATEWAY_ENABLED, UBUNTU_DHCP_OPTED_IN
    try:
        devices.ensure_forwarding()
    except Exception as e:
        log_event(f"FORWARDING WARN: {e}")
    try:
        devices.ensure_mikrotik_lab()
    except Exception as e:
        log_event(f"DHCP DNS WARN: {e}")
    if not devices.forwarding_ready():
        current = None
        try:
            current = devices.get_mikrotik_dhcp_gateway()
        except Exception:
            current = None
        if current == "192.168.50.10":
            devices.revert_mikrotik_dhcp_gateway()
            log_event("DHCP reverted to 192.168.50.1: forwarding not proven (avoid blackhole)")
        else:
            log_event("Gateway want-on: forwarding not ready — DHCP stays 192.168.50.1")
        GATEWAY_ENABLED = False
        devices._ctx["GATEWAY_ENABLED"] = False
        UBUNTU_DHCP_OPTED_IN = False
        return False
    try:
        dhcp_ok = bool(devices.set_mikrotik_dhcp_gateway())
    except Exception as e:
        log_event(f"DHCP SET WARN: {e}")
        dhcp_ok = False
    if not dhcp_ok:
        try:
            devices.revert_mikrotik_dhcp_gateway()
        except Exception:
            pass
        GATEWAY_ENABLED = False
        devices._ctx["GATEWAY_ENABLED"] = False
        UBUNTU_DHCP_OPTED_IN = False
        log_event("DHCP .10 failed; staying on 192.168.50.1")
        return False
    GATEWAY_ENABLED = True
    devices._ctx["GATEWAY_ENABLED"] = True
    UBUNTU_DHCP_OPTED_IN = True
    log_event("DHCP gateway 192.168.50.10 (Gateway On, forwarding proven)")
    return True


_WATCHDOG_INTERVAL = 10.0
_FWD_FAIL_LIMIT = 3
_DHCP_REAPPLY_COOLDOWN = 45.0
_fwd_fail = 0
_last_watchdog = 0.0
_dhcp_reapply_after = 0.0


def _watchdog_revert_dhcp(reason: str) -> None:
    """Point DHCP at MikroTik .1 and stop using Ubuntu as LAN gateway."""
    global GATEWAY_ENABLED, UBUNTU_DHCP_OPTED_IN, _dhcp_reapply_after, _fwd_fail
    if "ipconfig /renew" not in reason:
        reason = (
            reason
            + " — Windows still needs ipconfig /renew; Ubuntu cannot renew Windows leases"
        )
    log_event(reason)
    try:
        devices.revert_mikrotik_dhcp_gateway()
    except Exception as e:
        log_event(f"DHCP REVERT WARN: {e}")
    GATEWAY_ENABLED = False
    devices._ctx["GATEWAY_ENABLED"] = False
    UBUNTU_DHCP_OPTED_IN = False
    clear_host_route()
    devices.clear_device_routes()
    _fwd_fail = 0
    _dhcp_reapply_after = time.time() + _DHCP_REAPPLY_COOLDOWN
    try:
        devices.trigger_crash_log(
            "dhcp-revert-.1 " + reason.split("WATCHDOG:", 1)[-1].strip()[:80],
            force=True,
        )
    except Exception as e:
        log_event(f"WATCHDOG crash-log WARN: {e}")


def defense_watchdog_tick() -> None:
    """Keep Ubuntu default via .1; pin dead VPN client tables; DHCP .1 only if enp0s8 dies.

    Ping 8.8.8.8 uses `ping -I enp0s8` (3 retries/tick). Crash-log or DHCP revert
    only after 3 consecutive ticks (~30s) AND forwarding_ready is false.
    Client VPN tables stay on a proven tunnel; a single wg0/tun0 ping -I blink
    does not pin table 110+ to .1. After a DHCP revert, wait _DHCP_REAPPLY_COOLDOWN
    before .10 again.
    """
    global GATEWAY_ENABLED, UBUNTU_DHCP_OPTED_IN, _fwd_fail, _last_watchdog
    try:
        devices.protect_host_default()
    except Exception as e:
        log_event(f"WATCHDOG ROUTE WARN: {e}")

    try:
        devices.guard_client_vpn_tables()
    except Exception as e:
        log_event(f"WATCHDOG CLIENT PATH WARN: {e}")

    now = time.time()
    if now - _last_watchdog < _WATCHDOG_INTERVAL:
        return
    _last_watchdog = now

    dhcp_gw = None
    try:
        dhcp_gw = devices.get_mikrotik_dhcp_gateway()
    except Exception:
        dhcp_gw = None

    if not GATEWAY_WANT_ON:
        _fwd_fail = 0
        if dhcp_gw and dhcp_gw != "192.168.50.1":
            _watchdog_revert_dhcp(f"WATCHDOG: Gateway Off — DHCP {dhcp_gw} -> 192.168.50.1")
        return

    wan_ok = False
    try:
        wan_ok = bool(devices.ping_wan_via_lan())
    except Exception as e:
        log_event(f"WATCHDOG WAN PING WARN: {e}")
        wan_ok = False

    if not wan_ok:
        _fwd_fail += 1
        log_event(
            f"WATCHDOG ping -I enp0s8 8.8.8.8 FAIL ({_fwd_fail}/{_FWD_FAIL_LIMIT})"
        )
        if _fwd_fail >= _FWD_FAIL_LIMIT and dhcp_gw == "192.168.50.10":
            ready = False
            try:
                ready = bool(devices.forwarding_ready())
            except Exception:
                ready = False
            if ready:
                log_event(
                    "WATCHDOG enp0s8 ping missed consecutive ticks but "
                    "forwarding_ready true — leave DHCP .10"
                )
                _fwd_fail = 0
            else:
                _watchdog_revert_dhcp(
                    "WATCHDOG: Ubuntu cannot ping 8.8.8.8 via enp0s8 and "
                    "forwarding is not ready — DHCP revert to 192.168.50.1"
                )
        return

    _fwd_fail = 0
    try:
        ready = bool(devices.forwarding_ready())
    except Exception as e:
        log_event(f"WATCHDOG FWD WARN: {e}")
        ready = False

    if not ready:
        log_event(
            "WATCHDOG forwarding_ready FAIL — leaving DHCP .10 "
            "(Ubuntu ping via enp0s8 works); client tables guarded"
        )
        try:
            devices.ensure_forwarding()
        except Exception:
            pass
        return

    if GATEWAY_ENABLED and dhcp_gw == "192.168.50.10":
        return
    if now < _dhcp_reapply_after:
        return
    if not GATEWAY_ENABLED or dhcp_gw != "192.168.50.10":
        try_apply_gateway_on()


def _download_watch() -> None:
    """Commit Big downloads as soon as the file transfer shows, not after the slow device pass."""
    global AUTO_DETECTED, AUTO_EVIDENCE, AUTO_PENDING, AUTO_PENDING_HITS, AUTO_LAST_SWITCH
    while True:
        time.sleep(2)
        if CURRENT_PROFILE != "auto":
            continue
        try:
            guess, evidence = classify_activity()
        except Exception:
            continue
        if guess == "downloads":
            if AUTO_DETECTED != "downloads":
                prev = AUTO_DETECTED
                AUTO_DETECTED = "downloads"
                AUTO_EVIDENCE = evidence
                AUTO_PENDING = None
                AUTO_PENDING_HITS = 0
                AUTO_LAST_SWITCH = time.time()
                log_event(f"AUTO DETECT {prev} -> downloads")
            devices.commit_reported_pcs("downloads")
        elif AUTO_DETECTED == "downloads":
            # The file has stopped. Do not wait on the slow device pass.
            prev = AUTO_DETECTED
            AUTO_DETECTED = guess if guess in AUTO_LABELS else "balanced"
            AUTO_EVIDENCE = evidence
            AUTO_PENDING = None
            AUTO_PENDING_HITS = 0
            AUTO_LAST_SWITCH = time.time()
            log_event(f"AUTO DETECT {prev} -> {AUTO_DETECTED}")
            devices.release_finished_downloads()
        elif (
            guess == "balanced"
            and AUTO_DETECTED == "streaming"
            and devices.pc_open_counts() is not None
            and int((devices.pc_open_counts() or {}).get("streaming") or 0) == 0
        ):
            prev = AUTO_DETECTED
            AUTO_DETECTED = "balanced"
            AUTO_EVIDENCE = evidence
            AUTO_PENDING = None
            AUTO_PENDING_HITS = 0
            AUTO_LAST_SWITCH = time.time()
            log_event(f"AUTO DETECT {prev} -> balanced")
            devices.commit_reported_pcs("balanced")


def engine_loop():
    global UBUNTU_DHCP_OPTED_IN, GATEWAY_ENABLED
    global AUTO_DETECTED, AUTO_EVIDENCE, AUTO_PENDING, AUTO_PENDING_HITS
    load_engine_state()
    log_event(
        f"Engine started (want_on={GATEWAY_WANT_ON} "
        f"profile={CURRENT_PROFILE})"
    )
    try:
        devices.ensure_forwarding()
        devices.ensure_mikrotik_lab()
        devices.sync_devices_from_leases()
        n_pins = devices.clear_all_force_regimes()
        if n_pins:
            log_event(f"AUTO: cleared {n_pins} forced VPN pin(s) so SAW can pick")
        if GATEWAY_WANT_ON:
            if not try_apply_gateway_on():
                log_event("Boot: Gateway stays Off until forwarding is proven")
        else:
            if devices.revert_mikrotik_dhcp_gateway():
                log_event("DHCP bootstrap: gateway 192.168.50.1 (Gateway Off)")
            GATEWAY_ENABLED = False
            devices._ctx["GATEWAY_ENABLED"] = False
            UBUNTU_DHCP_OPTED_IN = False
            clear_host_route()
            devices.clear_device_routes()
    except Exception as e:
        log_event(f"DEVICE BOOTSTRAP WARN: {e}")
    if CURRENT_PROFILE == "auto":
        try:
            guess, evidence = classify_activity()
            AUTO_DETECTED = guess
            AUTO_EVIDENCE = evidence
            AUTO_PENDING = None
            AUTO_PENDING_HITS = 0
            log_event(f"AUTO START -> {guess} ({evidence})")
        except Exception as e:
            log_event(f"AUTO START WARN: {e}")
    while True:
        try:
            defense_watchdog_tick()
            changed = update_auto_detection()
            refresh_score_snapshot()
            evaluate_once()
            devices.evaluate_all_devices()
            if changed:
                RECOMPUTE.set()
            if not GATEWAY_ENABLED:
                devices.clear_device_routes()
        except Exception as e:
            log_event(f"ENGINE ERROR: {e}")
        RECOMPUTE.wait(timeout=3)
        RECOMPUTE.clear()


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


def client_ip() -> str:
    """Peer IP from the TCP connection. Never trust X-Forwarded-For (spoofable).

    Do not conflate with selected device_ip (remote control).
    """
    return request.remote_addr or ""


def is_remote_viewer() -> bool:
    """ZeroTier hallway: overlay /24 peer or Host is Ubuntu ZT IP. Not X-Forwarded-For."""
    return devices.is_overlay_remote(client_ip(), request.host or "")


def viewer_payload() -> dict:
    info = devices.classify_viewer(client_ip())
    if is_remote_viewer():
        info["off_lan"] = True
        info["limited"] = True
        if info.get("via") in ("unknown", "lan", "hostonly", "lab", "local"):
            info["via"] = "zerotier"
        info["skip_login"] = True
        info["banner"] = REMOTE_BANNER
        return info
    info["skip_login"] = False
    info["banner"] = ""
    return info


def _remote_admin_user() -> dict:
    acct = accounts_db.get_first_admin()
    if acct:
        return {
            "id": acct["id"],
            "username": acct["username"],
            "role": "admin",
            "remote": True,
            "data_consent": bool(acct.get("data_consent")),
        }
    return {"id": 0, "username": "admin", "role": "admin", "remote": True, "data_consent": False}


def mark_viewer_online() -> None:
    """Browsing the UI from a lab or cloud-ZT IP is proof that device is alive."""
    rip = client_ip()
    try:
        if devices.is_zt_cloud_client(rip):
            devices.ensure_runtime_device(
                rip, name="Remote", evidence="ZeroTier UI",
                egress_reason="ZT remote — MikroTik until Gateway On",
            )
            return
        if not devices.is_lan_client(rip):
            return
        devices.ensure_runtime_device(
            rip, evidence="LAN UI",
            egress_reason="LAN UI — MikroTik until Gateway On",
        )
    except Exception:
        pass


def _resolve_bound_ip(
    ip: str | None, mac: str | None = None, viewer_ip: str | None = None,
) -> str | None:
    """Follow MAC / live LAN after DHCP shuffle. Never SSH MikroTik on the request path."""
    try:
        return devices.live_ip_for_binding(ip, mac, viewer_ip=viewer_ip)
    except Exception:
        return (ip or "").strip() or None


def _follow_bound_row(row: dict, viewer_ip: str | None = None) -> dict:
    """Keep sqlite ip/mac in sync with the live engine row."""
    live_ip = _resolve_bound_ip(row.get("ip"), row.get("mac"), viewer_ip=viewer_ip)
    if live_ip and devices.is_steerable_client(live_ip) and not devices.get_device(live_ip):
        try:
            devices.ensure_runtime_device(
                live_ip, name=row.get("name") or "", evidence="bound IP follow",
                egress_reason="bound IP follow", online=True, rename=False,
            )
        except Exception:
            pass
    live = devices.get_device(live_ip) if live_ip else None
    mac = (live or {}).get("mac") or row.get("mac")
    owner = accounts_db.get_user_id_for_ip(live_ip) if live_ip else None
    if owner is not None and int(owner) != int(row.get("user_id") or 0):
        return row
    if live_ip and (
        live_ip != row.get("ip") or (mac and mac != (row.get("mac") or ""))
    ):
        try:
            updated = accounts_db.update_user_device_addr(
                row["user_id"], row["id"], live_ip, mac,
            )
            if updated:
                row = updated
        except Exception:
            row = {**row, "ip": live_ip, "mac": mac or row.get("mac")}
    return row


def _user_may_control_ip(user: dict | None, ip: str) -> bool:
    """True only for an authenticated owner (or admin). No anonymous control."""
    if not ip or not user:
        return False
    if user.get("role") == "admin":
        return True
    owner = accounts_db.get_user_id_for_ip(ip)
    if owner is not None:
        return int(owner) == int(user["id"])
    for row in accounts_db.list_user_devices(user["id"]):
        if row.get("ip") == ip:
            return True
        resolved = _resolve_bound_ip(row.get("ip"), row.get("mac"))
        if resolved == ip:
            claimed = accounts_db.get_user_id_for_ip(resolved)
            if claimed is None or int(claimed) == int(user["id"]):
                return True
    return False


def _account_should_steer(ip: str) -> bool:
    """Only this device's own account, and only while that account is connected.

    An address with no account stays on the router. Another account turning
    the gateway on does not pull it into a tunnel.
    """
    owner = _owner_user_id_for_ip(ip)
    if owner is None:
        return False
    return bool(accounts_db.is_gateway_connected(owner))


def _owner_user_id_for_ip(ip: str) -> int | None:
    """Account that bound this LAN/overlay IP, if any."""
    if not ip:
        return None
    try:
        exact = accounts_db.get_user_id_for_ip(ip)
        if exact is not None:
            return exact
        for acct in accounts_db.list_accounts():
            uid = int(acct["id"])
            for row in accounts_db.list_user_devices(uid):
                if row.get("ip") == ip:
                    return uid
                resolved = _resolve_bound_ip(row.get("ip"), row.get("mac"))
                if resolved == ip:
                    claimed = accounts_db.get_user_id_for_ip(resolved)
                    if claimed is None or int(claimed) == uid:
                        return uid
    except Exception:
        return None
    return None


def _qos_fields(metrics: list, failed_ids=None) -> dict:
    """How many paths still count as live for this account.

    Fail/Restore drives the number. Simulated-down paths drop out of the
    live count; real tunnels stay up. Before the first SAW rows, treat
    every enabled path as live so the dashboard starts at 8 of 8.
    """
    failed = {str(x) for x in (failed_ids or []) if x}
    rows = metrics or []
    if rows:
        total = len(rows)
        down = 0
        for m in rows:
            rid = str(m.get("id") or "")
            if m.get("failed") or rid in failed:
                down += 1
    else:
        total = sum(1 for meta in REGIMES.values() if meta.get("enabled", True))
        down = len(failed)
    live_n = max(0, total - down)
    if total == 0:
        mode, label = "none", "No scores yet"
    elif down == 0:
        mode, label = "live", f"{live_n} of {total} paths live"
    elif live_n == 0:
        mode, label = "failed", f"0 of {total} paths live"
    else:
        mode, label = "mixed", f"{live_n} of {total} paths live"
    return {
        "qos_mode": mode,
        "qos_live_count": live_n,
        "qos_total": total,
        "qos_label": label,
    }


def _bearer_token() -> str | None:
    auth = request.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    data = request.get_json(force=True, silent=True) or {}
    return data.get("token") or request.args.get("token")


def current_user() -> dict | None:
    if is_remote_viewer():
        token_user = accounts_db.user_from_token(_bearer_token())
        if token_user and token_user.get("role") == "admin":
            return {**token_user, "remote": True}
        return _remote_admin_user()
    return accounts_db.user_from_token(_bearer_token())


def require_user():
    user = current_user()
    if not user:
        return None, (jsonify({"error": "login required"}), 401)
    return user, None


def require_admin():
    user, err = require_user()
    if err:
        return None, err
    if user.get("role") != "admin":
        return None, (jsonify({"error": "admin only"}), 403)
    return user, None


def _mac_for_ip(ip: str) -> str:
    try:
        with devices.DEVICES_LOCK:
            d = devices.DEVICES.get(ip)
            if d:
                return (d.get("mac") or "").upper()
    except Exception:
        pass
    return ""


@app.route("/api/session")
def session_probe():
    """Unauthenticated bootstrap. Overlay hallway skips login as Advanced admin."""
    mark_viewer_online()
    viewer = viewer_payload()
    if is_remote_viewer():
        admin = _remote_admin_user()
        token = ""
        existing = accounts_db.user_from_token(_bearer_token())
        if existing and existing.get("role") == "admin":
            token = _bearer_token() or ""
        return jsonify({
            "ok": True,
            "remote": True,
            "skip_login": True,
            "role": "admin",
            "username": admin.get("username") or "admin",
            "user_id": admin.get("id"),
            "token": token,
            "data_consent": bool(admin.get("data_consent")),
            "viewer": viewer,
            "banner": REMOTE_BANNER,
        })
    user = accounts_db.user_from_token(_bearer_token())
    return jsonify({
        "ok": True,
        "remote": False,
        "skip_login": False,
        "login_required": user is None,
        "role": (user or {}).get("role"),
        "username": (user or {}).get("username"),
        "user_id": (user or {}).get("id"),
        "data_consent": bool((user or {}).get("data_consent")),
        "viewer": viewer,
        "banner": "",
    })


@app.route("/api/login", methods=["POST"])
def login():
    if is_remote_viewer():
        admin = _remote_admin_user()
        return jsonify({
            "username": admin.get("username") or "admin",
            "role": "admin",
            "user_id": admin.get("id"),
            "token": "",
            "data_consent": bool(admin.get("data_consent")),
            "remote": True,
            "skip_login": True,
            "banner": REMOTE_BANNER,
        })
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    acct = accounts_db.authenticate(username, password)
    if not acct:
        return jsonify({"error": "invalid credentials"}), 401
    token = accounts_db.create_session(acct["id"])
    return jsonify({
        "username": acct["username"],
        "role": acct["role"],
        "user_id": acct["id"],
        "token": token,
        "data_consent": bool(acct.get("data_consent")),
    })


@app.route("/api/me")
def me():
    user, err = require_user()
    if err:
        return err
    remote = bool(user.get("remote") or is_remote_viewer())
    return jsonify({
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "remote": remote,
        "skip_login": remote,
        "data_consent": bool(user.get("data_consent")),
        "banner": REMOTE_BANNER if remote else "",
    })


@app.route("/api/signup", methods=["POST"])
def signup():
    if is_remote_viewer():
        return jsonify({"error": "sign up is for the lab LAN"}), 403
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if str(data.get("role") or "").lower() == "admin":
        return jsonify({"error": "cannot create admin accounts"}), 403
    bootstrap = not accounts_db.has_admin()
    try:
        acct = accounts_db.create_user(
            username,
            password,
            role="admin" if bootstrap else "user",
            allow_admin=bootstrap,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    token = accounts_db.create_session(acct["id"])
    return jsonify({
        "username": acct["username"],
        "role": acct["role"],
        "user_id": acct["id"],
        "token": token,
        "data_consent": False,
    }), 201


@app.route("/api/account", methods=["DELETE"])
def delete_own_account():
    user, err = require_user()
    if err:
        return err
    if is_remote_viewer():
        return jsonify({"error": "remote hallway cannot delete the lab admin"}), 403
    token = _bearer_token()
    try:
        accounts_db.delete_user(user["id"])
    except ValueError as e:
        return jsonify({"error": str(e)}), 409 if "last admin" in str(e) else 400
    accounts_db.delete_session(token)
    return jsonify({"status": "deleted"})


@app.route("/api/consent", methods=["POST"])
def record_data_consent():
    user, err = require_user()
    if err:
        return err
    data = request.get_json(force=True, silent=True) or {}
    if data.get("consent") is not True:
        return jsonify({"error": "consent checkbox required"}), 400
    uid = user.get("id") or 0
    if uid:
        acct = accounts_db.set_data_consent(uid, True)
        consented = bool(acct and acct.get("data_consent"))
    else:
        consented = True
    return jsonify({"ok": True, "data_consent": consented})


@app.route("/api/speed-test", methods=["POST"])
def api_speed_test():
    """Mbps on the Fast.com hop: LAN client → Ubuntu → live tunnel.

    Leftover dummy paths (SSTP / OpenConnect / Nebula / ZeroTier) stay canned.
    Live tunnels never fall back to a fake Mbps.
    """
    user, err = require_user()
    if err:
        return err
    data = request.get_json(force=True, silent=True) or {}
    dip = (data.get("device_ip") or "").strip() or client_ip()
    if dip:
        if user.get("role") != "admin" and not _user_may_control_ip(user, dip):
            return jsonify({"error": "device not yours"}), 403
        if not devices.get_device(dip) and devices.is_steerable_client(dip):
            devices.ensure_runtime_device(
                dip, name=devices.guess_name(dip, ""), evidence="speed test",
                egress_reason="speed test", online=False,
            )
    try:
        devices._sync_device_egress_from_fib(dip, "speed test")
    except Exception:
        pass
    d = devices.get_device(dip) or {}
    rid = d.get("active_regime") or FORCE_LOCK or CURRENT_ACTIVE
    live_tun = ""
    if (d.get("egress") or "") == "tunnel":
        live_tun = (d.get("egress_dev") or "").strip()
    meta = REGIMES.get(rid) or {}
    if not meta:
        return jsonify({"error": "no VPN in use"}), 400
    name = meta.get("name") or rid
    saw_iface = resolve_iface(rid, meta)
    if _path_fakes_speed(rid, saw_iface):
        time.sleep(random.uniform(1.2, 2.0))
        return jsonify({
            "ok": True,
            "id": rid,
            "name": name,
            "mbps": _fake_speed_mbps(rid),
            "iface": saw_iface or "",
            "source": "dummy",
        })
    iface = ""
    if devices.is_client_wan_iface(saw_iface):
        iface = saw_iface
    elif devices.is_client_wan_iface(live_tun):
        iface = live_tun
        for r, m in REGIMES.items():
            if resolve_iface(r, m) == iface:
                rid, meta, name = r, m, (m.get("name") or r)
                break
    if not iface:
        log_event(f"SPEED {name}: no live iface fib={live_tun!r} saw={saw_iface!r}")
        return jsonify({
            "error": f"Could not measure {name} on the client path.",
            "id": rid,
            "name": name,
            "iface": "",
        }), 502
    mbps = None
    try:
        mbps = devices.measure_lan_client_mbps(iface)
    except Exception as e:
        log_event(f"SPEED ERROR {name} {iface}: {e}")
        mbps = None
    if mbps is None:
        return jsonify({
            "error": f"Could not measure {name} on the client path.",
            "id": rid,
            "name": name,
            "iface": iface or "",
        }), 502
    return jsonify({
        "ok": True,
        "id": rid,
        "name": name,
        "mbps": mbps,
        "iface": iface or "",
        "source": "lan-client",
    })


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
def admin_delete_user(user_id: int):
    user, err = require_admin()
    if err:
        return err
    if user_id == user["id"]:
        return jsonify({"error": "use Delete account to remove your own login"}), 400
    try:
        accounts_db.delete_user(user_id)
    except ValueError as e:
        return jsonify({"error": str(e)}), 409 if "last admin" in str(e) else 400
    return jsonify({"status": "deleted"})


@app.route("/api/bugs", methods=["POST"])
def submit_bug():
    user, err = require_user()
    if err:
        return err
    data = request.get_json(force=True, silent=True) or {}
    try:
        bug = accounts_db.create_bug(
            user.get("username") or "unknown",
            data.get("title") or "",
            data.get("body") or data.get("description") or "",
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    log_event(f"BUG #{bug['id']} from {bug['user']}: {bug['title']}")
    return jsonify({"status": "ok", "bug": bug}), 201


@app.route("/api/admin/bugs")
def admin_list_bugs():
    user, err = require_admin()
    if err:
        return err
    bugs = accounts_db.list_bugs()
    new_count = sum(1 for b in bugs if b.get("status") == "new")
    return jsonify({"bugs": bugs, "new_count": new_count})


@app.route("/api/admin/bugs/<int:bug_id>", methods=["PATCH", "POST"])
def admin_update_bug(bug_id: int):
    user, err = require_admin()
    if err:
        return err
    data = request.get_json(force=True, silent=True) or {}
    try:
        bug = accounts_db.update_bug(
            bug_id,
            status=data.get("status"),
            note=data["note"] if "note" in data else None,
        )
    except ValueError as e:
        code = 404 if "not found" in str(e) else 400
        return jsonify({"error": str(e)}), code
    return jsonify({"status": "ok", "bug": bug})


@app.route("/api/logout", methods=["POST"])
def logout_api():
    accounts_db.delete_session(_bearer_token())
    return jsonify({"status": "ok"})


@app.route("/api/me/devices")
def my_devices():
    user, err = require_user()
    if err:
        return err
    mark_viewer_online()
    viewer = client_ip()
    rows = accounts_db.list_user_devices(user["id"])
    # Enrich with live engine status; follow DHCP/MAC instead of inserting a second row
    out = []
    for r in rows:
        r = _follow_bound_row(r, viewer_ip=viewer)
        live_ip = r.get("ip")
        live = devices.get_device(live_ip) if live_ip else None
        auto = (live or {}).get("auto") or {}
        out.append({
            **r,
            "ip": live_ip or r.get("ip"),
            "online": bool(live and live.get("online")),
            "active_name": (live or {}).get("active_name"),
            "profile": (live or {}).get("profile"),
            "effective_profile": (live or {}).get("effective_profile"),
            "effective_label": (live or {}).get("effective_label"),
            "auto": auto,
            "auto_detected": auto.get("detected") or (live or {}).get("auto_detected"),
            "evidence": (live or {}).get("evidence") or auto.get("evidence"),
            "egress": (live or {}).get("egress") or "mikrotik",
            "egress_via": (live or {}).get("egress_via"),
            "egress_dev": (live or {}).get("egress_dev"),
            "egress_reason": (live or {}).get("egress_reason") or "",
        })
    return jsonify({"devices": out})


@app.route("/api/me/devices", methods=["POST"])
def add_my_device():
    user, err = require_user()
    if err:
        return err
    if user.get("role") == "admin":
        return jsonify({"error": "admin uses the accounts panel; sign up a user account to bind devices"}), 400
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip() or "My device"
    ip = client_ip()
    if not devices.is_steerable_client(ip):
        return jsonify({
            "error": "connect from the lab LAN (192.168.50.x) or ZeroTier overlay (10.71.80.x, join cf719fd540b50c25) to bind this device",
            "client_ip": ip,
        }), 400
    if devices.is_zt_cloud_client(ip) and name in ("My device", "My PC"):
        name = "Remote"
    mac = ""
    try:
        live = devices.get_device(ip) or {}
        mac = (live.get("mac") or "").strip()
    except Exception:
        mac = ""
    # Skip MikroTik MAC lookup here — SSH can hang; engine will fill MAC later from leases.
    try:
        devices.ensure_runtime_device(
            ip, name=name, mac=mac, evidence="Bound from UI",
            egress_reason="bound from UI", rename=True,
        )
    except Exception as e:
        log_event(f"BIND DEVICE WARN: {e}")
    row = accounts_db.add_user_device(user["id"], name, ip, mac or None)
    log_event(f"BIND DEVICE user={user.get('username')} ip={ip} name={name}")
    return jsonify({"status": "ok", "device": row, "client_ip": ip}), 201


@app.route("/api/me/devices/<int:device_id>", methods=["DELETE"])
def delete_my_device(device_id: int):
    user, err = require_user()
    if err:
        return err
    if user.get("role") == "admin":
        return jsonify({"error": "admin uses the accounts panel to remove devices"}), 400
    row = accounts_db.delete_user_device(user["id"], device_id)
    if not row:
        return jsonify({"error": "device not on your account"}), 404
    log_event(
        f"UNBIND DEVICE user={user.get('username')} id={device_id} "
        f"ip={row.get('ip') or '-'} name={row.get('name') or ''}"
    )
    return jsonify({"status": "deleted", "device": row})


@app.route("/api/admin/accounts")
def admin_accounts():
    user, err = require_admin()
    if err:
        return err
    q = request.args.get("q") or ""
    return jsonify({"accounts": accounts_db.list_accounts(q)})


@app.route("/api/admin/accounts/<int:account_id>/devices")
def admin_account_devices(account_id: int):
    user, err = require_admin()
    if err:
        return err
    acct = accounts_db.get_account(account_id)
    if not acct:
        return jsonify({"error": "account not found"}), 404
    rows = accounts_db.list_user_devices(account_id)
    out = []
    for r in rows:
        r = _follow_bound_row(r, viewer_ip=client_ip())
        live = devices.get_device(r["ip"]) if r.get("ip") else None
        out.append({
            **r,
            "online": bool(live and live.get("online")),
            "active_name": (live or {}).get("active_name"),
            "effective_profile": (live or {}).get("effective_profile"),
            "effective_label": (live or {}).get("effective_label"),
            "evidence": (live or {}).get("evidence") or ((live or {}).get("auto") or {}).get("evidence"),
            "egress": (live or {}).get("egress") or "mikrotik",
            "egress_via": (live or {}).get("egress_via"),
            "egress_dev": (live or {}).get("egress_dev"),
            "egress_reason": (live or {}).get("egress_reason") or "",
        })
    return jsonify({"account": acct, "devices": out})


@app.route("/api/admin/accounts/<int:account_id>/devices/<int:device_id>", methods=["DELETE"])
def admin_delete_account_device(account_id: int, device_id: int):
    user, err = require_admin()
    if err:
        return err
    acct = accounts_db.get_account(account_id)
    if not acct:
        return jsonify({"error": "account not found"}), 404
    row = accounts_db.delete_user_device(account_id, device_id)
    if not row:
        return jsonify({"error": "device not on that account"}), 404
    log_event(
        f"UNBIND DEVICE admin={user.get('username')} account={acct.get('username')} "
        f"id={device_id} ip={row.get('ip') or '-'} name={row.get('name') or ''}"
    )
    return jsonify({"status": "deleted", "device": row})


@app.route("/api/opened", methods=["POST"])
def api_opened():
    """This PC reports open windows. Names stay off the public dashboard."""
    ip = client_ip()
    if not ip or not (ip.startswith("192.168.50.") or ip.startswith("127.")):
        return jsonify({"error": "lab LAN only"}), 403
    data = request.get_json(force=True, silent=True) or {}
    apps = data.get("apps") or []
    if not isinstance(apps, list):
        return jsonify({"error": "need apps"}), 400
    devices.note_opened(ip, apps)
    devices.commit_opened_device(ip)
    _commit_host_opened()
    RECOMPUTE.set()
    return jsonify({"ok": True})


def _commit_host_mode(mode: str) -> None:
    """Right now matches the Test slide without waiting for the engine."""
    global AUTO_DETECTED, AUTO_PENDING, AUTO_PENDING_HITS, AUTO_LAST_SWITCH
    if CURRENT_PROFILE != "auto" or mode not in AUTO_LABELS or mode == AUTO_DETECTED:
        return
    prev = AUTO_DETECTED
    AUTO_DETECTED = mode
    AUTO_PENDING = None
    AUTO_PENDING_HITS = 0
    AUTO_LAST_SWITCH = time.time()
    log_event(f"AUTO DETECT {prev} -> {mode}")


@app.route("/api/opened-probe")
def api_opened_probe():
    """Test-only view of this PC's open apps and the Auto mode they produce.

    Open apps decide the mode here. This does not scan MikroTik, so the
    dashboard can follow the Test slide immediately.
    """
    ip = client_ip()
    opened = devices.opened_for(ip) or {
        "age": None, "apps": [], "browsers": [], "video": False, "game": False,
    }
    mode = devices.opened_commit_for(ip) or devices.device_auto_mode(ip) or AUTO_DETECTED
    if devices.opened_commit_for(ip):
        devices.commit_detected(ip, mode)
        _commit_host_mode(mode)
    return jsonify({
        "ip": ip,
        "opened": opened,
        "mode": mode,
        "label": AUTO_LABELS.get(mode, mode),
        "evidence": "",
    })


@app.route("/api/status")
def status():
    """Status for a specific device when device_ip is set (remote control).

    Without device_ip, fall back to the viewing client's LAN IP if known.
    Login required — unauthenticated callers do not get the device list.
    """
    user, err = require_user()
    if err:
        return err
    asked = (request.args.get("device_ip") or "").strip() or None
    dip = asked
    mark_viewer_online()
    if dip:
        dip = _resolve_bound_ip(dip, _mac_for_ip(dip), viewer_ip=client_ip()) or dip
        rows = []
        try:
            if user.get("role") == "admin":
                for acct in accounts_db.list_accounts():
                    rows.extend(accounts_db.list_user_devices(acct["id"]))
            else:
                rows = accounts_db.list_user_devices(user["id"])
        except Exception:
            rows = []
        for row in rows:
            if row.get("ip") in (asked, dip):
                followed = _follow_bound_row(row, viewer_ip=client_ip())
                dip = followed.get("ip") or dip
                break
    if dip:
        if user.get("role") != "admin" and not _user_may_control_ip(user, dip):
            return jsonify({"error": "device not yours"}), 403
        if not devices.get_device(dip) and devices.is_steerable_client(dip):
            # Soft stub so UI can still show offline/selected device.
            # Do not sync leases or evaluate here — MikroTik / LAN-proof would wedge Flask.
            mac = _mac_for_ip(dip) if devices.is_lan_client(dip) else ""
            devices.ensure_runtime_device(
                dip, name=devices.guess_name(dip, mac), mac=mac,
                evidence="selected in UI", egress_reason="selected in UI",
                online=False,
            )
    else:
        rip = client_ip()
        if (
            devices.is_steerable_client(rip)
            and devices.get_device(rip)
            and (user.get("role") == "admin" or _user_may_control_ip(user, rip))
        ):
            dip = rip
    payload = build_status_payload(dip, user_id=user.get("id"))
    if user.get("role") != "admin":
        allowed = {
            (row.get("ip") or "")
            for row in accounts_db.list_user_devices(user["id"])
        }
        allowed.discard("")
        payload["devices"] = [
            d for d in (payload.get("devices") or [])
            if d.get("ip") in allowed
        ]
        # No device of this account is on screen. Do not show the lab-wide
        # mode, path list, or another account's devices.
        if not dip:
            payload["events"] = []
            payload["metrics"] = []
            payload["active_path"] = None
            payload["switch_reason"] = ""
            payload["auto"] = {
                "detected": "balanced",
                "label": "Everyday browsing",
                "evidence": "",
                "active": False,
            }
    return jsonify(payload)


@app.route("/api/devices")
def api_devices():
    user, err = require_admin()
    if err:
        return err
    devices.sync_devices_from_leases()
    return jsonify({"devices": devices.list_devices()})


@app.route("/api/devices/<ip>")
def api_device_detail(ip: str):
    user, err = require_user()
    if err:
        return err
    if not _user_may_control_ip(user, ip):
        return jsonify({"error": "device not yours"}), 403
    devices.sync_devices_from_leases()
    d = devices.get_device(ip)
    if not d:
        # Evaluate once in case lease just appeared
        devices.evaluate_all_devices()
        d = devices.get_device(ip)
    if not d:
        return jsonify({"error": "unknown device"}), 404
    return jsonify(d)


@app.route("/api/devices/<ip>/rename", methods=["POST"])
def api_device_rename(ip: str):
    user, err = require_user()
    if err:
        return err
    if not _user_may_control_ip(user, ip):
        return jsonify({"error": "device not yours"}), 403
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    d = devices.rename_device(ip, name)
    if not d:
        return jsonify({"error": "unknown device"}), 404
    return jsonify(d)


@app.route("/api/devices/<ip>/profile", methods=["POST"])
def api_device_profile(ip: str):
    user, err = require_user()
    if err:
        return err
    if not _user_may_control_ip(user, ip):
        return jsonify({"error": "device not yours"}), 403
    data = request.get_json(force=True, silent=True) or {}
    profile = data.get("profile") or "balanced"
    weights = data.get("weights")
    try:
        d = devices.set_device_profile(ip, profile, weights)
    except ValueError:
        return jsonify({"error": "unknown profile"}), 400
    if not d:
        return jsonify({"error": "unknown device"}), 404
    return jsonify({"status": "ok", "device": devices.get_device(ip)})


@app.route("/api/devices/<ip>/force", methods=["POST"])
def api_device_force(ip: str):
    user, err = require_admin()
    if err:
        return err
    data = request.get_json(force=True, silent=True) or {}
    regime = data.get("regime")
    if regime not in REGIMES:
        for rid, meta in REGIMES.items():
            if meta["name"] == regime:
                regime = rid
                break
    if regime not in REGIMES:
        if not regime or str(regime).lower() in ("none", "auto", "clear"):
            d = devices.set_device_force(ip, None)
            if not d:
                return jsonify({"error": "unknown device"}), 404
            return jsonify({"status": "unforced", "device": devices.get_device(ip)})
        return jsonify({"error": "unknown regime"}), 400
    d = devices.set_device_force(ip, regime)
    if not d:
        return jsonify({"error": "unknown device"}), 404
    return jsonify({"status": "forced", "device": devices.get_device(ip)})


_GW_JOB = threading.Lock()
_GW_GEN: dict[int, int] = {}


def _gw_bump(user_id: int) -> int:
    with _GW_JOB:
        n = _GW_GEN.get(user_id, 0) + 1
        _GW_GEN[user_id] = n
        return n


def _gw_live(user_id: int, gen: int) -> bool:
    with _GW_JOB:
        return _GW_GEN.get(user_id) == gen


def _finish_gateway_connect(user_id: int, username: str, gen: int) -> None:
    """DHCP and forwarding run after the toggle has already answered."""
    global GATEWAY_ENABLED, GATEWAY_WANT_ON, UBUNTU_DHCP_OPTED_IN
    if not _gw_live(user_id, gen):
        return
    try:
        devices.ensure_forwarding()
    except Exception as e:
        log_event(f"FORWARDING WARN: {e}")
    if not _gw_live(user_id, gen):
        return
    if not devices.forwarding_ready():
        accounts_db.set_gateway_connected(user_id, False)
        log_event(
            f"CONNECT refused for {username}: "
            "Ubuntu cannot reach internet yet — DHCP stays .1"
        )
        return
    dhcp_ok = False
    try:
        dhcp_ok = bool(devices.set_mikrotik_dhcp_gateway())
    except Exception as e:
        log_event(f"DHCP SET WARN: {e}")
    if not _gw_live(user_id, gen):
        return
    if not dhcp_ok:
        accounts_db.set_gateway_connected(user_id, False)
        log_event(f"CONNECT refused for {username}: DHCP stayed 192.168.50.1")
        return
    GATEWAY_WANT_ON = True
    GATEWAY_ENABLED = True
    devices._ctx["GATEWAY_ENABLED"] = True
    UBUNTU_DHCP_OPTED_IN = True
    persist_engine_state()
    log_event(f"CONNECT {username} to gateway")
    RECOMPUTE.set()


def _finish_gateway_disconnect(user_id: int, username: str, gen: int) -> None:
    """Point this account's devices back at MikroTik without blocking the page."""
    if not _gw_live(user_id, gen):
        return
    disconnected = 0
    for row in accounts_db.list_user_devices(user_id):
        if not _gw_live(user_id, gen):
            return
        ip = (row.get("ip") or "").strip()
        if not ip:
            continue
        try:
            if devices.revert_device_table(ip):
                disconnected += 1
        except Exception as e:
            log_event(f"DISCONNECT {ip} WARN: {e}")
    log_event(
        f"DISCONNECT {username} from gateway "
        f"({disconnected} device(s)) — other accounts unchanged"
    )
    RECOMPUTE.set()


@app.route("/api/gateway", methods=["POST"])
def set_gateway():
    global FORCE_LOCK
    user, err = require_user()
    if err:
        return err
    if is_remote_viewer():
        return jsonify({
            "error": "Gateway is lab Wi-Fi only.",
            "gateway_enabled": GATEWAY_ENABLED,
        }), 403
    data = request.get_json(force=True, silent=True) or {}
    enabled = data.get("enabled")
    if enabled is None:
        return jsonify({"error": "need enabled true/false"}), 400
    # Per account. The lab gateway stays up for everyone else.
    # The button returns now. Pings, DHCP, and route changes follow.
    user_id = int(user["id"])
    username = str(user.get("username") or user_id)
    accounts_db.set_gateway_connected(user_id, bool(enabled))
    FORCE_LOCK = None
    gen = _gw_bump(user_id)
    worker = _finish_gateway_connect if enabled else _finish_gateway_disconnect
    threading.Thread(
        target=worker, args=(user_id, username, gen), daemon=True,
    ).start()
    return jsonify({
        "status": "ok",
        "gateway_enabled": bool(enabled),
        "switched": False,
    })


@app.route("/api/set-weights", methods=["POST"])
def set_weights():
    global CUSTOM_WEIGHTS, CURRENT_PROFILE, FORCE_LOCK
    user, err = require_user()
    if err:
        return err
    data = request.get_json(force=True, silent=True) or {}
    weights = data.get("weights") or []
    if not isinstance(weights, list) or len(weights) < 7:
        return jsonify({"error": "need 7 weights"}), 400
    applied = [float(x) for x in weights[:7]]

    explicit = (data.get("device_ip") or "").strip() or None
    rip = explicit or client_ip()
    is_admin = user.get("role") == "admin"
    if not is_admin:
        if not _user_may_control_ip(user, rip):
            return jsonify({"error": "device not yours — add this device first"}), 403
    elif explicit and not _user_may_control_ip(user, rip):
        return jsonify({"error": "device not yours"}), 403

    target_device = bool(explicit) or (
        not is_admin and devices.is_steerable_client(rip)
    )
    if target_device:
        devices.sync_devices_from_leases()
        devices.set_device_profile(rip, "custom", custom_weights=applied)
        devices.evaluate_device(rip)
        payload = build_status_payload(rip)
        return jsonify({
            "status": "weights applied",
            "profile": "custom",
            "device_ip": rip,
            "view": "device",
            "qos_mode": payload.get("qos_mode"),
            "qos_label": payload.get("qos_label"),
            "active": payload.get("active_path"),
            "switched": True,
            "metrics": payload["metrics"],
            "device": devices.get_device(rip),
        })

    if not is_admin:
        return jsonify({"error": "device not yours — add this device first"}), 403
    CUSTOM_WEIGHTS = applied
    CURRENT_PROFILE = "custom"
    FORCE_LOCK = None
    RECOMPUTE.set()
    switched, best = evaluate_once()
    payload = build_status_payload()
    return jsonify({
        "status": "weights applied",
        "profile": "custom",
        "view": "host",
        "qos_mode": payload.get("qos_mode"),
        "qos_label": payload.get("qos_label"),
        "active": REGIMES.get(best, {}).get("name"),
        "switched": switched,
        "metrics": payload["metrics"],
    })


@app.route("/api/set-profile", methods=["POST"])
def set_profile():
    global CURRENT_PROFILE, FORCE_LOCK, AUTO_DETECTED, AUTO_PENDING, AUTO_PENDING_HITS, AUTO_EVIDENCE, AUTO_LAST_SWITCH
    user, err = require_user()
    if err:
        return err
    data = request.get_json(force=True, silent=True) or {}
    profile = data.get("profile") or "balanced"
    device_ip = (data.get("device_ip") or "").strip() or None
    allowed = set(PROFILES) | {"custom", "auto"}
    if profile not in allowed:
        return jsonify({"error": "unknown profile"}), 400

    rip = device_ip or client_ip()
    is_admin = user.get("role") == "admin"
    if not is_admin:
        if not _user_may_control_ip(user, rip):
            return jsonify({"error": "device not yours — add this device first"}), 403
    elif device_ip and not _user_may_control_ip(user, rip):
        return jsonify({"error": "device not yours"}), 403

    target_device = bool(device_ip) or (
        not is_admin and devices.is_steerable_client(rip)
    )
    if target_device:
        if not devices.get_device(rip):
            devices.ensure_runtime_device(
                rip, name=devices.guess_name(rip, ""),
                evidence="UI client", egress_reason="UI client",
            )
        d = devices.set_device_profile(rip, profile)
        payload = build_status_payload(rip)
        return jsonify({
            "status": "ok",
            "profile": profile,
            "device_ip": rip,
            "view": "device",
            "qos_mode": payload.get("qos_mode"),
            "qos_label": payload.get("qos_label"),
            "effective_profile": payload.get("effective_profile"),
            "profile_info": payload.get("profile_info"),
            "auto": payload.get("auto"),
            "active": (d or {}).get("active_name") if d else payload.get("active_path"),
            "switched": True,
            "metrics": payload["metrics"],
            "device": devices.get_device(rip),
        })

    if not is_admin:
        return jsonify({"error": "device not yours — add this device first"}), 403

    CURRENT_PROFILE = profile
    FORCE_LOCK = None
    if profile == "auto":
        AUTO_PENDING = None
        AUTO_PENDING_HITS = 0
        guess, evidence = classify_activity()
        AUTO_DETECTED = guess
        AUTO_EVIDENCE = evidence
        AUTO_LAST_SWITCH = time.time()
        log_event(f"AUTO START -> {guess} ({evidence})")
    persist_engine_state()
    log_event(f"PROFILE SET -> {profile}")
    RECOMPUTE.set()
    switched, best = evaluate_once()
    payload = build_status_payload()
    return jsonify({
        "status": "ok",
        "profile": profile,
        "view": "host",
        "qos_mode": payload.get("qos_mode"),
        "qos_label": payload.get("qos_label"),
        "effective_profile": payload.get("effective_profile"),
        "profile_info": payload.get("profile_info"),
        "auto": payload.get("auto"),
        "active": REGIMES.get(best, {}).get("name") if best else None,
        "switched": switched,
        "metrics": payload["metrics"],
    })


@app.route("/api/toggle-failure", methods=["POST"])
def toggle_failure():
    user, err = require_user()
    if err:
        return err
    global FORCE_LOCK
    data = request.get_json(force=True, silent=True) or {}
    rid = _resolve_regime_id(data.get("id") or data.get("regime") or data.get("name"))
    if not rid:
        rid = "my-wireguard"
    if rid not in REGIMES:
        return jsonify({"error": "unknown path"}), 400
    target_uid = int(user["id"])
    dip = (data.get("device_ip") or "").strip()
    if dip:
        owner = _owner_user_id_for_ip(dip)
        # Per-account simulation: never 403 the Fail buttons.
        # Admin on another user's device dashboard applies that owner's set.
        # Unknown or unbound IPs stay on the logged-in account.
        if owner is not None and (
            user.get("role") == "admin" or int(owner) == int(user["id"])
        ):
            target_uid = int(owner)
    current = fail_ids_for_user(target_uid)
    down = rid not in current
    if "failed" in data:
        down = bool(data.get("failed"))
    elif "simulated" in data or "down" in data:
        down = bool(data.get("simulated", data.get("down")))
    _set_simulated_for_user(target_uid, rid, down)
    FORCE_LOCK = None
    label = REGIMES[rid]["name"]
    log_event(f"FAILSIM user={target_uid} {label} simulated={'down' if down else 'up'}")
    RECOMPUTE.set()
    switched, best = evaluate_once()
    try:
        devices.evaluate_all_devices()
    except Exception:
        pass
    sim = simulated_status(target_uid)
    return jsonify({
        "status": "ok",
        "id": rid,
        "name": label,
        "simulated": down,
        "active": REGIMES.get(best, {}).get("name") if best else None,
        "switched": switched,
        **sim,
    })


@app.route("/api/isolate-path", methods=["POST"])
def isolate_path():
    """Fail every other VPN for this account so only the picked path stays up."""
    user, err = require_user()
    if err:
        return err
    global FORCE_LOCK
    data = request.get_json(force=True, silent=True) or {}
    rid = _resolve_regime_id(data.get("id") or data.get("regime") or data.get("name"))
    if not rid or rid not in REGIMES:
        return jsonify({"error": "unknown path"}), 400
    target_uid = int(user["id"])
    dip = (data.get("device_ip") or "").strip()
    if dip:
        owner = _owner_user_id_for_ip(dip)
        if owner is not None and (
            user.get("role") == "admin" or int(owner) == int(user["id"])
        ):
            target_uid = int(owner)
    others = {key for key in REGIMES if key != rid}
    _replace_simulated_for_user(target_uid, others)
    FORCE_LOCK = None
    label = REGIMES[rid]["name"]
    log_event(f"FAILSIM user={target_uid} isolate {label}")
    RECOMPUTE.set()
    sim = simulated_status(target_uid)
    return jsonify({
        "status": "ok",
        "id": rid,
        "name": label,
        "isolated": True,
        **sim,
    })


@app.route("/api/restore-paths", methods=["POST"])
def restore_paths():
    """Bring every simulated path back for this account. Other accounts stay put."""
    user, err = require_user()
    if err:
        return err
    global FORCE_LOCK
    data = request.get_json(force=True, silent=True) or {}
    target_uid = int(user["id"])
    dip = (data.get("device_ip") or "").strip()
    if dip:
        owner = _owner_user_id_for_ip(dip)
        if owner is not None and (
            user.get("role") == "admin" or int(owner) == int(user["id"])
        ):
            target_uid = int(owner)
    _replace_simulated_for_user(target_uid, set())
    FORCE_LOCK = None
    log_event(f"FAILSIM user={target_uid} restore all")
    RECOMPUTE.set()
    sim = simulated_status(target_uid)
    return jsonify({
        "status": "ok",
        "restored": True,
        **sim,
    })


def _iface_health(name: str) -> dict:
    """Honest iface snapshot: present / up / ipv4. Never invent UP."""
    if not name or not iface_exists(name):
        return {"name": name, "present": False, "up": False, "ipv4": None}
    r = run(["ip", "-br", "addr", "show", "dev", name], timeout=3)
    line = (r.stdout or "").strip()
    parts = line.split()
    state = parts[1] if len(parts) >= 2 else ""
    up = state in ("UP", "UNKNOWN")
    addrs = re.findall(r"(\d+\.\d+\.\d+\.\d+)", line)
    return {
        "name": name,
        "present": True,
        "up": up,
        "ipv4": addrs[0] if addrs else None,
        "state": state or None,
    }


def _proc_running(pattern: str) -> bool:
    r = run(["pgrep", "-f", pattern], timeout=3)
    return r.returncode == 0


def _unit_state(name: str) -> dict:
    active = (run(["systemctl", "is-active", name], timeout=3).stdout or "").strip()
    enabled = (run(["systemctl", "is-enabled", name], timeout=3).stdout or "").strip()
    return {"active": active == "active", "state": active or "missing", "enabled": enabled}


@app.route("/api/admin/health")
def admin_health():
    user, err = require_admin()
    if err:
        return err
    containers = []
    for rid, meta in REGIMES.items():
        iface = resolve_iface(rid, meta)
        running = container_running(meta["container"])
        if rid == "my-nebula" and not running:
            running = _proc_running("/nebula") or _proc_running("nebula -config")
        if rid == "my-openvpn" and not running:
            running = _proc_running("openvpn --config") or _proc_running("ovpn-lab-c")
        if rid == "my-ipsec" and not running:
            running = _proc_running("charon") or iface_exists("vti0")
        if rid == "my-sstp" and not running:
            running = _proc_running("sstpc ")
        if rid == "my-openconnect" and not running:
            running = _proc_running("openconnect")
        if rid == "my-softether" and not running:
            running = _proc_running("vpnclient") or _proc_running("vpnserver")
        iface_up = iface_exists(iface)
        # lo is not an IPsec tunnel — do not report it as the path being up
        if rid == "my-ipsec" and iface in ("", "lo"):
            iface_up = False
        dummy = False
        if iface_up:
            det = run(["ip", "-details", "link", "show", "dev", iface], timeout=3)
            dummy = "dummy" in ((det.stdout or "") + (det.stderr or "")).lower()
        carries = False
        if iface_up and not dummy and iface not in ("", "lo"):
            try:
                carries = bool(devices.vpn_carries_internet(iface))
            except Exception:
                carries = False
        kind = "dummy" if dummy else "tunnel"
        lan_ok, lan_why = False, "not probed"
        if iface_up and not dummy and iface not in ("", "lo"):
            cached = devices._LAN_PROOF_CACHE.get(iface)
            if cached:
                lan_ok, lan_why = bool(cached[1]), cached[2]
        containers.append({
            "id": rid,
            "name": meta["name"],
            "container": meta["container"],
            "kind": kind,
            "running": running,
            "iface": iface,
            "iface_up": iface_up,
            "ipv4": iface_has_ipv4(iface) if iface_up else False,
            "vpn_carries_internet": carries,
            "lan_forward_proven": lan_ok,
            "lan_proof_reason": lan_why,
            "dummy": dummy,
        })
    dhcp_gw = None
    try:
        dhcp_gw = devices.get_mikrotik_dhcp_gateway()
    except Exception:
        dhcp_gw = None
    mikrotik_ok = run(["ping", "-c", "1", "-W", "1", MIKROTIK_HOST], timeout=3).returncode == 0
    try:
        fwd_ready = bool(devices.forwarding_ready())
    except Exception:
        fwd_ready = False
    fwd = (run(["sysctl", "-n", "net.ipv4.ip_forward"], timeout=3).stdout or "").strip() == "1"
    extra = {n: _iface_health(n) for n in (
        "wg0", "tun0", "tap_soft", "vti0", "sstp0", "tun1", "nebula1",
    )}
    sstp_live = resolve_iface("my-sstp", REGIMES["my-sstp"])
    if sstp_live and sstp_live not in extra:
        extra[sstp_live] = _iface_health(sstp_live)
    zt_lab = devices.zerotier_lab_client_iface()
    if zt_lab:
        extra[zt_lab] = _iface_health(zt_lab)
    vm = {n: _iface_health(n) for n in ("enp0s3", "enp0s8", "enp0s9")}
    notes = [
        "SAW live QoS is ping 8.8.8.8 on that iface (cheap live speed/MTU, not iperf). Dummy 10.66 loops are not WAN.",
    ]
    if not vm["enp0s9"]["up"]:
        notes.append("enp0s9 (host-only 192.168.56.10) is down")
    if not vm["enp0s8"]["up"]:
        notes.append("enp0s8 (lab LAN 192.168.50.10) is down")
    if not mikrotik_ok:
        notes.append("MikroTik 192.168.50.1 is unreachable")
    if dhcp_gw == "192.168.50.10" and not fwd_ready:
        notes.append("BLACKHOLE: DHCP is .10 but forwarding is not ready — restore to .1")
    if not extra.get("wg0", {}).get("up"):
        notes.append("wg0 is down")
    if not extra.get("tun0", {}).get("up"):
        notes.append("tun0 (OpenVPN) is down")
    if not extra.get("sstp0", {}).get("up"):
        notes.append("sstp0 is down")
    if not extra.get("tun1", {}).get("up"):
        notes.append("tun1 (OpenConnect) is down")
    if not extra.get("nebula1", {}).get("up"):
        notes.append("nebula1 is down")
    sim = simulated_status(user.get("id"))
    failed = fail_ids_for_user(user.get("id"))
    if failed:
        names = [REGIMES[r]["name"] for r in sorted(failed) if r in REGIMES]
        notes.append(
            "Simulated down for this account: " + ", ".join(names) + " (SAW treats them as failed; ifaces stay up)."
        )
    by_id = {c["id"]: c for c in containers}
    neb = by_id.get("my-nebula") or {}
    if neb.get("iface_up") and not neb.get("vpn_carries_internet"):
        notes.append(
            "Nebula leftover: overlay to lighthouse works; unsafe_routes does not "
            "carry 8.8.8.8 (overlay-only, not a fake WAN)."
        )
    sstp = by_id.get("my-sstp") or {}
    if sstp.get("dummy") or (
        sstp.get("iface_up") and not sstp.get("vpn_carries_internet")
    ):
        notes.append(
            "SSTP leftover: no PPP to SoftEther :443 — dummy/baseline, never WAN."
        )
    zt = by_id.get("my-zerotier") or {}
    if zt.get("vpn_carries_internet"):
        notes.append(
            "ZeroTier exit is lab-local (second identity in netns + MASQUERADE out enp0s8); "
            "not a Central 0.0.0.0/0 and not a dummy WAN."
        )
    elif zt.get("iface_up"):
        notes.append("ZeroTier leftover: no lab-local exit — overlay only, not a fake WAN.")
    notes.append(
        "Off-LAN: join ZeroTier cf719fd540b50c25 (allowDefault=0). "
        "SAW may swap a lab VPN after ZT (fwmark/tables 112+). "
        "remote-limit: UI :5006 + ~4 Mbit hashlimit; drop 192.168.50.0/24 except .10. "
        "Not Central 0.0.0.0/0, not eight WAN ports."
    )
    se = by_id.get("my-softether") or {}
    if se.get("iface_up") and se.get("vpn_carries_internet") and not se.get("lan_forward_proven"):
        notes.append(
            "SoftEther: ping -I tap_soft works but LAN FORWARD+NAT not proven yet."
        )
    stolen = run(["ip", "route", "show", "8.8.8.8"], timeout=3)
    if "10.0.2.2" in ((stolen.stdout or "") + (stolen.stderr or "")):
        notes.append("STOLEN: 8.8.8.8 via 10.0.2.2 (VBox NAT) — should have been dropped.")
    core_ok = bool(vm["enp0s8"]["up"] and mikrotik_ok and fwd)
    return jsonify({
        "ok": core_ok and not (dhcp_gw == "192.168.50.10" and not fwd_ready),
        "containers": containers,
        "active": CURRENT_ACTIVE,
        "profile": CURRENT_PROFILE,
        "gateway_enabled": GATEWAY_ENABLED,
        "gateway_want_on": GATEWAY_WANT_ON,
        "wireguard_healthy": sim["wireguard_healthy"],
        "simulated_down": sim["simulated_down"],
        "fail_paths": sim["paths"],
        "devices": devices.list_devices(),
        "lab": {
            "forwarding": fwd,
            "forwarding_ready": fwd_ready,
            "mikrotik_reachable": mikrotik_ok,
            "mikrotik_host": MIKROTIK_HOST,
            "dhcp_gateway": dhcp_gw,
            "ifaces": {**vm, **extra},
            "services": {
                "adaptive-gateway": _unit_state("adaptive-gateway.service"),
                "extra-ifaces": _unit_state("autovpn-extra-ifaces.service"),
                "lan-forward": _unit_state("autovpn-lan-forward.service"),
                "watchdog": _unit_state("autovpn-watchdog.timer"),
            },
            "processes": {
                "vpnserver": _proc_running("vpnserver execsvc"),
                "nebula": _proc_running("/nebula"),
                "openvpn": _proc_running("openvpn --config"),
                "zerotier": _proc_running("zerotier-one"),
            },
            "notes": notes,
        },
    })


@app.route("/api/admin/logs")
def admin_logs():
    user, err = require_admin()
    if err:
        return err
    return jsonify({"lines": list(HANDOVER_LOG)})


@app.route("/api/events")
def api_events():
    """Live engine log for this session. Device view is this client only."""
    user, err = require_user()
    if err:
        return err
    asked = (request.args.get("device_ip") or "").strip() or None
    lines = list(HANDOVER_LOG)
    if asked:
        dev = devices.get_device(asked) or {}
        return jsonify({
            "lines": filter_handover_lines(
                lines, device_ip=asked, device_name=dev.get("name"),
            )
        })
    return jsonify({"lines": filter_handover_lines(lines, host_only=True)})


@app.route("/api/admin/force", methods=["POST"])
def admin_force():
    user, err = require_admin()
    if err:
        return err
    global FORCE_LOCK, CURRENT_ACTIVE
    data = request.get_json(force=True, silent=True) or {}
    regime = data.get("regime")
    if regime not in REGIMES:
        for rid, meta in REGIMES.items():
            if meta["name"] == regime:
                regime = rid
                break
    if regime not in REGIMES:
        return jsonify({"error": "unknown regime"}), 400
    FORCE_LOCK = regime
    iface = resolve_iface(regime, REGIMES[regime])
    apply_host_route(iface, REGIMES[regime]["name"])
    CURRENT_ACTIVE = regime
    log_event(f"ADMIN FORCE -> {REGIMES[regime]['name']}")
    RECOMPUTE.set()
    evaluate_once()
    return jsonify({"status": "forced", "regime": regime})


def _bind_device_manager():
    devices.bind_context(
        log_event=log_event,
        run=run,
        sudo_ip=sudo_ip,
        mikrotik_run=mikrotik_run,
        resolve_iface=resolve_iface,
        iface_exists=iface_exists,
        calculate_saw_for=calculate_saw_for,
        ping_metrics=cached_ping_metrics,
        rank_regimes_live=rank_regimes_live,
        REGIMES=REGIMES,
        PROFILE_AFFINITY=PROFILE_AFFINITY,
        CHARACTERISTICS=CHARACTERISTICS,
        PROFILES=PROFILES,
        PROFILE_INFO=PROFILE_INFO,
        AUTO_LABELS=AUTO_LABELS,
        STREAMING_DNS=STREAMING_DNS,
        GAMING_DNS=GAMING_DNS,
        CALL_DNS=CALL_DNS,
        DOWNLOAD_DNS=DOWNLOAD_DNS,
        mikrotik_dns_hints=mikrotik_dns_hints,
        mikrotik_dns_hints_for_ip=mikrotik_dns_hints_for_ip,
        mikrotik_wan_rx_mbps=mikrotik_wan_rx_mbps,
        sample_local_rx_mbps=sample_local_rx_mbps,
        SUDO=SUDO,
        SUDO_PASS=SUDO_PASS,
        WIREGUARD_HEALTHY=lambda: True,
        fail_ids_for_ip=fail_ids_for_ip,
        is_gateway_enabled=lambda: GATEWAY_ENABLED,
        device_should_steer=_account_should_steer,
    )
    devices._ctx["GATEWAY_ENABLED"] = GATEWAY_ENABLED


if __name__ == "__main__":
    _bind_device_manager()
    threading.Thread(target=engine_loop, daemon=True).start()
    threading.Thread(target=_download_watch, daemon=True).start()
    app.run(host="0.0.0.0", port=5006, use_reloader=False, threaded=True)
