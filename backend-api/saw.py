"""Live-first SAW scoring shared by host and per-device evaluate.

When a probe succeeds, latency / jitter / loss / MOS enter the 7-metric
formula. Protocol characteristics are fallback only (iface down or probe
fail). Affinity is a small capped tie-breaker so a worse live tunnel
cannot beat a clearly better live tunnel.
"""
from __future__ import annotations

# Raw PROFILE_AFFINITY values are 0.1–3.5 (legacy personality boosts).
# After scale+cap the max add-on is AFFINITY_CAP — smaller than a clear
# live QoS gap (e.g. 20ms vs 80ms on the gaming profile).
AFFINITY_SCALE = 0.02
AFFINITY_CAP = 0.08

# Lab dummy pings are often <1ms. Floor inverse terms so 10/lat does not
# explode and drown the other six metrics / profile weights.
LIVE_LAT_FLOOR_MS = 10.0
LIVE_JIT_FLOOR_MS = 3.0

DEFAULT_CHAR = (80.0, 10.0, 1.0, 70.0, 1.0, 3.5, 1400.0)
FAILED_METRICS = (999.0, 100.0, 100.0, 0.1, 100.0, 1.0, 1280.0)


def normalize_weights(weights) -> list[float]:
    w = [float(x) for x in (weights or [])]
    while len(w) < 7:
        w.append(0.0)
    w = w[:7]
    total = sum(w) or 1.0
    return [x / total for x in w]


def resolve_weights(profile_key: str, profiles: dict, custom_weights=None) -> list[float]:
    if profile_key == "custom" and custom_weights:
        return normalize_weights(custom_weights)
    return normalize_weights(profiles.get(profile_key) or profiles.get("balanced") or [1] * 7)


def blend_live_and_char(live, char) -> tuple:
    """Live QoS + cheap live speed/MTU. Characteristic if those probes omitted.

    Throughput is the ping-derived estimate already in live[3]
    (max(100-2*loss, 0.1)) — never iperf. MTU is a DF ping around 1400
    (live[6] >= 1200); else the protocol table value.
    """
    lat, jit, loss, thr, reorder, mos, mtu = (float(x) for x in live)
    c_thr = float(char[3])
    c_mtu = float(char[6])
    if thr <= 0.0:
        thr = c_thr
    if mtu < 1200.0:
        mtu = c_mtu
    return (lat, jit, loss, thr, reorder, mos, mtu)


def prepare_metrics(metrics, source: str) -> tuple:
    """Values that enter SAW. Live sub-ms pings saturate at 'excellent'."""
    lat, jit, loss, thr, reorder, mos, mtu = (float(x) for x in metrics)
    if source == "live":
        lat = max(lat, LIVE_LAT_FLOOR_MS)
        jit = max(jit, LIVE_JIT_FLOOR_MS)
    return (lat, jit, loss, thr, reorder, mos, mtu)


METRIC_NAMES = (
    "Latency", "Jitter", "Loss", "Throughput", "Reorder", "MOS", "MTU",
)


def normalized_terms(metrics) -> list[float]:
    lat, jit, loss, thr, reorder, mos, mtu = (float(x) for x in metrics)
    return [
        10.0 / max(lat, 0.1),
        5.0 / max(jit, 0.01),
        (100.0 - loss) / 100.0,
        thr / 100.0,
        (100.0 - reorder) / 100.0,
        mos / 5.0,
        mtu / 1500.0,
    ]


def calculate_saw_core(metrics, sec: float, rel: float, weights) -> float:
    w = normalize_weights(weights)
    n = normalized_terms(metrics)
    score = sum(n[i] * w[i] for i in range(7))
    score += (float(sec) / 5.0) * 0.03 + (float(rel) / 5.0) * 0.03
    return score


def affinity_bonus(raw: float) -> float:
    return min(max(float(raw), 0.0) * AFFINITY_SCALE, AFFINITY_CAP)


def score_one(
    *,
    metrics,
    sec: float,
    rel: float,
    weights,
    raw_affinity: float,
    source: str,
    failed: bool = False,
) -> dict:
    src = "live" if source == "live" else "baseline"
    used = prepare_metrics(metrics, src)
    w = normalize_weights(weights)
    n = normalized_terms(used)
    contrib = [n[i] * w[i] for i in range(7)]
    base = calculate_saw_core(used, sec, rel, w)
    aff = affinity_bonus(raw_affinity)
    score = base + aff
    if failed:
        score *= 0.05
    raw = tuple(float(x) for x in metrics)
    return {
        "score": score,
        "base": base,
        "affinity": aff,
        "source": src,
        "failed": failed,
        "weights": w,
        "terms": n,
        "contrib": contrib,
        "used_latency": used[0],
        "used_jitter": used[1],
        "used_loss": used[2],
        "used_mos": used[5],
        "sample_latency": raw[0],
        "sample_jitter": raw[1],
        "sample_loss": raw[2],
        "sample_mos": raw[5],
    }


def rank_regimes(
    *,
    regimes: dict,
    characteristics: dict,
    affinity_map: dict,
    profiles: dict,
    profile_key: str,
    custom_weights=None,
    samples: dict | None = None,
    wg_healthy: bool = True,
    failed_ids: set | None = None,
) -> tuple[dict, list]:
    """Score every enabled regime. Host and per-device must call this.

    samples[rid] = {metrics, live, failed, display_iface}
    """
    samples = samples or {}
    failed_ids = set(failed_ids or ())
    weights = resolve_weights(profile_key, profiles, custom_weights)
    affinity = affinity_map.get(profile_key) or affinity_map.get("balanced") or {}
    if profile_key == "custom":
        affinity = affinity_map.get("custom") or affinity

    scores: dict[str, float] = {}
    rows: list[dict] = []
    for rid, meta in regimes.items():
        if not meta.get("enabled", True):
            continue
        char = characteristics.get(rid, DEFAULT_CHAR)
        sample = samples.get(rid) or {}
        failed = bool(sample.get("failed")) or rid in failed_ids
        if rid == "my-wireguard" and not wg_healthy:
            failed = True
        live = bool(sample.get("live")) and not failed and sample.get("metrics")
        live_thr = False
        live_mtu = False
        if failed:
            used_metrics = FAILED_METRICS
            display = FAILED_METRICS
            source = "baseline"
            score_source = "baseline"
        elif live:
            raw = sample["metrics"]
            used_metrics = blend_live_and_char(raw, char)
            display = used_metrics
            source = "live"
            score_source = "live"
            try:
                live_thr = float(raw[3]) > 0.0
                live_mtu = float(raw[6]) >= 1200.0
            except (TypeError, ValueError, IndexError):
                live_thr, live_mtu = False, False
        else:
            # Dummy / leftover tunnels cannot ping 8.8.8.8. Score from the
            # characteristic table, but label them live so the dashboard does
            # not show baseline next to the four WAN paths.
            used_metrics = char
            display = char
            source = "live"
            score_source = "baseline"

        result = score_one(
            metrics=used_metrics,
            sec=float(meta.get("sec", 3.0)),
            rel=float(meta.get("rel", 3.0)),
            weights=weights,
            raw_affinity=float(affinity.get(rid, 0.0)),
            source=score_source,
            failed=failed,
        )
        scores[rid] = result["score"]
        lat, jit, loss, thr, reorder, mos, mtu = (float(x) for x in display)
        rows.append({
            "id": rid,
            "name": meta["name"],
            "iface": sample.get("display_iface") or meta.get("iface") or "",
            "score": round(result["score"], 4),
            "base": round(result["base"], 4),
            "live_bonus": 0.0,
            "latency": round(lat, 2),
            "jitter": round(jit, 2),
            "mos": round(mos, 1),
            "loss": round(loss, 1),
            "throughput": round(thr, 1),
            "reorder": round(reorder, 1),
            "mtu": round(mtu, 0),
            "live": source == "live",
            "source": source,
            "affinity": round(result["affinity"], 4),
            "used_latency": round(result["used_latency"], 2),
            "used_jitter": round(result["used_jitter"], 2),
            "used_loss": round(result["used_loss"], 1),
            "used_mos": round(result["used_mos"], 1),
            "char_latency": round(float(char[0]), 2),
            "char_jitter": round(float(char[1]), 2),
            "char_loss": round(float(char[2]), 1),
            "char_mos": round(float(char[5]), 1),
            "char_throughput": round(float(char[3]), 1),
            "char_mtu": round(float(char[6]), 0),
            "throughput_live": live_thr,
            "mtu_live": live_mtu,
            "failed": failed,
            "is_active": False,
            "weights": [round(x, 4) for x in result["weights"]],
            "contrib": [round(x, 4) for x in result["contrib"]],
        })
    return scores, rows


# Display-only. Does not change SAW, affinity, or routing.
STILL_LOG_INTERVAL = 30.0

METRIC_META = (
    {"key": "latency", "label": "Latency", "unit": "ms", "lower_better": True, "live": True},
    {"key": "jitter", "label": "Jitter", "unit": "ms", "lower_better": True, "live": True},
    {"key": "loss", "label": "Loss", "unit": "%", "lower_better": True, "live": True},
    {"key": "throughput", "label": "Throughput", "unit": "", "lower_better": False, "live": True},
    {"key": "reorder", "label": "Reorder", "unit": "%", "lower_better": True, "live": False},
    {"key": "mos", "label": "MOS", "unit": "", "lower_better": False, "live": True},
    {"key": "mtu", "label": "MTU", "unit": "", "lower_better": False, "live": True},
)

DEFAULT_PROFILE_LABELS = {
    "balanced": "Everyday browsing",
    "gaming": "Gaming & calls",
    "streaming": "Video streaming",
    "downloads": "Big downloads",
    "custom": "Custom",
}

VPN_SHORT = {
    "WireGuard": "WG",
    "IKEv2/IPsec": "IPsec",
    "OpenVPN": "OpenVPN",
    "SoftEther": "SoftEther",
    "ZeroTier": "ZT",
    "SSTP": "SSTP",
    "OpenConnect": "OpenConnect",
    "Nebula": "Nebula",
}

WEIGHT_NAME = {
    "streaming": "streaming",
    "gaming": "gaming",
    "downloads": "downloads",
    "balanced": "balanced",
    "custom": "custom",
}


def math_payload(
    profile_key: str,
    weights,
    *,
    auto: bool = False,
    labels: dict | None = None,
    prefers: list | None = None,
) -> dict:
    """Display-only: what this mode prioritizes and how SAW is computed."""
    w = normalize_weights(weights)
    names = dict(DEFAULT_PROFILE_LABELS)
    if labels:
        names.update(labels)
    parts = [
        {"name": METRIC_NAMES[i], "pct": int(round(w[i] * 100))}
        for i in range(7)
    ]
    ranked = sorted(parts, key=lambda p: (-p["pct"], p["name"]))
    return {
        "key": profile_key,
        "label": names.get(profile_key, profile_key),
        "auto": bool(auto),
        "parts": parts,
        "ranked": ranked,
        "prefers": list(prefers or []),
        "formula": "score = sum(n x w) + affinity",
        "n": [
            "Latency 10/ms",
            "Jitter 5/ms",
            "Loss (100-loss%)/100",
            "Throughput /100",
            "Reorder (100-re%)/100",
            "MOS /5",
            "MTU /1500",
        ],
    }


def _fmt_metric(meta: dict, value) -> str:
    if value is None:
        return "?"
    try:
        num = float(value)
    except (TypeError, ValueError):
        return "?"
    key = meta["key"]
    if key in ("latency", "jitter"):
        return f"{num:.0f}ms"
    if key == "loss":
        return f"{num:.0f}%" if num >= 1 or num == 0 else f"{num:.1f}%"
    if key == "mos":
        return f"{num:.1f}"
    if key in ("mtu", "throughput"):
        return f"{num:.0f}"
    unit = meta.get("unit") or ""
    return f"{num:.1f}{unit}"


def _src_word(row: dict, meta: dict) -> str:
    key = meta.get("key")
    if key == "throughput":
        return "live" if row.get("throughput_live") else "table"
    if key == "mtu":
        return "live" if row.get("mtu_live") else "table"
    if row.get("source") == "live" and meta.get("live"):
        return "live"
    return "table"


def _cheap_live_phrase(row: dict) -> str:
    speed = "cheap live speed" if row.get("throughput_live") else "table speed"
    mtu = "DF-1400 MTU" if row.get("mtu_live") else "table MTU"
    return f"LIVE loss/lat/jitter/MOS + {speed} + {mtu}"


def _used_data_phrase(winner: dict, loser: dict | None = None) -> str:
    wsrc = winner.get("source")
    lsrc = (loser or {}).get("source")
    if wsrc == "live" and (not loser or lsrc == "live"):
        return f"used {_cheap_live_phrase(winner)}"
    if wsrc == "live" and lsrc == "baseline":
        return (
            f"used LIVE on {winner.get('name')} vs table baseline on "
            f"{loser.get('name')}"
        )
    if wsrc == "baseline" and lsrc == "live":
        return (
            f"used table baseline on {winner.get('name')} vs LIVE on "
            f"{loser.get('name')}"
        )
    return "used table baseline (no live probe)"


def _metric_edge(winner: dict, loser: dict, idx: int) -> tuple[float, str]:
    meta = METRIC_META[idx]
    wv = winner.get(meta["key"])
    lv = loser.get(meta["key"])
    wsrc = _src_word(winner, meta)
    lsrc = _src_word(loser, meta)
    lshort = VPN_SHORT.get(loser.get("name", ""), loser.get("name", "?"))
    phrase = (
        f"{winner.get('name')} {wsrc} {meta['label']} {_fmt_metric(meta, wv)} "
        f"beat {lshort} {lsrc} {meta['label']} {_fmt_metric(meta, lv)}"
    )
    try:
        wv_f, lv_f = float(wv), float(lv)
    except (TypeError, ValueError):
        return 0.0, phrase
    adv = (lv_f - wv_f) if meta["lower_better"] else (wv_f - lv_f)
    return adv, phrase


def explain_choice(
    rows,
    weights,
    *,
    profile_key: str,
    device: str,
    from_name: str | None = None,
    to_id: str | None = None,
    to_name: str | None = None,
    auto: bool = False,
    still: bool = False,
    labels: dict | None = None,
) -> str:
    """Plain-English why this VPN won. Display-only — does not score."""
    names = dict(DEFAULT_PROFILE_LABELS)
    if labels:
        names.update(labels)
    ranked = sorted(
        list(rows or []),
        key=lambda r: float(r.get("score") or 0),
        reverse=True,
    )
    if not ranked:
        who = device or "host"
        return f"{'STILL' if still else 'SWITCH'} {who} (no scores yet)"

    winner = None
    if to_id:
        winner = next((r for r in ranked if r.get("id") == to_id), None)
    if winner is None and to_name:
        winner = next((r for r in ranked if r.get("name") == to_name), None)
    if winner is None:
        winner = ranked[0]

    loser = None
    if from_name and from_name != winner.get("name"):
        loser = next((r for r in ranked if r.get("name") == from_name), None)
    if loser is None:
        loser = next((r for r in ranked if r.get("id") != winner.get("id")), None)

    w = normalize_weights(weights)
    top = sorted(range(7), key=lambda i: w[i], reverse=True)[:2]
    prof_label = names.get(profile_key, profile_key)
    prof_show = f"Auto → {prof_label}" if auto else prof_label
    weight_name = WEIGHT_NAME.get(profile_key, profile_key)
    weight_bits = " + ".join(
        f"{METRIC_META[i]['label']} {int(round(w[i] * 100))}%" for i in top
    )

    score_bit = f"{winner.get('name')} SAW {float(winner.get('score') or 0):.2f}"
    if loser:
        lshort = VPN_SHORT.get(loser.get("name"), loser.get("name"))
        score_bit += f" vs {lshort} {float(loser.get('score') or 0):.2f}"

    because = f"{weight_name} weights {weight_bits}"
    if loser:
        best_adv = None
        best_phrase = None
        for i in top:
            adv, phrase = _metric_edge(winner, loser, i)
            if best_adv is None or adv > best_adv:
                best_adv = adv
                best_phrase = phrase
        if best_phrase:
            if best_adv is not None and best_adv > 0:
                because += f" and {best_phrase}"
            else:
                because += f" (overall score; {best_phrase.replace(' beat ', ' vs ')})"

    used = _used_data_phrase(winner, loser)
    who = device or "host"
    if still:
        return (
            f"STILL {who} {winner.get('name')} · profile={prof_show} · {used} · "
            f"{score_bit} because {because}"
        )
    prev = from_name or "-"
    return (
        f"SWITCH {who} {prev} → {winner.get('name')} · profile={prof_show} · {used} · "
        f"{score_bit} because {because}"
    )
