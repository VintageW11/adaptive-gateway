#!/bin/bash
# Defense watchdog (~10s via systemd timer).
# - Ubuntu default stays via MikroTik .1 (never a VPN / VBox NAT steal).
# - Device tables 110+ (LAN clients): if default is a VPN that is down,
#   fails ping -I 8.8.8.8 with a FAIL LAN-proof stamp, or is overlay-only
#   (nebula1) → pin that table to default via 192.168.50.1.
#   wg0 / vti0 / tap_soft are real client WAN when LAN-proof PASSes.
# - Never `ip route del default dev wg0` without `table main` — that also
#   deleted client table 110+ `default dev wg0`.
# - DHCP .10 → .1 ONLY after 3 consecutive ticks (~30s) of
#   `ping -I enp0s8 8.8.8.8` failing (3 retries/tick) AND forwarding
#   not ready. Client-table / VPN ping-I flaps do not revert DHCP.
# - Crash-log only for real events: stolen 10.0.2.2 / stolen default,
#   Ubuntu enp0s8 WAN dead (consecutive), DHCP actually changed.
#   Do not crash-log default-route ping blinks or table-110 ping-I.
set -uo pipefail

WAN_IF="enp0s8"
WAN_GW="192.168.50.1"
VBOX_GW="10.0.2.2"
VBOX_IF="enp0s3"
MT_HOST="${AUTOVPN_MIKROTIK_HOST:-192.168.50.1}"
MT_USER="${AUTOVPN_MIKROTIK_USER:-admin}"
MT_PASS="${AUTOVPN_MIKROTIK_PASS:-capstone}"
FAIL_FILE="/run/autovpn-watchdog.fail"
FAIL_LIMIT=3
CRASH_COOLDOWN="${AUTOVPN_CRASH_LOG_COOLDOWN:-120}"
CRASH_STAMP="/run/autovpn-crash-log.ts"
CRASH_LOG=""
if [[ -f /usr/local/sbin/crash-log.sh ]]; then
  CRASH_LOG="/usr/local/sbin/crash-log.sh"
elif [[ -f /home/user/adaptive-gateway/scripts/crash-log.sh ]]; then
  CRASH_LOG="/home/user/adaptive-gateway/scripts/crash-log.sh"
fi

log() { logger -t autovpn-watchdog -- "$*"; printf '%s\n' "$*"; }

maybe_crash_log() {
  local reason="${1:-unknown}"
  local force="${2:-0}"
  [[ -n "$CRASH_LOG" ]] || return 0
  local now last=0
  now="$(date +%s)"
  if [[ -f "$CRASH_STAMP" ]]; then
    last="$(cat "$CRASH_STAMP" 2>/dev/null || echo 0)"
  fi
  last="${last:-0}"
  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  if [[ "$force" != "1" ]] && (( now - last < CRASH_COOLDOWN )); then
    log "crash-log skipped (cooldown ${CRASH_COOLDOWN}s) reason=${reason}"
    return 0
  fi
  printf '%s\n' "$now" >"$CRASH_STAMP"
  log "crash-log reason=${reason}"
  export AUTOVPN_CRASH_REASON="$reason"
  if command -v timeout >/dev/null 2>&1; then
    timeout 15 /bin/bash "$CRASH_LOG" || true
  else
    /bin/bash "$CRASH_LOG" || true
  fi
}

protect_default() {
  ip route del 192.168.50.1 via "$VBOX_GW" dev "$VBOX_IF" 2>/dev/null || true
  ip route del 8.8.8.8 via "$VBOX_GW" dev "$VBOX_IF" 2>/dev/null || true
  ip route del 1.1.1.1 via "$VBOX_GW" dev "$VBOX_IF" 2>/dev/null || true
  ip route del default via 192.168.100.1 dev "$WAN_IF" table main 2>/dev/null || true
  # Only drop VPN defaults that are actually on main. Bare `del default
  # dev wg0` also removed client table 110+ `default dev wg0`.
  while read -r ln; do
    [[ -n "$ln" ]] || continue
    dev="$(echo "$ln" | awk '{for (i=1;i<=NF;i++) if ($i=="dev") { print $(i+1); exit }}')"
    [[ -n "$dev" ]] || continue
    if is_vpn_iface "$dev"; then
      ip route del default dev "$dev" table main 2>/dev/null || true
    fi
  done < <(ip route show table main 2>/dev/null | awk '/^default/')
  ip route del 8.8.8.8/32 2>/dev/null || true
  # Leftover demo rule sent 1.1.1.1 via WG table 200.
  while ip rule del to 1.1.1.1 table 200 2>/dev/null; do :; done
  ip route flush table 200 2>/dev/null || true
  ip route replace default via "$WAN_GW" dev "$WAN_IF" metric 10 src 192.168.50.10 table main
  ip route replace default via "$VBOX_GW" dev "$VBOX_IF" metric 100 table main 2>/dev/null || true
}

# Bind to enp0s8. Default-route ping follows NAT metric 100 and false-positives.
ping_enp0s8() {
  local i
  for i in 1 2 3; do
    ping -I "$WAN_IF" -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 && return 0
  done
  return 1
}

forwarding_cfg_ok() {
  local fwd
  fwd="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
  [[ "$fwd" == "1" ]] || return 1
  iptables -t nat -C POSTROUTING -o "$WAN_IF" -j MASQUERADE >/dev/null 2>&1
}

forwarding_ready() {
  forwarding_cfg_ok || return 1
  ping_enp0s8
}

dhcp_gw() {
  command -v sshpass >/dev/null 2>&1 || return 0
  sshpass -p "$MT_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=6 \
    "$MT_USER@$MT_HOST" '/ip dhcp-server network print detail' 2>/dev/null \
    | grep -oE 'gateway=[0-9.]+' | head -1 | cut -d= -f2
}

revert_dhcp() {
  command -v sshpass >/dev/null 2>&1 || return 1
  sshpass -p "$MT_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 \
    "$MT_USER@$MT_HOST" \
    '/ip dhcp-server network set [find address="192.168.50.0/24"] gateway=192.168.50.1 dns-server=192.168.50.1' \
    >/dev/null 2>&1
}

is_vpn_iface() {
  local d="${1:-}"
  [[ -n "$d" ]] || return 1
  case "$d" in
    wg0|tun0|tun1|sstp0|vti0|nebula1|tap_soft|ppp0|ppp1) return 0 ;;
    zt*) return 0 ;;
    *) return 1 ;;
  esac
}

# Overlay / lab-local that can ping -I but must never carry LAN client internet.
# Match Python _CLIENT_EGRESS_DENY: nebula1 only. wg0 is a real client WAN.
client_egress_denied() {
  case "${1:-}" in
    nebula1) return 0 ;;
    *) return 1 ;;
  esac
}

table_default_dev() {
  ip route show table "$1" 2>/dev/null | awk '/^default/ {
    for (i=1;i<=NF;i++) if ($i=="dev") { print $(i+1); exit }
  }'
}

iface_down() {
  local d="$1" st
  st="$(ip -br link show "$d" 2>/dev/null | awk '{print $2}')"
  [[ -z "$st" || "$st" == "DOWN" ]]
}

lan_proof_failed() {
  local iface="$1"
  local stamp="/run/autovpn-lan-proof/${iface}"
  local age=9999 line now mtime
  now="$(date +%s)"
  if [[ -f "$stamp" ]]; then
    mtime="$(stat -c %Y "$stamp" 2>/dev/null || echo 0)"
    age=$((now - mtime))
    if (( age >= 0 && age < 45 )); then
      line="$(head -1 "$stamp" 2>/dev/null || true)"
      [[ "$line" == FAIL ]] && return 0
    fi
  fi
  if ! iptables -t nat -C POSTROUTING -o "$iface" -j MASQUERADE >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

client_tables() {
  # 110–125: kiyo 110, phone 111, cloud ZT remotes 112+. Plus any lookup 110–199.
  {
    seq 110 125
    ip rule show 2>/dev/null | awk '{
      for (i=1;i<NF;i++) if ($i=="lookup") {
        t=$(i+1)+0
        if (t>=110 && t<200) print t
      }
    }'
  } | sort -n | uniq
}

pin_table_mikrotik() {
  local table="$1"
  ip route replace 192.168.50.0/24 dev "$WAN_IF" table "$table" 2>/dev/null || true
  ip route replace default via "$WAN_GW" dev "$WAN_IF" table "$table"
}

# Snapshot first (before protect_default / table pins) so crash logs show the broken state.
stolen=0
stolen_nat=0
if ! ip -4 route show default 2>/dev/null | grep -Eq "via ${WAN_GW}[[:space:]].*dev[[:space:]]${WAN_IF}|via ${WAN_GW}[[:space:]]dev[[:space:]]${WAN_IF}"; then
  stolen=1
fi
got="$(ip route get 8.8.8.8 2>/dev/null || true)"
if echo "$got" | grep -q "via ${VBOX_GW}"; then
  stolen=1
  stolen_nat=1
fi

# Client path: independent of Ubuntu's own ping. Do not pin a proven tunnel
# on one ping -I blink. wg0 is allowed (Python LAN-proof).
client_hits=()
while read -r t; do
  [[ -n "$t" ]] || continue
  defdev="$(table_default_dev "$t")"
  is_vpn_iface "$defdev" || continue
  why=""
  if client_egress_denied "$defdev"; then
    why="overlay-no-client-wan"
  elif iface_down "$defdev"; then
    why="iface-down"
  elif ! ping -I "$defdev" -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
    if lan_proof_failed "$defdev"; then
      why="ping-I-fail"
    fi
  elif lan_proof_failed "$defdev"; then
    why="lan-proof-fail"
  fi
  [[ -n "$why" ]] || continue
  client_hits+=("table-${t}:${defdev}:${why}")
done < <(client_tables)

if [[ "$stolen" -eq 1 ]]; then
  if [[ "$stolen_nat" -eq 1 ]]; then
    maybe_crash_log "stolen-default via-${VBOX_GW}"
  else
    maybe_crash_log "stolen-default"
  fi
fi

protect_default

if [[ ${#client_hits[@]} -gt 0 ]]; then
  for h in "${client_hits[@]}"; do
    t="${h#table-}"
    t="${t%%:*}"
    pin_table_mikrotik "$t"
    log "client table ${t} pinned via ${WAN_GW} (${h}) — DHCP unchanged"
  done
fi

# VPN path self-heal (wg0 + tun0/tap_soft/vti0/sstp0/tun1/nebula1/ztfn5ujzh6).
# Per-path /tmp/ag-heal-PATH cooldown 90s — this timer is 10s; do not restart the stack.
if [[ -f /usr/local/sbin/heal-vpn-paths.sh ]]; then
  /bin/bash /usr/local/sbin/heal-vpn-paths.sh || true
elif [[ -f /home/user/adaptive-gateway/scripts/heal-vpn-paths.sh ]]; then
  /bin/bash /home/user/adaptive-gateway/scripts/heal-vpn-paths.sh || true
elif [[ -f /usr/local/sbin/heal-wireguard.sh ]]; then
  /bin/bash /usr/local/sbin/heal-wireguard.sh || true
elif [[ -f /home/user/adaptive-gateway/scripts/heal-wireguard.sh ]]; then
  /bin/bash /home/user/adaptive-gateway/scripts/heal-wireguard.sh || true
fi

changed=0
def="$(ip -4 route show default | awk '/metric 10|dev '"$WAN_IF"'/{print; exit}')"
if ! echo "$def" | grep -q "via ${WAN_GW}"; then
  got="$(ip route get 8.8.8.8 2>/dev/null || true)"
  if ! echo "$got" | grep -q "via ${WAN_GW}.*dev ${WAN_IF}"; then
    log "restored default via ${WAN_GW} dev ${WAN_IF}"
    changed=1
  fi
fi

gw="$(dhcp_gw || true)"

if ping_enp0s8; then
  echo 0 > "$FAIL_FILE"
  exit 0
fi

n=0
[[ -f "$FAIL_FILE" ]] && n="$(cat "$FAIL_FILE" 2>/dev/null || echo 0)"
n=$((n + 1))
echo "$n" > "$FAIL_FILE"
log "Ubuntu ping -I ${WAN_IF} 8.8.8.8 FAIL (${n}/${FAIL_LIMIT}) DHCP=${gw:-?}"
if [[ "$n" -lt "$FAIL_LIMIT" ]]; then
  exit 0
fi

# Last-chance: forwarding_ready re-pings enp0s8. A recovered WAN must not
# crash-log or yank Windows off .10.
if forwarding_ready; then
  echo 0 > "$FAIL_FILE"
  log "enp0s8 ping missed ${FAIL_LIMIT} ticks but forwarding_ready true — leave DHCP ${gw:-?}"
  exit 0
fi

maybe_crash_log "ubuntu-enp0s8-wan-dead"

if [[ "$gw" != "192.168.50.10" ]]; then
  exit 0
fi

if revert_dhcp; then
  echo 0 > "$FAIL_FILE"
  log "DHCP reverted to 192.168.50.1 (Ubuntu enp0s8 ping failed + forwarding not ready). Windows still needs ipconfig /renew — Ubuntu cannot renew Windows leases."
  maybe_crash_log "dhcp-revert-.1 ubuntu-enp0s8-ping-fail" 1
else
  log "DHCP revert FAILED — run restore-mikrotik-internet.sh"
  maybe_crash_log "dhcp-revert-failed ubuntu-enp0s8-ping-fail" 1
fi
exit 0
