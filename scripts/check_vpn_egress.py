#!/usr/bin/env python3
import subprocess


def run(cmd, timeout=8):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def sudo(cmd, timeout=12):
    r = subprocess.run(
        ["sudo", "-S", *cmd],
        input="user\n",
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return r.returncode, (r.stdout or "") + (r.stderr or "")


print("=== host default ===")
_, out = run(["ip", "route", "show", "table", "main"])
for ln in out.splitlines():
    if ln.startswith("default") or "192.168.50" in ln:
        print(ln)

print("=== tunnels ===")
_, out = run(["ip", "-br", "addr"])
keys = ("wg0", "vti0", "tun0", "tap_soft", "enp0s8", "enp0s9", "agph")
for ln in out.splitlines():
    if any(x in ln for x in keys):
        print(ln)

print("=== ping -I tunnels 8.8.8.8 ===")
for iface in ("wg0", "vti0", "tap_soft", "tun0"):
    rc, out = run(["ping", "-I", iface, "-c", "1", "-W", "2", "8.8.8.8"], timeout=6)
    ok = rc == 0 and "bytes from" in out
    print(f"{iface}: {'YES' if ok else 'NO'}")

print("=== ip rules ===")
_, out = run(["ip", "rule"])
for ln in out.splitlines():
    if "fwmark" in ln or "lookup 11" in ln or "lookup 250" in ln:
        print(ln)

print("=== client table defaults ===")
for t in range(110, 118):
    _, out = run(["ip", "route", "show", "table", str(t)])
    defs = [ln for ln in out.splitlines() if ln.startswith("default")]
    if defs:
        print(f"table {t}:")
        for ln in defs:
            print(" ", ln)

print("=== route get 8.8.8.8 from LAN ===")
for ip in ("192.168.50.251", "192.168.50.252"):
    rc, out = sudo(["ip", "route", "get", "8.8.8.8", "from", ip, "iif", "enp0s8"], timeout=6)
    print(ip + ":", " ".join(out.split())[:220] or f"rc={rc}")

print("=== MASQUERADE out tunnels ===")
rc, out = sudo(["iptables", "-t", "nat", "-S", "POSTROUTING"], timeout=8)
for ln in out.splitlines():
    if any(x in ln for x in ("wg0", "vti0", "tap_soft", "tun0")):
        print(ln)

print("=== recent SPEED / DEVICE / TICK ===")
rc, out = sudo(["journalctl", "-u", "adaptive-gateway", "--no-pager", "-n", "400"], timeout=15)
keep = (" SPEED ", "DEVICE ", "TICK ", "SPEED lan-client", "exit=")
for ln in out.splitlines():
    if any(k in ln for k in ("SPEED ", "SPEED lan", "DEVICE ", " lan-client ")):
        if "sudo[" in ln:
            continue
        print(ln[-220:])
