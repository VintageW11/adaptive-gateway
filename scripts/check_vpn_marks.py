#!/usr/bin/env python3
import subprocess
import time


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


print("=== mangle MARK (client steering) ===")
_, out = sudo(["iptables", "-t", "mangle", "-L", "PREROUTING", "-n", "-v"], timeout=8)
for ln in out.splitlines():
    if "192.168.50." in ln and ("MARK" in ln or "mark" in ln):
        print(ln)

print("=== route get with fwmark (what marked packets use) ===")
for mark, label in (("0x6e", "table110"), ("0x6f", "table111"), ("0x70", "table112"), ("0x71", "table113")):
    _, out = sudo(["ip", "route", "get", "8.8.8.8", "mark", mark], timeout=6)
    print(f"{label} mark {mark}:", " ".join(out.split())[:200])

print("=== table defaults ===")
for t in (110, 111, 112, 113, 250):
    _, out = run(["ip", "route", "show", "table", str(t)])
    defs = [ln for ln in out.splitlines() if "default" in ln]
    print(f"table {t}:", "; ".join(defs) if defs else "(empty)")

print("=== gateway flag from python service log ===")
_, out = sudo(["journalctl", "-u", "adaptive-gateway", "--no-pager", "-n", "80"], timeout=12)
for ln in out.splitlines():
    if any(k in ln for k in ("GATEWAY", "DEVICE ", "exit=", "LAN-PROOF wg0", "SPEED lan-client")):
        if "sudo[" in ln:
            continue
        print(ln[-240:])
