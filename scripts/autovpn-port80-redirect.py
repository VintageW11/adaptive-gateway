#!/usr/bin/env python3
"""Keep http://autovpn.lab/ on port 80 serving Flask (:5006).

LAN browsers type autovpn.lab (no port). A 302 to the IP would rewrite the
address bar. REDIRECT leaves the name in the URL.
"""
from __future__ import annotations

import subprocess
import time

_RULES = (
    ("192.168.50.10", "5006"),
    ("192.168.56.10", "5006"),
)


def _run(args: list[str]) -> int:
    return subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode


def _ensure() -> None:
    for dest, port in _RULES:
        spec = [
            "PREROUTING", "-p", "tcp", "-d", dest,
            "--dport", "80", "-j", "REDIRECT", "--to-ports", port,
        ]
        if _run(["iptables", "-t", "nat", "-C", *spec]) != 0:
            _run(["iptables", "-t", "nat", "-I", *spec[:1], "1", *spec[1:]])


if __name__ == "__main__":
    while True:
        try:
            _ensure()
        except Exception:
            pass
        time.sleep(15)
