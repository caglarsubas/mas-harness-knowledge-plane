#!/usr/bin/env python3
"""Require the parent OS sandbox to deny outbound IPv4 and IPv6."""

from __future__ import annotations

import errno
import socket


def denied(family: socket.AddressFamily, address: tuple[object, ...]) -> bool:
    client = socket.socket(family, socket.SOCK_STREAM)
    client.settimeout(0.25)
    try:
        client.connect(address)
    except OSError as exc:
        return exc.errno in {errno.EACCES, errno.EPERM}
    finally:
        client.close()
    return False


if not denied(socket.AF_INET, ("127.0.0.1", 9)) or not denied(socket.AF_INET6, ("::1", 9, 0, 0)):
    raise SystemExit("offline network canary: outbound isolation is absent")
print("offline network canary: OS denied IPv4 and IPv6 outbound egress")
