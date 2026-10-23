"""Safety policy, checked before every broker call (RV-4; PLAN.md §6.14).

* The host must match the repository's ``verifier.preview_hosts`` (base-branch config) and be
  the host of the preview deployment this run was triggered for; HTTPS only; no userinfo or
  non-default ports.
* Every address the host resolves to must be public: private, loopback, link-local (cloud
  metadata), multicast, reserved and unspecified ranges are refused (SSRF guard). The resolved
  address is pinned for the request so a second DNS answer cannot redirect it.
* Methods: GET/HEAD by default. POST only through ``create_fixture``; PUT/PATCH/DELETE only on a
  path that contains the id of a fixture this run created.
* A per-run call budget and a response size cap; redirects are never followed.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

READ_METHODS = frozenset({"GET", "HEAD"})
WRITE_METHODS = frozenset({"PUT", "PATCH", "DELETE"})
DEFAULT_BUDGET = 30
MAX_RESPONSE_BYTES = 256 * 1024

Resolver = Callable[[str], list[str]]


def system_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    return sorted({str(ai[4][0]) for ai in infos})


class PolicyError(Exception):
    """The call was refused before anything left the broker."""


def public_ip(addr: str) -> bool:
    """Globally routable unicast only: excludes RFC 1918, loopback, link-local (169.254.0.0/16,
    cloud metadata), CGNAT, ULA, multicast, reserved and unspecified addresses."""
    ip = ipaddress.ip_address(addr)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def host_allowed(host: str, patterns: list[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(fnmatch.fnmatchcase(host, p.lower()) for p in patterns if p)


@dataclass
class Policy:
    preview_host: str  # host of the deployment that triggered this run
    allowed_hosts: list[str]  # verifier.preview_hosts from the base-branch config
    budget: int = DEFAULT_BUDGET
    resolver: Resolver = system_resolver
    fixtures: set[str] = field(default_factory=set)  # ids of objects this run created
    calls: int = 0

    def check(self, method: str, url: str, *, fixture_call: bool = False) -> str:
        """Validate one call; returns the pinned IP address to connect to."""
        method = method.upper()
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise PolicyError("only https preview URLs are allowed")
        if parts.username or parts.password or parts.port not in (None, 443):
            raise PolicyError("credentials or non-default ports in the URL are not allowed")
        host = (parts.hostname or "").lower()
        if host != self.preview_host.lower():
            raise PolicyError("host is not the preview deployment of this run")
        if not host_allowed(host, self.allowed_hosts):
            raise PolicyError("host is not in verifier.preview_hosts")
        if method == "POST" and not fixture_call:
            raise PolicyError("POST is only allowed through create_fixture")
        if method in WRITE_METHODS and not any(f in parts.path.split("/") for f in self.fixtures):
            raise PolicyError("writes are only allowed on objects this run created")
        if method not in READ_METHODS | WRITE_METHODS | {"POST"}:
            raise PolicyError(f"method {method} is not allowed")
        if self.calls >= self.budget:
            raise PolicyError("call budget exhausted")
        addrs = self.resolver(host)
        if not addrs or not all(public_ip(a) for a in addrs):
            raise PolicyError("host resolves to a non-public address")
        self.calls += 1
        return addrs[0]
