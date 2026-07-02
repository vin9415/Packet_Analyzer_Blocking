"""Blocking rules for DPI traffic filtering."""

from __future__ import annotations

import threading

from .dpi_types import AppType, app_type_from_string, app_type_to_string, parse_ip_string


class BlockingRules:
    def __init__(self, quiet: bool = False) -> None:
        self._mutex = threading.Lock()
        self.blocked_ips: set[int] = set()
        self.blocked_apps: set[AppType] = set()
        self.blocked_domains: list[str] = []
        self._quiet = quiet

    def block_ip(self, ip: str) -> None:
        with self._mutex:
            self.blocked_ips.add(parse_ip_string(ip))
        if not self._quiet:
            print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app: str) -> None:
        app_type = app_type_from_string(app)
        if app_type is None:
            if not self._quiet:
                print(f"[Rules] Unknown app: {app}")
            return
        with self._mutex:
            self.blocked_apps.add(app_type)
        if not self._quiet:
            print(f"[Rules] Blocked app: {app}")

    def block_domain(self, domain: str) -> None:
        with self._mutex:
            self.blocked_domains.append(domain)
        if not self._quiet:
            print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        with self._mutex:
            if src_ip in self.blocked_ips:
                return True
            if app in self.blocked_apps:
                return True
            for domain in self.blocked_domains:
                if domain in sni:
                    return True
        return False
