"""Data types and application classification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class AppType(Enum):
    UNKNOWN = auto()
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    TLS = auto()
    QUIC = auto()
    GOOGLE = auto()
    FACEBOOK = auto()
    YOUTUBE = auto()
    TWITTER = auto()
    INSTAGRAM = auto()
    NETFLIX = auto()
    AMAZON = auto()
    MICROSOFT = auto()
    APPLE = auto()
    WHATSAPP = auto()
    TELEGRAM = auto()
    TIKTOK = auto()
    SPOTIFY = auto()
    ZOOM = auto()
    DISCORD = auto()
    GITHUB = auto()
    CLOUDFLARE = auto()


_APP_NAMES = {
    AppType.UNKNOWN: "Unknown",
    AppType.HTTP: "HTTP",
    AppType.HTTPS: "HTTPS",
    AppType.DNS: "DNS",
    AppType.TLS: "TLS",
    AppType.QUIC: "QUIC",
    AppType.GOOGLE: "Google",
    AppType.FACEBOOK: "Facebook",
    AppType.YOUTUBE: "YouTube",
    AppType.TWITTER: "Twitter/X",
    AppType.INSTAGRAM: "Instagram",
    AppType.NETFLIX: "Netflix",
    AppType.AMAZON: "Amazon",
    AppType.MICROSOFT: "Microsoft",
    AppType.APPLE: "Apple",
    AppType.WHATSAPP: "WhatsApp",
    AppType.TELEGRAM: "Telegram",
    AppType.TIKTOK: "TikTok",
    AppType.SPOTIFY: "Spotify",
    AppType.ZOOM: "Zoom",
    AppType.DISCORD: "Discord",
    AppType.GITHUB: "GitHub",
    AppType.CLOUDFLARE: "Cloudflare",
}


def app_type_to_string(app: AppType) -> str:
    return _APP_NAMES.get(app, "Unknown")


def app_type_from_string(name: str) -> AppType | None:
    for app, label in _APP_NAMES.items():
        if label == name:
            return app
    return None


def list_blockable_apps() -> list[str]:
    skip = {AppType.UNKNOWN, AppType.TLS, AppType.QUIC}
    return sorted(
        label for app, label in _APP_NAMES.items() if app not in skip
    )


def parse_ip_string(ip: str) -> int:
    """Parse dotted IPv4 into uint32 (first octet in low byte)."""
    result = 0
    octet = 0
    shift = 0
    for char in ip:
        if char == ".":
            result |= octet << shift
            shift += 8
            octet = 0
        elif char.isdigit():
            octet = octet * 10 + (ord(char) - ord("0"))
    return result | (octet << shift)


def format_ip(addr: int) -> str:
    return (
        f"{addr & 0xFF}.{(addr >> 8) & 0xFF}."
        f"{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}"
    )


@dataclass(frozen=True)
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int

    def reverse(self) -> FiveTuple:
        return FiveTuple(
            self.dst_ip,
            self.src_ip,
            self.dst_port,
            self.src_port,
            self.protocol,
        )

    def to_string(self) -> str:
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return (
            f"{format_ip(self.src_ip)}:{self.src_port} -> "
            f"{format_ip(self.dst_ip)}:{self.dst_port} ({proto})"
        )


def five_tuple_hash(tuple_: FiveTuple) -> int:
    """Hash combining all five-tuple fields (for load balancing)."""
    h = 0
    for value in (
        tuple_.src_ip,
        tuple_.dst_ip,
        tuple_.src_port,
        tuple_.dst_port,
        tuple_.protocol,
    ):
        h ^= hash(value) + 0x9E3779B9 + ((h << 6) & 0xFFFFFFFFFFFFFFFF) + (h >> 2)
        h &= 0xFFFFFFFFFFFFFFFF
    return h


def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN

    lower = sni.lower()

    if any(
        p in lower
        for p in ("google", "gstatic", "googleapis", "ggpht", "gvt1")
    ):
        return AppType.GOOGLE

    if any(p in lower for p in ("youtube", "ytimg", "youtu.be", "yt3.ggpht")):
        return AppType.YOUTUBE

    if any(
        p in lower
        for p in ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")
    ):
        return AppType.FACEBOOK

    if any(p in lower for p in ("instagram", "cdninstagram")):
        return AppType.INSTAGRAM

    if any(p in lower for p in ("whatsapp", "wa.me")):
        return AppType.WHATSAPP

    if any(p in lower for p in ("twitter", "twimg", "x.com", "t.co")):
        return AppType.TWITTER

    if any(p in lower for p in ("netflix", "nflxvideo", "nflximg")):
        return AppType.NETFLIX

    if any(
        p in lower
        for p in ("amazon", "amazonaws", "cloudfront", "aws")
    ):
        return AppType.AMAZON

    if any(
        p in lower
        for p in ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")
    ):
        return AppType.MICROSOFT

    if any(p in lower for p in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE

    if any(p in lower for p in ("telegram", "t.me")):
        return AppType.TELEGRAM

    if any(
        p in lower
        for p in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")
    ):
        return AppType.TIKTOK

    if any(p in lower for p in ("spotify", "scdn.co")):
        return AppType.SPOTIFY

    if "zoom" in lower:
        return AppType.ZOOM

    if any(p in lower for p in ("discord", "discordapp")):
        return AppType.DISCORD

    if any(p in lower for p in ("github", "githubusercontent")):
        return AppType.GITHUB

    if any(p in lower for p in ("cloudflare", "cf-")):
        return AppType.CLOUDFLARE

    return AppType.HTTPS
