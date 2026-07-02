"""Structured PCAP processing for CLI and web."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from .blocking_rules import BlockingRules
from .packet_parser import parse, tuple_from_parsed
from .pcap_reader import PcapReader
from .sni_extractor import extract_http_host, extract_sni
from .dpi_types import AppType, FiveTuple, app_type_to_string, sni_to_app_type


@dataclass
class Flow:
    tuple: FiveTuple | None = None
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False


@dataclass
class BlockedEvent:
    src_ip: str
    dest_ip: str
    app: str
    sni: str = ""


@dataclass
class ProcessResult:
    success: bool
    error: str | None = None
    total_packets: int = 0
    forwarded: int = 0
    dropped: int = 0
    active_flows: int = 0
    app_breakdown: list[dict] = field(default_factory=list)
    detected_domains: list[dict] = field(default_factory=list)
    blocked_events: list[BlockedEvent] = field(default_factory=list)
    output_file: str | None = None


def _payload_from_raw(data: bytes) -> tuple[int, int]:
    if len(data) <= 14:
        return 0, 0
    ip_ihl = data[14] & 0x0F
    payload_offset = 14 + ip_ihl * 4
    if payload_offset + 12 >= len(data):
        return payload_offset, max(0, len(data) - payload_offset)
    tcp_offset = (data[payload_offset + 12] >> 4) & 0x0F
    payload_offset += tcp_offset * 4
    return payload_offset, max(0, len(data) - payload_offset)


def _classify_flow(flow: Flow, parsed, raw_data: bytes) -> None:
    if (
        flow.app_type in (AppType.UNKNOWN, AppType.HTTPS)
        and not flow.sni
        and parsed.has_tcp
        and parsed.dest_port == 443
    ):
        offset, length = _payload_from_raw(raw_data)
        if length > 5:
            sni = extract_sni(raw_data[offset : offset + length])
            if sni:
                flow.sni = sni
                flow.app_type = sni_to_app_type(sni)

    if (
        flow.app_type in (AppType.UNKNOWN, AppType.HTTP)
        and not flow.sni
        and parsed.has_tcp
        and parsed.dest_port == 80
    ):
        offset, length = _payload_from_raw(raw_data)
        host = extract_http_host(raw_data[offset : offset + length])
        if host:
            flow.sni = host
            flow.app_type = sni_to_app_type(host)

    if flow.app_type == AppType.UNKNOWN and (
        parsed.dest_port == 53 or parsed.src_port == 53
    ):
        flow.app_type = AppType.DNS

    if flow.app_type == AppType.UNKNOWN:
        if parsed.dest_port == 443:
            flow.app_type = AppType.HTTPS
        elif parsed.dest_port == 80:
            flow.app_type = AppType.HTTP


def process_pcap(
    input_file: str | Path,
    output_file: str | Path,
    rules: BlockingRules | None = None,
    quiet: bool = False,
) -> ProcessResult:
    rules = rules or BlockingRules(quiet=quiet)

    reader = PcapReader()
    if not reader.open(input_file, quiet=quiet):
        return ProcessResult(success=False, error="Could not open input PCAP file")

    output_path = Path(output_file)
    try:
        output = output_path.open("wb")
    except OSError:
        reader.close()
        return ProcessResult(success=False, error="Could not create output file")

    output.write(reader.get_global_header_bytes())

    flows: dict[FiveTuple, Flow] = {}
    total_packets = 0
    forwarded = 0
    dropped = 0
    app_stats: dict[AppType, int] = {}
    blocked_events: list[BlockedEvent] = []

    while True:
        raw = reader.read_next_packet()
        if raw is None:
            break

        total_packets += 1
        parsed = parse(raw)
        if parsed is None:
            continue
        if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            continue

        tuple_ = tuple_from_parsed(parsed)
        flow = flows.setdefault(tuple_, Flow())
        if flow.tuple is None:
            flow.tuple = tuple_
        flow.packets += 1
        flow.bytes += len(raw.data)

        _classify_flow(flow, parsed, raw.data)

        if not flow.blocked:
            flow.blocked = rules.is_blocked(tuple_.src_ip, flow.app_type, flow.sni)
            if flow.blocked:
                blocked_events.append(
                    BlockedEvent(
                        src_ip=parsed.src_ip,
                        dest_ip=parsed.dest_ip,
                        app=app_type_to_string(flow.app_type),
                        sni=flow.sni,
                    )
                )

        app_stats[flow.app_type] = app_stats.get(flow.app_type, 0) + 1

        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            pkt_hdr = struct.pack(
                "<IIII",
                raw.header.ts_sec,
                raw.header.ts_usec,
                len(raw.data),
                len(raw.data),
            )
            output.write(pkt_hdr)
            output.write(raw.data)

    reader.close()
    output.close()

    sorted_apps = sorted(app_stats.items(), key=lambda x: x[1], reverse=True)
    app_breakdown = [
        {
            "name": app_type_to_string(app),
            "count": count,
            "percent": round(100.0 * count / total_packets, 1) if total_packets else 0,
        }
        for app, count in sorted_apps
    ]

    unique_snis: dict[str, AppType] = {}
    for flow in flows.values():
        if flow.sni:
            unique_snis[flow.sni] = flow.app_type

    detected_domains = [
        {"domain": sni, "app": app_type_to_string(app)}
        for sni, app in sorted(unique_snis.items())
    ]

    return ProcessResult(
        success=True,
        total_packets=total_packets,
        forwarded=forwarded,
        dropped=dropped,
        active_flows=len(flows),
        app_breakdown=app_breakdown,
        detected_domains=detected_domains,
        blocked_events=blocked_events,
        output_file=str(output_path),
    )
