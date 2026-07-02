"""Multi-threaded DPI engine."""

from __future__ import annotations

import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .blocking_rules import BlockingRules
from .packet_parser import parse, tuple_from_parsed
from .pcap_reader import PcapReader
from .sni_extractor import extract_http_host, extract_sni
from .thread_safe_queue import TSQueue
from .report import banner, row, section
from .dpi_types import (
    AppType,
    FiveTuple,
    app_type_to_string,
    five_tuple_hash,
    sni_to_app_type,
)


@dataclass
class Packet:
    id: int
    ts_sec: int
    ts_usec: int
    tuple: FiveTuple
    data: bytes
    tcp_flags: int = 0
    payload_offset: int = 0
    payload_length: int = 0


@dataclass
class FlowEntry:
    tuple: FiveTuple | None = None
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False
    classified: bool = False


class Stats:
    def __init__(self) -> None:
        self.total_packets = 0
        self.total_bytes = 0
        self.forwarded = 0
        self.dropped = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self._lock = threading.Lock()
        self.app_counts: dict[AppType, int] = {}
        self.detected_snis: dict[str, AppType] = {}

    def record_app(self, app: AppType, sni: str) -> None:
        with self._lock:
            self.app_counts[app] = self.app_counts.get(app, 0) + 1
            if sni:
                self.detected_snis[sni] = app


class FastPath:
    def __init__(
        self,
        fp_id: int,
        rules: BlockingRules,
        stats: Stats,
        output_queue: TSQueue[Packet],
    ) -> None:
        self.id = fp_id
        self._rules = rules
        self._stats = stats
        self._output_queue = output_queue
        self.input_queue: TSQueue[Packet] = TSQueue()
        self._flows: dict[FiveTuple, FlowEntry] = {}
        self._running = False
        self._thread: threading.Thread | None = None
        self.processed = 0

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self.input_queue.shutdown()
        if self._thread:
            self._thread.join()

    def _classify_flow(self, pkt: Packet, flow: FlowEntry) -> None:
        if pkt.tuple.dst_port == 443 and pkt.payload_length > 5:
            payload = pkt.data[pkt.payload_offset : pkt.payload_offset + pkt.payload_length]
            sni = extract_sni(payload)
            if sni:
                flow.sni = sni
                flow.app_type = sni_to_app_type(sni)
                flow.classified = True
                return

        if pkt.tuple.dst_port == 80 and pkt.payload_length > 10:
            payload = pkt.data[pkt.payload_offset : pkt.payload_offset + pkt.payload_length]
            host = extract_http_host(payload)
            if host:
                flow.sni = host
                flow.app_type = sni_to_app_type(host)
                flow.classified = True
                return

        if pkt.tuple.dst_port == 53 or pkt.tuple.src_port == 53:
            flow.app_type = AppType.DNS
            flow.classified = True
            return

        if pkt.tuple.dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif pkt.tuple.dst_port == 80:
            flow.app_type = AppType.HTTP

    def _run(self) -> None:
        while self._running:
            pkt = self.input_queue.pop(0.1)
            if pkt is None:
                continue

            self.processed += 1
            flow = self._flows.setdefault(pkt.tuple, FlowEntry())
            if flow.tuple is None:
                flow.tuple = pkt.tuple
            flow.packets += 1
            flow.bytes += len(pkt.data)

            if not flow.classified:
                self._classify_flow(pkt, flow)

            if not flow.blocked:
                flow.blocked = self._rules.is_blocked(
                    pkt.tuple.src_ip, flow.app_type, flow.sni
                )

            self._stats.record_app(flow.app_type, flow.sni)

            if flow.blocked:
                self._stats.dropped += 1
            else:
                self._stats.forwarded += 1
                self._output_queue.push(pkt)


class LoadBalancer:
    def __init__(self, lb_id: int, fps: list[FastPath]) -> None:
        self.id = lb_id
        self._fps = fps
        self.input_queue: TSQueue[Packet] = TSQueue()
        self._running = False
        self._thread: threading.Thread | None = None
        self.dispatched = 0

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self.input_queue.shutdown()
        if self._thread:
            self._thread.join()

    def _run(self) -> None:
        while self._running:
            pkt = self.input_queue.pop(0.1)
            if pkt is None:
                continue
            fp_idx = five_tuple_hash(pkt.tuple) % len(self._fps)
            self._fps[fp_idx].input_queue.push(pkt)
            self.dispatched += 1


@dataclass
class EngineConfig:
    num_lbs: int = 2
    fps_per_lb: int = 2


class DPIEngine:
    def __init__(self, config: EngineConfig | None = None) -> None:
        self.config = config or EngineConfig()
        self.rules = BlockingRules()
        self.stats = Stats()
        self._output_queue: TSQueue[Packet] = TSQueue()

        total_fps = self.config.num_lbs * self.config.fps_per_lb
        banner("DPI ENGINE v2.0 (Multi-threaded, Python)")
        row("Load Balancers", self.config.num_lbs, 4)
        row("FPs per LB", self.config.fps_per_lb, 4)
        row("Total FPs", total_fps, 4)
        print()

        self._fps = [
            FastPath(i, self.rules, self.stats, self._output_queue)
            for i in range(total_fps)
        ]

        self._lbs: list[LoadBalancer] = []
        for lb in range(self.config.num_lbs):
            start = lb * self.config.fps_per_lb
            lb_fps = self._fps[start : start + self.config.fps_per_lb]
            self._lbs.append(LoadBalancer(lb, lb_fps))

    def block_ip(self, ip: str) -> None:
        self.rules.block_ip(ip)

    def block_app(self, app: str) -> None:
        self.rules.block_app(app)

    def block_domain(self, domain: str) -> None:
        self.rules.block_domain(domain)

    def _calc_payload_offset(self, data: bytes, has_tcp: bool, has_udp: bool) -> tuple[int, int]:
        payload_offset = 14
        if len(data) > 14:
            ip_ihl = data[14] & 0x0F
            payload_offset += ip_ihl * 4
            if has_tcp and payload_offset + 12 < len(data):
                tcp_off = (data[payload_offset + 12] >> 4) & 0x0F
                payload_offset += tcp_off * 4
            elif has_udp:
                payload_offset += 8
        payload_length = max(0, len(data) - payload_offset) if payload_offset < len(data) else 0
        return payload_offset, payload_length

    def process(self, input_file: str | Path, output_file: str | Path) -> bool:
        reader = PcapReader()
        if not reader.open(input_file):
            return False

        try:
            output = Path(output_file).open("wb")
        except OSError:
            print("Cannot open output file")
            reader.close()
            return False

        output.write(reader.get_global_header_bytes())

        for fp in self._fps:
            fp.start()
        for lb in self._lbs:
            lb.start()

        output_running = True

        def output_thread() -> None:
            while output_running or self._output_queue.size() > 0:
                pkt = self._output_queue.pop(0.05)
                if pkt is None:
                    continue
                pkt_hdr = struct.pack(
                    "<IIII",
                    pkt.ts_sec,
                    pkt.ts_usec,
                    len(pkt.data),
                    len(pkt.data),
                )
                output.write(pkt_hdr)
                output.write(pkt.data)

        writer = threading.Thread(target=output_thread, daemon=True)
        writer.start()

        print("[Reader] Processing packets...")
        pkt_id = 0

        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break

            parsed = parse(raw)
            if parsed is None:
                continue
            if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                continue

            payload_offset, payload_length = self._calc_payload_offset(
                raw.data, parsed.has_tcp, parsed.has_udp
            )

            pkt = Packet(
                id=pkt_id,
                ts_sec=raw.header.ts_sec,
                ts_usec=raw.header.ts_usec,
                tuple=tuple_from_parsed(parsed),
                data=raw.data,
                tcp_flags=parsed.tcp_flags,
                payload_offset=payload_offset,
                payload_length=payload_length,
            )
            pkt_id += 1

            self.stats.total_packets += 1
            self.stats.total_bytes += len(pkt.data)
            if parsed.has_tcp:
                self.stats.tcp_packets += 1
            elif parsed.has_udp:
                self.stats.udp_packets += 1

            lb_idx = five_tuple_hash(pkt.tuple) % len(self._lbs)
            self._lbs[lb_idx].input_queue.push(pkt)

        print(f"[Reader] Done reading {pkt_id} packets")
        reader.close()

        time.sleep(0.5)

        for lb in self._lbs:
            lb.stop()
        for fp in self._fps:
            fp.stop()

        output_running = False
        self._output_queue.shutdown()
        writer.join()
        output.close()

        self._print_report()
        print(f"\nOutput written to: {output_file}")
        return True

    def _print_report(self) -> None:
        section("PROCESSING REPORT")
        row("Total Packets", self.stats.total_packets)
        row("Total Bytes", self.stats.total_bytes)
        row("TCP Packets", self.stats.tcp_packets)
        row("UDP Packets", self.stats.udp_packets)
        print()
        row("Forwarded", self.stats.forwarded)
        row("Dropped", self.stats.dropped)
        print()
        section("THREAD STATISTICS")
        for i, lb in enumerate(self._lbs):
            row(f"LB{i} dispatched", lb.dispatched)
        for i, fp in enumerate(self._fps):
            row(f"FP{i} processed", fp.processed)
        print()
        section("APPLICATION BREAKDOWN")

        with self.stats._lock:
            sorted_apps = sorted(
                self.stats.app_counts.items(), key=lambda x: x[1], reverse=True
            )
            total = self.stats.total_packets
            for app, count in sorted_apps:
                pct = 100.0 * count / total if total else 0
                bar = "#" * int(pct / 5)
                print(
                    f"  {app_type_to_string(app):<15} {count:>8} "
                    f"{pct:5.1f}% {bar}"
                )
            detected = dict(self.stats.detected_snis)

        if detected:
            print("\n[Detected Domains/SNIs]")
            for sni, app in sorted(detected.items()):
                print(f"  - {sni} -> {app_type_to_string(app)}")
