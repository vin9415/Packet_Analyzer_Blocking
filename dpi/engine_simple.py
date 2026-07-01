"""Single-threaded DPI engine CLI wrapper."""

from __future__ import annotations

from pathlib import Path

from .blocking_rules import BlockingRules
from .processor import process_pcap
from .report import banner, row, section


def run_simple(
    input_file: str | Path,
    output_file: str | Path,
    rules: BlockingRules | None = None,
) -> bool:
    rules = rules or BlockingRules()
    banner("DPI ENGINE v1.0 (Python)")
    print("[DPI] Processing packets...")

    result = process_pcap(input_file, output_file, rules, quiet=False)
    if not result.success:
        print(f"Error: {result.error}")
        return False

    section("PROCESSING REPORT")
    row("Total Packets", result.total_packets, 10)
    row("Forwarded", result.forwarded, 10)
    row("Dropped", result.dropped, 10)
    row("Active Flows", result.active_flows, 10)
    print()
    section("APPLICATION BREAKDOWN")

    for item in result.app_breakdown:
        bar = "#" * int(item["percent"] / 5)
        print(
            f"  {item['name']:<15} {item['count']:>8} "
            f"{item['percent']:5.1f}% {bar}"
        )

    for event in result.blocked_events:
        msg = f"[BLOCKED] {event.src_ip} -> {event.dest_ip} ({event.app}"
        if event.sni:
            msg += f": {event.sni}"
        print(msg + ")")

    if result.detected_domains:
        print("\n[Detected Applications/Domains]")
        for item in result.detected_domains:
            print(f"  - {item['domain']} -> {item['app']}")

    print(f"\nOutput written to: {output_file}")
    return True
