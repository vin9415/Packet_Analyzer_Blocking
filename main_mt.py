#!/usr/bin/env python3
"""Multi-threaded DPI engine CLI.

Author: Vinit Kumar Pandey
"""

from __future__ import annotations

import argparse
import sys

from dpi.engine_mt import DPIEngine, EngineConfig


def print_usage() -> None:
    print(
        """
DPI Engine v2.0 - Multi-threaded Deep Packet Inspection (Python)
================================================================

Usage: python main_mt.py <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)

Example:
  python main_mt.py capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
"""
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DPI Engine - multi-threaded packet inspection",
        add_help=False,
    )
    parser.add_argument("input_pcap")
    parser.add_argument("output_pcap")
    parser.add_argument("--block-ip", action="append", default=[])
    parser.add_argument("--block-app", action="append", default=[])
    parser.add_argument("--block-domain", action="append", default=[])
    parser.add_argument("--lbs", type=int, default=2)
    parser.add_argument("--fps", type=int, default=2)
    parser.add_argument("-h", "--help", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.help or not args.input_pcap or not args.output_pcap:
        print_usage()
        return 1

    engine = DPIEngine(EngineConfig(num_lbs=args.lbs, fps_per_lb=args.fps))

    for ip in args.block_ip:
        engine.block_ip(ip)
    for app in args.block_app:
        engine.block_app(app)
    for domain in args.block_domain:
        engine.block_domain(domain)

    ok = engine.process(args.input_pcap, args.output_pcap)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
