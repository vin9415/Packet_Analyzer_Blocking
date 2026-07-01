#!/usr/bin/env python3
"""Single-threaded DPI engine CLI.

Author: Vinit Kumar Pandey
"""

from __future__ import annotations

import argparse
import sys

from dpi.blocking_rules import BlockingRules
from dpi.engine_simple import run_simple


def print_usage() -> None:
    print(
        """
DPI Engine - Deep Packet Inspection System (Python)
===================================================

Usage: python main_simple.py <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)

Example:
  python main_simple.py capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
"""
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DPI Engine - single-threaded packet inspection",
        add_help=False,
    )
    parser.add_argument("input_pcap")
    parser.add_argument("output_pcap")
    parser.add_argument("--block-ip", action="append", default=[])
    parser.add_argument("--block-app", action="append", default=[])
    parser.add_argument("--block-domain", action="append", default=[])
    parser.add_argument("-h", "--help", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.help or not args.input_pcap or not args.output_pcap:
        print_usage()
        return 1

    rules = BlockingRules()
    for ip in args.block_ip:
        rules.block_ip(ip)
    for app in args.block_app:
        rules.block_app(app)
    for domain in args.block_domain:
        rules.block_domain(domain)

    ok = run_simple(args.input_pcap, args.output_pcap, rules)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
