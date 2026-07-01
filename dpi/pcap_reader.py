"""PCAP file reader."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

PCAP_MAGIC_NATIVE = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1


@dataclass
class PcapGlobalHeader:
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int


@dataclass
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


@dataclass
class RawPacket:
    header: PcapPacketHeader
    data: bytes = field(default_factory=bytes)


class PcapReader:
    def __init__(self) -> None:
        self._file = None
        self.global_header: PcapGlobalHeader | None = None
        self._needs_byte_swap = False
        self._endian = "<"

    def open(self, filename: str | Path, quiet: bool = False) -> bool:
        self.close()
        path = Path(filename)
        try:
            self._file = path.open("rb")
        except OSError:
            print(f"Error: Could not open file: {filename}")
            return False

        header_data = self._file.read(24)
        if len(header_data) < 24:
            print("Error: Could not read PCAP global header")
            self.close()
            return False

        magic = struct.unpack_from("<I", header_data, 0)[0]
        if magic == PCAP_MAGIC_NATIVE:
            self._needs_byte_swap = False
            self._endian = "<"
        elif magic == PCAP_MAGIC_SWAPPED:
            self._needs_byte_swap = True
            self._endian = ">"
        else:
            print(f"Error: Invalid PCAP magic number: 0x{magic:08x}")
            self.close()
            return False

        (
            _magic,
            version_major,
            version_minor,
            thiszone,
            sigfigs,
            snaplen,
            network,
        ) = struct.unpack(f"{self._endian}IHHIIII", header_data)

        self.global_header = PcapGlobalHeader(
            magic_number=magic,
            version_major=version_major,
            version_minor=version_minor,
            thiszone=thiszone,
            sigfigs=sigfigs,
            snaplen=snaplen,
            network=network,
        )

        if not quiet:
            print(f"Opened PCAP file: {filename}")
            print(f"  Version: {version_major}.{version_minor}")
            print(f"  Snaplen: {snaplen} bytes")
            link = " (Ethernet)" if network == 1 else ""
            print(f"  Link type: {network}{link}")
        return True

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
        self._needs_byte_swap = False
        self.global_header = None

    def is_open(self) -> bool:
        return self._file is not None

    def read_next_packet(self) -> RawPacket | None:
        if self._file is None or self.global_header is None:
            return None

        header_data = self._file.read(16)
        if not header_data:
            return None
        if len(header_data) < 16:
            return None

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            f"{self._endian}IIII", header_data
        )

        if incl_len > self.global_header.snaplen or incl_len > 65535:
            print(f"Error: Invalid packet length: {incl_len}")
            return None

        data = self._file.read(incl_len)
        if len(data) < incl_len:
            print("Error: Could not read packet data")
            return None

        return RawPacket(
            header=PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len),
            data=data,
        )

    def get_global_header_bytes(self) -> bytes:
        if self.global_header is None:
            raise RuntimeError("PCAP file is not open")
        gh = self.global_header
        return struct.pack(
            f"{self._endian}IHHIIII",
            gh.magic_number if not self._needs_byte_swap else PCAP_MAGIC_SWAPPED,
            gh.version_major,
            gh.version_minor,
            gh.thiszone,
            gh.sigfigs,
            gh.snaplen,
            gh.network,
        )
