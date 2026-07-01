"""TLS SNI, HTTP Host, and DNS query extraction."""

from __future__ import annotations

CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
EXTENSION_SNI = 0x0000
SNI_TYPE_HOSTNAME = 0x00


def _read_uint16_be(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _read_uint24_be(data: bytes, offset: int) -> int:
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def is_tls_client_hello(payload: bytes) -> bool:
    if len(payload) < 9:
        return False
    if payload[0] != CONTENT_TYPE_HANDSHAKE:
        return False
    version = _read_uint16_be(payload, 1)
    if version < 0x0300 or version > 0x0304:
        return False
    record_length = _read_uint16_be(payload, 3)
    if record_length > len(payload) - 5:
        return False
    if payload[5] != HANDSHAKE_CLIENT_HELLO:
        return False
    return True


def extract_sni(payload: bytes) -> str | None:
    if not is_tls_client_hello(payload):
        return None

    offset = 5
    offset += 4  # handshake header
    offset += 2  # client version
    offset += 32  # random

    if offset >= len(payload):
        return None
    session_id_length = payload[offset]
    offset += 1 + session_id_length

    if offset + 2 > len(payload):
        return None
    cipher_suites_length = _read_uint16_be(payload, offset)
    offset += 2 + cipher_suites_length

    if offset >= len(payload):
        return None
    compression_methods_length = payload[offset]
    offset += 1 + compression_methods_length

    if offset + 2 > len(payload):
        return None
    extensions_length = _read_uint16_be(payload, offset)
    offset += 2
    extensions_end = min(offset + extensions_length, len(payload))

    while offset + 4 <= extensions_end:
        extension_type = _read_uint16_be(payload, offset)
        extension_length = _read_uint16_be(payload, offset + 2)
        offset += 4

        if offset + extension_length > extensions_end:
            break

        if extension_type == EXTENSION_SNI:
            if extension_length < 5:
                break
            sni_length = _read_uint16_be(payload, offset + 3)
            sni_type = payload[offset + 2]
            if sni_type != SNI_TYPE_HOSTNAME:
                break
            if sni_length > extension_length - 5:
                break
            return payload[offset + 5 : offset + 5 + sni_length].decode(
                "ascii", errors="replace"
            )

        offset += extension_length

    return None


def is_http_request(payload: bytes) -> bool:
    if len(payload) < 4:
        return False
    methods = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")
    return any(payload[:4] == method for method in methods)


def extract_http_host(payload: bytes) -> str | None:
    if not is_http_request(payload):
        return None

    text = payload.decode("latin-1", errors="replace")
    for i, line in enumerate(text.split("\r\n")):
        if i == 0:
            continue
        if line.lower().startswith("host:"):
            host = line[5:].strip()
            if ":" in host:
                host = host.split(":", 1)[0]
            return host or None
    return None


def is_dns_query(payload: bytes) -> bool:
    if len(payload) < 12:
        return False
    if payload[2] & 0x80:
        return False
    qdcount = _read_uint16_be(payload, 4)
    return qdcount > 0


def extract_dns_query(payload: bytes) -> str | None:
    if not is_dns_query(payload):
        return None

    offset = 12
    labels: list[str] = []
    while offset < len(payload):
        label_length = payload[offset]
        if label_length == 0:
            break
        if label_length > 63:
            break
        offset += 1
        if offset + label_length > len(payload):
            break
        labels.append(payload[offset : offset + label_length].decode("ascii", errors="replace"))
        offset += label_length

    return ".".join(labels) if labels else None


def is_quic_initial(payload: bytes) -> bool:
    if len(payload) < 5:
        return False
    return (payload[0] & 0x80) != 0


def extract_quic_sni(payload: bytes) -> str | None:
    if not is_quic_initial(payload):
        return None
    for i in range(len(payload) - 50):
        if payload[i] == HANDSHAKE_CLIENT_HELLO:
            start = max(0, i - 5)
            result = extract_sni(payload[start:])
            if result:
                return result
    return None
