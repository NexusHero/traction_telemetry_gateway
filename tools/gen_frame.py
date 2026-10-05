#!/usr/bin/env python3
"""Generate a valid TTB frame on stdout (binary) for smoke-testing the gateway.

Usage:
  python3 tools/gen_frame.py > /tmp/frame.bin
  curl --data-binary @/tmp/frame.bin http://localhost:8080/v1/frames

The wire format is documented in include/ttg/frame.hpp. This tool exists so
that a frame can be produced without linking against the C++ library.
"""
import struct
import sys

MAGIC = 0x5454
VERSION = 1
MSG_TELEMETRY = 1
POLY = 0x1021


def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ POLY) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def channel_int(channel_id: int, value: int) -> bytes:
    # >HBBi : id (u16), value_type=0 (int32), reserved, int32 value
    return struct.pack(">HBBi", channel_id, 0, 0, value)


def channel_float(channel_id: int, value: float) -> bytes:
    # >HBBf : id (u16), value_type=1 (float32), reserved, float32 value
    return struct.pack(">HBBf", channel_id, 1, 0, value)


def build_frame(sequence: int, timestamp_ms: int, channels: list[bytes]) -> bytes:
    payload = b"".join(channels)
    head = struct.pack(">HBB", MAGIC, VERSION, MSG_TELEMETRY)
    head += struct.pack(">IQ", sequence, timestamp_ms)
    head += struct.pack(">H", len(payload))
    body = head + payload
    return body + struct.pack(">H", crc16_ccitt(body))


def main() -> int:
    sequence = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    channels = [
        channel_int(0x0001, 1500),          # e.g. motor speed
        channel_int(0x0002, 42),            # e.g. temperature
        channel_float(0x0003, 3.75),        # e.g. torque
    ]
    sys.stdout.buffer.write(build_frame(sequence, 1_700_000_000_000, channels))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
