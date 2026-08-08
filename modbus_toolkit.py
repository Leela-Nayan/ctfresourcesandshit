#!/usr/bin/env python3
"""
Modbus TCP parser for OT/ICS forensics challenges.
Pure Python — parses raw TCP payload bytes, no scapy contrib dependency
(useful if scapy.contrib.modbus isn't available on the comp machine).

Modbus TCP frame layout:
  MBAP header (7 bytes):
    Transaction ID   (2 bytes)
    Protocol ID      (2 bytes, always 0x0000)
    Length           (2 bytes)
    Unit ID          (1 byte)
  PDU:
    Function code    (1 byte)
    Data             (variable)

Usage:
    from modbus_toolkit import parse_modbus_frame, extract_modbus_from_pcap
    frames = extract_modbus_from_pcap("capture.pcap")
    for f in frames:
        print(parse_modbus_frame(f))
"""

import struct
import sys

FUNCTION_CODES = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
}


def parse_modbus_frame(data: bytes):
    """Parse a single Modbus TCP frame (MBAP + PDU) from raw bytes."""
    if len(data) < 8:
        return None
    transaction_id, protocol_id, length, unit_id, function_code = struct.unpack(
        ">HHHBB", data[:8]
    )
    if protocol_id != 0:
        return None  # not Modbus
    payload = data[8:8 + (length - 2)] if length >= 2 else b""

    result = {
        "transaction_id": transaction_id,
        "unit_id": unit_id,
        "function_code": function_code,
        "function_name": FUNCTION_CODES.get(function_code, f"unknown(0x{function_code:02x})"),
        "raw_payload": payload,
    }

    # Decode common cases
    if function_code in (0x03, 0x04) and len(payload) >= 4:
        # Request form: start_addr(2) + quantity(2)
        # Response form: byte_count(1) + values...
        if len(payload) == 4:
            addr, qty = struct.unpack(">HH", payload)
            result["start_address"] = addr
            result["quantity"] = qty
        else:
            byte_count = payload[0]
            values = payload[1:1 + byte_count]
            regs = [struct.unpack(">H", values[i:i+2])[0] for i in range(0, len(values) - 1, 2)]
            result["register_values"] = regs

    elif function_code == 0x06 and len(payload) == 4:
        addr, value = struct.unpack(">HH", payload)
        result["address"] = addr
        result["value"] = value

    elif function_code == 0x10 and len(payload) >= 5:
        addr, qty, byte_count = struct.unpack(">HHB", payload[:5])
        values = payload[5:5 + byte_count]
        regs = [struct.unpack(">H", values[i:i+2])[0] for i in range(0, len(values) - 1, 2)]
        result["start_address"] = addr
        result["quantity"] = qty
        result["register_values"] = regs

    elif function_code == 0x05 and len(payload) == 4:
        addr, value = struct.unpack(">HH", payload)
        result["address"] = addr
        result["value_raw"] = value  # 0xFF00 = ON, 0x0000 = OFF

    return result


def extract_modbus_from_pcap(pcap_path: str, tcp_port: int = 502):
    """Requires scapy. Pulls raw TCP payloads on the Modbus port and parses each."""
    from scapy.all import rdpcap, TCP, Raw

    packets = rdpcap(pcap_path)
    frames = []
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if pkt[TCP].sport == tcp_port or pkt[TCP].dport == tcp_port:
                parsed = parse_modbus_frame(bytes(pkt[Raw].load))
                if parsed:
                    frames.append(parsed)
    return frames


def registers_to_ascii(values: list) -> str:
    """Convert a list of 16-bit register values to ASCII (2 chars each, big-endian)."""
    chars = []
    for v in values:
        hi, lo = (v >> 8) & 0xFF, v & 0xFF
        if 32 <= hi < 127:
            chars.append(chr(hi))
        if 32 <= lo < 127:
            chars.append(chr(lo))
    return "".join(chars)


def addresses_to_ascii(addresses: list) -> str:
    """If the flag is hidden in register ADDRESSES rather than values —
    treat each address as a raw ASCII code point."""
    return "".join(chr(a) for a in addresses if 32 <= a < 127)


def coils_to_ascii(coil_bits: list) -> str:
    """Convert a list of 0/1 coil states (MSB first, 8 per byte) to ASCII."""
    chars = []
    for i in range(0, len(coil_bits) - 7, 8):
        byte = 0
        for bit in coil_bits[i:i+8]:
            byte = (byte << 1) | bit
        if 32 <= byte < 127:
            chars.append(chr(byte))
    return "".join(chars)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 modbus_toolkit.py capture.pcap")
        sys.exit(1)

    frames = extract_modbus_from_pcap(sys.argv[1])
    print(f"[*] {len(frames)} Modbus frames found.\n")

    all_values = []
    all_addresses = []

    for f in frames:
        print(f"txn={f['transaction_id']} unit={f['unit_id']} "
              f"fc={f['function_code']:#04x} ({f['function_name']})", end="")
        if "start_address" in f:
            print(f" addr={f['start_address']}", end="")
            all_addresses.append(f["start_address"])
        if "address" in f:
            print(f" addr={f['address']}", end="")
            all_addresses.append(f["address"])
        if "register_values" in f:
            print(f" values={f['register_values']}", end="")
            all_values.extend(f["register_values"])
        if "value" in f:
            print(f" value={f['value']}", end="")
        print()

    print("\n[*] Try reading values as ASCII first:")
    print("   ", registers_to_ascii(all_values))
    print("[*] If that's garbage, try addresses as ASCII:")
    print("   ", addresses_to_ascii(all_addresses))
