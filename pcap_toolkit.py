#!/usr/bin/env python3
"""
PCAP extraction toolkit — scapy-based.
pip install scapy --break-system-packages

Covers:
  - DNS exfiltration (subdomain payload extraction)
  - ICMP covert channel payload extraction
  - USB HID keystroke reconstruction from usb.capdata
  - Generic TCP stream reassembly + file-signature scanning
  - Modbus TCP frame parsing (see modbus_toolkit.py for deeper Modbus work)

Run with: python3 pcap_toolkit.py capture.pcap
"""

import sys
import base64
import binascii

try:
    from scapy.all import rdpcap, DNS, DNSQR, ICMP, IP, Raw, TCP
    from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse  # may need scapy contrib
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("    pip install scapy --break-system-packages")
    sys.exit(1)


# ---------------------------------------------------------------------------
# File signature table — check first bytes of any reconstructed blob
# ---------------------------------------------------------------------------

MAGIC_BYTES = {
    b"\x50\x4b\x03\x04": "ZIP",
    b"\x89\x50\x4e\x47": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"\x25\x50\x44\x46": "PDF",
    b"\x7f\x45\x4c\x46": "ELF",
    b"\x4d\x5a": "PE/EXE",
    b"\x1f\x8b": "GZIP",
    b"\x42\x5a\x68": "BZIP2",
    b"\x52\x61\x72\x21": "RAR",
}


def identify_bytes(data: bytes) -> str:
    for sig, name in MAGIC_BYTES.items():
        if data.startswith(sig):
            return name
    return "unknown"


# ---------------------------------------------------------------------------
# DNS exfiltration extraction
# ---------------------------------------------------------------------------

def extract_dns_subdomains(pcap_path: str, base_domain: str = None):
    """
    Pull all queried subdomain labels, in packet order.
    If base_domain given, strips it off; otherwise returns full qname.
    Try concatenating the result and feeding through base64/hex decode.
    """
    packets = rdpcap(pcap_path)
    labels = []
    for pkt in packets:
        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            if base_domain and qname.endswith(base_domain):
                qname = qname[: -len(base_domain)].rstrip(".")
            labels.append(qname)
    return labels


def try_decode_concat(labels: list):
    """Try common decodings on the concatenated label string."""
    joined = "".join(labels)
    print(f"[*] Concatenated ({len(joined)} chars): {joined[:120]}...")

    # base64 attempt
    try:
        padded = joined + "=" * (-len(joined) % 4)
        decoded = base64.b64decode(padded)
        print(f"[+] base64 decode -> signature: {identify_bytes(decoded)}")
        print(f"    preview: {decoded[:60]!r}")
    except Exception:
        pass

    # hex attempt
    try:
        decoded = binascii.unhexlify(joined)
        print(f"[+] hex decode -> signature: {identify_bytes(decoded)}")
        print(f"    preview: {decoded[:60]!r}")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# ICMP covert channel extraction
# ---------------------------------------------------------------------------

def extract_icmp_payloads(pcap_path: str, min_len: int = 1):
    """
    Pull the Raw payload from every ICMP packet, in order.
    Normal ping payloads are usually a fixed repeating pattern (e.g. abcdefg...);
    anything that deviates is worth concatenating and inspecting.
    """
    packets = rdpcap(pcap_path)
    payloads = []
    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
            data = bytes(pkt[Raw].load)
            if len(data) >= min_len:
                payloads.append(data)
    return payloads


def concat_and_identify(payloads: list):
    blob = b"".join(payloads)
    print(f"[*] Concatenated {len(blob)} bytes, signature: {identify_bytes(blob)}")
    print(f"    preview: {blob[:60]!r}")
    return blob


# ---------------------------------------------------------------------------
# USB HID keystroke reconstruction
# ---------------------------------------------------------------------------

# USB HID keyboard usage ID -> character (US layout, no modifier)
HID_KEYCODES = {
    0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e', 0x09: 'f',
    0x0A: 'g', 0x0B: 'h', 0x0C: 'i', 0x0D: 'j', 0x0E: 'k', 0x0F: 'l',
    0x10: 'm', 0x11: 'n', 0x12: 'o', 0x13: 'p', 0x14: 'q', 0x15: 'r',
    0x16: 's', 0x17: 't', 0x18: 'u', 0x19: 'v', 0x1A: 'w', 0x1B: 'x',
    0x1C: 'y', 0x1D: 'z',
    0x1E: '1', 0x1F: '2', 0x20: '3', 0x21: '4', 0x22: '5',
    0x23: '6', 0x24: '7', 0x25: '8', 0x26: '9', 0x27: '0',
    0x28: '\n', 0x2C: ' ', 0x2D: '-', 0x2E: '=',
}

HID_KEYCODES_SHIFT = {
    0x1E: '!', 0x1F: '@', 0x20: '#', 0x21: '$', 0x22: '%',
    0x23: '^', 0x24: '&', 0x25: '*', 0x26: '(', 0x27: ')',
    0x2D: '_', 0x2E: '+',
}


def decode_hid_reports(raw_reports: list):
    """
    raw_reports: list of 8-byte HID reports (bytes objects), as seen in
    usb.capdata for a boot-protocol keyboard.
    Report layout: [modifier, reserved, key1, key2, key3, key4, key5, key6]
    """
    text = []
    for report in raw_reports:
        if len(report) < 3:
            continue
        modifier = report[0]
        shift = bool(modifier & 0x22)  # left or right shift
        keycode = report[2]
        if keycode == 0:
            continue
        if shift and keycode in HID_KEYCODES_SHIFT:
            text.append(HID_KEYCODES_SHIFT[keycode])
        elif keycode in HID_KEYCODES:
            c = HID_KEYCODES[keycode]
            text.append(c.upper() if shift else c)
    return "".join(text)


def extract_usb_hid(pcap_path: str):
    """
    Extract usb.capdata-equivalent payloads. Scapy's USB support is limited —
    if this doesn't find frames, export from Wireshark instead:
      Wireshark -> apply filter usb.capdata -> File > Export Packet Dissections
    or use tshark:
      tshark -r capture.pcap -Y usb.capdata -T fields -e usb.capdata
    """
    packets = rdpcap(pcap_path)
    reports = []
    for pkt in packets:
        if pkt.haslayer(Raw):
            data = bytes(pkt[Raw].load)
            if len(data) == 8:  # boot-protocol HID report size
                reports.append(data)
    return decode_hid_reports(reports)


# ---------------------------------------------------------------------------
# Generic TCP stream reassembly (simple, single-direction)
# ---------------------------------------------------------------------------

def reassemble_tcp_stream(pcap_path: str, port: int):
    """Naive reassembly by sequence number for one TCP port. For anything
    complex, just use Wireshark's Follow TCP Stream instead — it's faster."""
    packets = rdpcap(pcap_path)
    segments = []
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if pkt[TCP].sport == port or pkt[TCP].dport == port:
                segments.append((pkt[TCP].seq, bytes(pkt[Raw].load)))
    segments.sort(key=lambda x: x[0])
    return b"".join(data for _, data in segments)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 pcap_toolkit.py capture.pcap")
        sys.exit(1)
    path = sys.argv[1]

    print("== DNS subdomain scan ==")
    labels = extract_dns_subdomains(path)
    if labels:
        print(f"[*] {len(labels)} query labels found. First 10: {labels[:10]}")
        try_decode_concat(labels)
    else:
        print("[*] No DNS queries found.")

    print("\n== ICMP payload scan ==")
    icmp_payloads = extract_icmp_payloads(path)
    if icmp_payloads:
        print(f"[*] {len(icmp_payloads)} ICMP packets with payload.")
        concat_and_identify(icmp_payloads)
    else:
        print("[*] No ICMP payloads found.")
