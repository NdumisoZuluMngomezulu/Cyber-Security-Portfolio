#!/usr/bin/env python3
"""
Raw-socket packet sniffer for Linux.

Captures live traffic off a network interface and manually decodes:
  Ethernet (Layer 2) -> IPv4 (Layer 3) -> TCP / UDP / ICMP (Layer 4)

No third-party libraries. Everything is unpacked from raw bytes using
the `struct` module, so you see exactly how each header is laid out.

MUST be run as root (raw sockets require elevated privileges):
    sudo python3 packet_sniffer.py

Only run this on networks / machines you own or have explicit
permission to monitor.
"""

import socket
import struct
import textwrap
from datetime import datetime
from collections import defaultdict, deque

# ---------------------------------------------------------------------------
# Simple in-memory state for a basic security heuristic: SYN scan detection.
# We track recent SYN packets (no matching ACK) per source IP.
# ---------------------------------------------------------------------------
SYN_TRACKER = defaultdict(lambda: deque(maxlen=50))
SYN_SCAN_THRESHOLD = 15     # SYNs to more than this many distinct ports...
SYN_SCAN_WINDOW_SEC = 5     # ...within this many seconds triggers an alert


def format_mac(raw_bytes):
    """Convert 6 raw bytes into human-readable MAC address string."""
    return ':'.join('%02x' % b for b in raw_bytes).upper()


def format_ip(raw_bytes):
    """Convert 4 raw bytes into dotted-quad IPv4 string."""
    return '.'.join(map(str, raw_bytes))


def unpack_ethernet_frame(data):
    """
    Ethernet II header is the first 14 bytes:
        6 bytes  destination MAC
        6 bytes  source MAC
        2 bytes  EtherType (what protocol comes next, e.g. 0x0800 = IPv4)
    '!6s6sH' = network byte order, 6-byte string, 6-byte string, unsigned short
    """
    dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    payload = data[14:]
    return format_mac(dest_mac), format_mac(src_mac), socket.htons(ethertype), payload


def unpack_ipv4_header(data):
    """
    IPv4 header (minimum 20 bytes, no options):

        Byte 0:      version (4 bits) + IHL/header length (4 bits)
        Byte 1:      DSCP/ECN (type of service)
        Bytes 2-3:   total length
        Bytes 4-5:   identification
        Bytes 6-7:   flags (3 bits) + fragment offset (13 bits)
        Byte 8:      TTL
        Byte 9:      protocol (1=ICMP, 6=TCP, 17=UDP)
        Bytes 10-11: header checksum
        Bytes 12-15: source IP
        Bytes 16-19: destination IP
    """
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4  # IHL is in 32-bit words -> multiply by 4 for bytes

    ttl, proto, src, dst = struct.unpack('!8xBB2x4s4s', data[:20])
    src_ip = format_ip(src)
    dst_ip = format_ip(dst)

    payload = data[ihl:]
    return version, ihl, ttl, proto, src_ip, dst_ip, payload


def unpack_tcp_segment(data):
    """
    TCP header (minimum 20 bytes, no options):

        Bytes 0-1:   source port
        Bytes 2-3:   destination port
        Bytes 4-7:   sequence number
        Bytes 8-11:  acknowledgment number
        Byte 12:     data offset (4 bits) + reserved (4 bits)
        Byte 13:     flags (CWR ECE URG ACK PSH RST SYN FIN)
        Bytes 14-15: window size
        Bytes 16-17: checksum
        Bytes 18-19: urgent pointer
    """
    (src_port, dst_port, seq, ack, offset_reserved, flags,
     window) = struct.unpack('!HHLLBBH', data[:16])

    data_offset = (offset_reserved >> 4) * 4

    flag_bits = {
        'URG': (flags & 0x20) >> 5,
        'ACK': (flags & 0x10) >> 4,
        'PSH': (flags & 0x08) >> 3,
        'RST': (flags & 0x04) >> 2,
        'SYN': (flags & 0x02) >> 1,
        'FIN': (flags & 0x01),
    }

    payload = data[data_offset:]
    return src_port, dst_port, seq, ack, flag_bits, payload


def unpack_udp_segment(data):
    """
    UDP header is fixed at 8 bytes -- much simpler than TCP:
        Bytes 0-1: source port
        Bytes 2-3: destination port
        Bytes 4-5: length (header + data)
        Bytes 6-7: checksum
    """
    src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])
    payload = data[8:]
    return src_port, dst_port, length, payload


def unpack_icmp_packet(data):
    """
    ICMP header (first 4 bytes are common to all ICMP messages):
        Byte 0:    type (8 = echo request/ping, 0 = echo reply, etc.)
        Byte 1:    code
        Bytes 2-3: checksum
    """
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    payload = data[4:]
    return icmp_type, code, payload


def format_payload_preview(data, max_bytes=48):
    """Show a short, safe preview of raw payload bytes as hex + ASCII."""
    snippet = data[:max_bytes]
    hexdump = ' '.join(f'{b:02x}' for b in snippet)
    ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in snippet)
    return hexdump, ascii_repr


def check_syn_scan(src_ip, dst_port, flags):
    """
    Very lightweight heuristic: if one source IP sends SYN packets (no ACK)
    to many distinct destination ports in a short window, flag it as a
    possible port scan. Real IDS tools (e.g. Snort/Zeek) do this with far
    more nuance -- this is a teaching-scale version of the same idea.
    """
    if not (flags['SYN'] == 1 and flags['ACK'] == 0):
        return None

    now = datetime.now()
    tracker = SYN_TRACKER[src_ip]
    tracker.append((now, dst_port))

    # Drop entries outside the time window
    while tracker and (now - tracker[0][0]).total_seconds() > SYN_SCAN_WINDOW_SEC:
        tracker.popleft()

    distinct_ports = {port for _, port in tracker}
    if len(distinct_ports) > SYN_SCAN_THRESHOLD:
        return f"[ALERT] Possible SYN port scan from {src_ip}: " \
               f"{len(distinct_ports)} distinct ports in {SYN_SCAN_WINDOW_SEC}s"
    return None


def main():
    # AF_PACKET + SOCK_RAW gives us full Ethernet frames on Linux.
    # ETH_P_ALL (0x0003) means "capture every EtherType", not just IP.
    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("ERROR: This script needs root privileges. Run with: sudo python3 packet_sniffer.py")
        return
    except AttributeError:
        print("ERROR: AF_PACKET raw sockets are Linux-only. "
              "On macOS/Windows, use scapy instead (see notes below).")
        return

    print("Packet sniffer running. Press Ctrl+C to stop.\n")

    packet_count = 0
    try:
        while True:
            raw_data, _ = sniffer.recvfrom(65535)
            packet_count += 1

            dest_mac, src_mac, eth_proto, eth_payload = unpack_ethernet_frame(raw_data)

            print(f"\n{'='*70}")
            print(f"Packet #{packet_count}  |  {datetime.now().strftime('%H:%M:%S.%f')}")
            print(f"Ethernet:  {src_mac} -> {dest_mac}  (EtherType: {hex(eth_proto)})")

            # 0x0800 = IPv4
            if eth_proto == 0x0800:
                (version, ihl, ttl, proto, src_ip, dst_ip,
                 ip_payload) = unpack_ipv4_header(eth_payload)

                print(f"IPv4:      {src_ip} -> {dst_ip}  "
                      f"(TTL={ttl}, header_len={ihl}B, protocol={proto})")

                if proto == 6:  # TCP
                    (src_port, dst_port, seq, ack, flags,
                     tcp_payload) = unpack_tcp_segment(ip_payload)

                    active_flags = ','.join(f for f, v in flags.items() if v)
                    print(f"TCP:       {src_ip}:{src_port} -> {dst_ip}:{dst_port}  "
                          f"[{active_flags}]  seq={seq} ack={ack}")

                    alert = check_syn_scan(src_ip, dst_port, flags)
                    if alert:
                        print(alert)

                    if tcp_payload:
                        hexdump, ascii_repr = format_payload_preview(tcp_payload)
                        print(f"Payload:   {hexdump}")
                        print(f"           {ascii_repr}")

                elif proto == 17:  # UDP
                    (src_port, dst_port, length,
                     udp_payload) = unpack_udp_segment(ip_payload)

                    print(f"UDP:       {src_ip}:{src_port} -> {dst_ip}:{dst_port}  "
                          f"(length={length})")

                    if udp_payload:
                        hexdump, ascii_repr = format_payload_preview(udp_payload)
                        print(f"Payload:   {hexdump}")
                        print(f"           {ascii_repr}")

                elif proto == 1:  # ICMP
                    icmp_type, code, icmp_payload = unpack_icmp_packet(ip_payload)
                    kind = {8: "Echo Request (ping)", 0: "Echo Reply (pong)"}.get(icmp_type, f"type={icmp_type}")
                    print(f"ICMP:      {src_ip} -> {dst_ip}  {kind} (code={code})")

                else:
                    print(f"IP payload: protocol {proto} not decoded (raw only)")

            # 0x0806 = ARP
            elif eth_proto == 0x0806:
                print("ARP packet (not decoded in this version)")

            else:
                print(f"Non-IPv4 EtherType {hex(eth_proto)} (not decoded)")

    except KeyboardInterrupt:
        print(f"\n\nStopped. Captured {packet_count} packets.")


if __name__ == '__main__':
    main()