#!/usr/bin/env python3
"""
fuzz_packet_parser.py — Extreme Packet Parser Fuzzing Test Harness

Generates malformed TCP, UDP, ICMP, fragmented packets, and corrupt checksums
to fuzz the firewall's packet parser and rule evaluation pipeline under ASan.

Can run with Scapy (if installed) or with built-in pure Python raw packet generator.
"""

import sys
import socket
import struct
import random
import time

def checksum(data: bytes) -> int:
    """Standard internet checksum calculation."""
    if len(data) % 2 != 0:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def generate_malformed_ip_packet() -> bytes:
    """Generate randomized malformed IPv4 packets."""
    # Base IPv4 header fields
    version = random.choice([4, 6, 0, 15])  # corrupt IP version
    ihl = random.choice([0, 1, 4, 5, 15])    # corrupt IHL (<5 is illegal)
    tos = random.randint(0, 255)
    tot_len = random.choice([0, 10, 20, 1500, 65535, random.randint(1, 100)])
    ident = random.randint(0, 65535)
    flags_offset = random.choice([
        0x2000,          # MF (More Fragments) set
        0x2001,          # MF + fragment offset 8
        0x1FFF,          # illegal high fragment offset
        0x0000,
        random.randint(0, 65535)
    ])
    ttl = random.randint(0, 255)
    proto = random.choice([6, 17, 1, 255, 0, random.randint(0, 255)]) # TCP, UDP, ICMP, corrupt
    chk = random.choice([0, 0xFFFF, random.randint(0, 65535)]) # corrupt checksum

    src_ip = socket.inet_aton(f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
    dst_ip = socket.inet_aton("127.0.0.1")

    ver_ihl = (version << 4) | (ihl & 0x0F)
    hdr = struct.pack('!BBHHHBBH4s4s',
                      ver_ihl, tos, tot_len, ident, flags_offset, ttl, proto, chk, src_ip, dst_ip)

    # Corrupt payload: random lengths, truncated, or garbage
    payload_len = random.choice([0, 4, 8, 16, 20, 64, 512, random.randint(0, 1500)])
    payload = bytes(random.getrandbits(8) for _ in range(payload_len))
    return hdr + payload

def generate_malformed_tcp_packet() -> bytes:
    """Generate malformed TCP segment over valid or malformed IP header."""
    src_port = random.randint(0, 65535)
    dst_port = random.choice([80, 443, 8080, 22, 53, random.randint(0, 65535)])
    seq = random.randint(0, 0xFFFFFFFF)
    ack = random.randint(0, 0xFFFFFFFF)
    # Corrupt data offset (< 5 is illegal)
    data_offset = random.choice([0, 1, 4, 5, 15]) << 4
    flags = random.choice([
        0x02,             # SYN
        0x03,             # SYN + FIN (illegal combination)
        0x07,             # SYN + FIN + RST (illegal combination)
        0x00,             # NULL scan (no flags)
        0x3F,             # XMAS scan (FIN + PSH + URG + ...)
        random.randint(0, 255)
    ])
    window = random.randint(0, 65535)
    chk = random.randint(0, 65535)
    urg_ptr = random.randint(0, 65535)

    tcp_hdr = struct.pack('!HHLLBBHHH',
                          src_port, dst_port, seq, ack, data_offset, flags, window, chk, urg_ptr)

    # Random TCP options or malformed options
    opts = bytes(random.getrandbits(8) for _ in range(random.choice([0, 4, 12, 40])))
    payload = bytes(random.getrandbits(8) for _ in range(random.randint(0, 256)))
    tcp_seg = tcp_hdr + opts + payload

    # Wrap in IP header
    ip_hdr = struct.pack('!BBHHHBBH4s4s',
                         0x45, 0, 20 + len(tcp_seg), random.randint(0, 65535),
                         0, 64, 6, 0,
                         socket.inet_aton("192.168.1.100"), socket.inet_aton("127.0.0.1"))
    return ip_hdr + tcp_seg

def generate_malformed_udp_packet() -> bytes:
    """Generate malformed UDP packet with length mismatch or corrupt payload."""
    src_port = random.randint(0, 65535)
    dst_port = random.choice([53, 9000, 123, 161, random.randint(0, 65535)])
    # UDP length field < 8 is illegal, or mismatch actual payload size
    udp_len = random.choice([0, 1, 7, 8, 100, 65535, random.randint(0, 1000)])
    chk = random.randint(0, 65535)

    udp_hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, chk)
    payload = bytes(random.getrandbits(8) for _ in range(random.randint(0, 256)))
    udp_pkt = udp_hdr + payload

    ip_hdr = struct.pack('!BBHHHBBH4s4s',
                         0x45, 0, 20 + len(udp_pkt), random.randint(0, 65535),
                         0, 64, 17, 0,
                         socket.inet_aton("10.0.0.5"), socket.inet_aton("127.0.0.1"))
    return ip_hdr + udp_pkt

def run_fuzzer(target_host: str = "127.0.0.1", target_port: int = 9000, count: int = 10000):
    print("==========================================================")
    print(f" Starting Extreme Packet Fuzzer against {target_host}:{target_port}")
    print(f" Total generated packets: {count}")
    print(" Target: Parser robustness, fragment handling, ASan checks")
    print("==========================================================")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)

    start_time = time.time()
    for i in range(1, count + 1):
        gen = random.choice([
            generate_malformed_ip_packet,
            generate_malformed_tcp_packet,
            generate_malformed_udp_packet
        ])
        pkt = gen()
        try:
            sock.sendto(pkt, (target_host, target_port))
        except OSError:
            pass  # Expected if OS socket layer drops bad headers locally

        if i % 1000 == 0:
            elapsed = time.time() - start_time
            rate = i / elapsed if elapsed > 0 else 0
            print(f"[*] Fuzz progress: {i}/{count} packets dispatched ({rate:.1f} pkts/sec)...")

    elapsed = time.time() - start_time
    print("==========================================================")
    print(f"[+] Completed {count} fuzzed packets in {elapsed:.2f} seconds.")
    print("[+] If running under ASan, verify stderr has 0 error reports.")
    print("==========================================================")

if __name__ == "__main__":
    count = 5000
    if len(sys.argv) > 1:
        try:
            count = int(sys.argv[1])
        except ValueError:
            pass
    run_fuzzer(count=count)
