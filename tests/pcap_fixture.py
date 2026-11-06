"""仅供软件测试的合成包：文档保留地址，不产生网络通信。"""
import socket
import struct
from pathlib import Path


def frame(src="192.0.2.1", dst="198.51.100.2", sport=12345, dport=443,
          protocol=6, ipv6=False):
    if protocol == 6:
        payload = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 2, 8192, 0, 0)
    elif protocol == 17:
        payload = struct.pack("!HHHH", sport, dport, 8, 0)
    else:
        payload = b"\x08\x00\x00\x00\x00\x00\x00\x00"
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    addresses = socket.inet_pton(family, src) + socket.inet_pton(family, dst)
    if ipv6:
        network = struct.pack("!IHBB", 6 << 28, len(payload), protocol, 64) + addresses
    else:
        network = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), 0, 0, 64, protocol, 0) + addresses
    return bytes.fromhex("00112233445566778899aabb") + struct.pack("!H", 0x86dd if ipv6 else 0x0800) + network + payload


def write_pcap(path: Path, records=None, endian="<", nano=False, linktype=1):
    if records is None:
        records = [(1700000000, 0, frame()), (1700000001, 0, frame(
            "198.51.100.2", "192.0.2.1", 443, 12345))]
    with path.open("wb") as stream:
        stream.write(struct.pack(endian + "IHHIIII", 0xa1b23c4d if nano else 0xa1b2c3d4,
                                 2, 4, 0, 0, 65535, linktype))
        for seconds, fraction, payload in records:
            stream.write(struct.pack(endian + "IIII", seconds, fraction, len(payload), len(payload)))
            stream.write(payload)
    return path
