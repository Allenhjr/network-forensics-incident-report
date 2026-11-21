"""Write a deterministic simulated Ethernet/IPv4 PCAP without network I/O."""
import argparse
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
import struct

START = int(datetime.fromisoformat("2026-11-20T14:00:00+00:00").timestamp())
WORKSTATION = "192.0.2.25"
RESOLVER = "192.0.2.53"
PORTAL = "198.51.100.80"
TEST_SERVER = "203.0.113.40"
MACS = {
    WORKSTATION: bytes.fromhex("020000000025"),
    RESOLVER: bytes.fromhex("020000000053"),
    PORTAL: bytes.fromhex("020000000080"),
    TEST_SERVER: bytes.fromhex("020000000040"),
}


def checksum(data):
    """Compute the Internet checksum for IPv4 and transport headers."""
    if len(data) % 2:
        data += b"\0"
    total = sum(word for (word,) in struct.iter_unpack("!H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class Capture:
    def __init__(self):
        self.frames = []

    def add(self, ms, src, dst, protocol, segment, checksum_offset):
        addresses = IPv4Address(src).packed + IPv4Address(dst).packed
        pseudo_header = addresses + struct.pack("!BBH", 0, protocol, len(segment))
        value = checksum(pseudo_header + segment) or (0xFFFF if protocol == 17 else 0)
        segment = (segment[:checksum_offset] + struct.pack("!H", value)
                   + segment[checksum_offset + 2:])
        ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(segment),
                         len(self.frames) + 1, 0x4000, 64, protocol, 0) + addresses
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        frame = MACS[dst] + MACS[src] + b"\x08\x00" + ip + segment
        self.frames.append((ms, frame.ljust(60, b"\0")))

    def udp(self, ms, src, dst, sport, dport, payload):
        header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
        self.add(ms, src, dst, 17, header + payload, 6)

    def tcp(self, ms, src, dst, sport, dport, seq, ack, flags, payload):
        header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                             0x50, flags, 64240, 0, 0)
        self.add(ms, src, dst, 6, header + payload, 16)

    def write(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as output:
            output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ms, frame in sorted(self.frames, key=lambda entry: entry[0]):
                seconds, milliseconds = divmod(ms, 1000)
                output.write(struct.pack("<IIII", START + seconds, milliseconds * 1000,
                                         len(frame), len(frame)))
                output.write(frame)


def dns_exchange(capture, ms, transaction, host, answer):
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in host.split("."))
    question = labels + b"\0" + struct.pack("!HH", 1, 1)
    query = struct.pack("!6H", transaction, 0x0100, 1, 0, 0, 0) + question
    response = struct.pack("!6H", transaction, 0x8180, 1, 1, 0, 0) + question
    response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + IPv4Address(answer).packed
    port = 53000 + transaction
    capture.udp(ms, WORKSTATION, RESOLVER, port, 53, query)
    capture.udp(ms + 25, RESOLVER, WORKSTATION, 53, port, response)


def http_exchange(capture, ms, server, port, host, path):
    request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii")
    body = b"Simulated lab response\n"
    response = (f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode("ascii") + body
    client_seq = 100_000 + port * 10
    server_seq = 800_000 + port * 10
    client_end = client_seq + 1 + len(request)
    server_end = server_seq + 1 + len(response)

    def client(offset, seq, ack, flags, payload=b""):
        capture.tcp(ms + offset, WORKSTATION, server, port, 80, seq, ack, flags, payload)

    def reply(offset, seq, ack, flags, payload=b""):
        capture.tcp(ms + offset, server, WORKSTATION, 80, port, seq, ack, flags, payload)

    client(0, client_seq, 0, 0x02)                       # SYN
    reply(20, server_seq, client_seq + 1, 0x12)           # SYN/ACK
    client(40, client_seq + 1, server_seq + 1, 0x10)     # ACK
    client(60, client_seq + 1, server_seq + 1, 0x18, request)
    reply(90, server_seq + 1, client_end, 0x18, response)
    reply(110, server_end, client_end, 0x11)              # FIN/ACK
    client(130, client_end, server_end + 1, 0x11)         # FIN/ACK
    reply(150, server_end + 1, client_end + 1, 0x10)      # ACK


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("data/simulated-lab.pcap"))
    args = parser.parse_args()
    capture = Capture()
    dns_exchange(capture, 1000, 1, "portal.lab.test", PORTAL)
    dns_exchange(capture, 4000, 2, "status.lab.test", TEST_SERVER)
    for index, second in enumerate((8, 47, 83, 170)):
        http_exchange(capture, second * 1000, PORTAL, 41000 + index,
                      "portal.lab.test", "/welcome")
    for index, second in enumerate((15, 45, 75, 105, 135, 165)):
        http_exchange(capture, second * 1000, TEST_SERVER, 42000 + index,
                      "status.lab.test", "/status")
    capture.write(args.output)
    print(f"Wrote {len(capture.frames)} simulated packets to {args.output}")


if __name__ == "__main__":
    main()
