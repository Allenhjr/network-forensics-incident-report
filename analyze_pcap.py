"""Read the simulated lab's Ethernet/IPv4 classic PCAP and export a timeline."""
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from pathlib import Path
from statistics import median
import struct

MIN_CONNECTIONS = 4
TOLERANCE_US = 1_000_000
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
FIELDS = ("packet", "timestamp_utc", "src_ip", "dst_ip", "protocol",
          "src_port", "dst_port", "event", "detail", "regular_connection")


def utc(timestamp_us):
    return (EPOCH + timedelta(microseconds=timestamp_us)).isoformat(
        timespec="microseconds").replace("+00:00", "Z")


def read_pcap(path):
    with path.open("rb") as capture:
        header = capture.read(24)
        if len(header) != 24 or header[:4] != b"\xd4\xc3\xb2\xa1":
            raise ValueError("Expected little-endian, microsecond-resolution classic PCAP")
        _, major, minor, _, _, snaplen, linktype = struct.unpack("<IHHIIII", header)
        if (major, minor, linktype) != (2, 4, 1):
            raise ValueError("Expected PCAP version 2.4 with Ethernet link type")
        number = 0
        while record := capture.read(16):
            if len(record) != 16:
                raise ValueError("Truncated PCAP record header")
            seconds, micros, length, original = struct.unpack("<IIII", record)
            if micros >= 1_000_000 or length > snaplen or length != original:
                raise ValueError("Invalid or truncated PCAP record")
            frame = capture.read(length)
            if len(frame) != length:
                raise ValueError("Truncated PCAP packet")
            number += 1
            yield number, seconds * 1_000_000 + micros, frame


def decode(number, timestamp, frame):
    row = dict.fromkeys(FIELDS, "")
    row.update(packet=number, timestamp_utc=utc(timestamp), protocol="OTHER",
               event="other", regular_connection="no")
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return row, None
    ip = frame[14:]
    header_size = (ip[0] & 15) * 4
    total_size = int.from_bytes(ip[2:4], "big")
    if ip[0] >> 4 != 4 or not 20 <= header_size <= total_size <= len(ip):
        return row, None
    row.update(src_ip=str(IPv4Address(ip[12:16])), dst_ip=str(IPv4Address(ip[16:20])))
    if int.from_bytes(ip[6:8], "big") & 0x3FFF:
        row.update(protocol="IPv4", event="fragment")
        return row, None
    transport = ip[header_size:total_size]
    if ip[9] == 17 and len(transport) >= 8:
        sport, dport, length = struct.unpack_from("!HHH", transport)
        row.update(protocol="UDP", src_port=sport, dst_port=dport, event="udp")
        if 53 in (sport, dport) and 20 <= length <= len(transport):
            event = "dns_response" if transport[10] & 0x80 else "dns_query"
            row.update(protocol="DNS", event=event)
    if ip[9] != 6 or len(transport) < 20:
        return row, None

    sport, dport, sequence = struct.unpack_from("!HHI", transport)
    row.update(protocol="TCP", src_port=sport, dst_port=dport, event="tcp")
    offset, flags = (transport[12] >> 4) * 4, transport[13]
    if not 20 <= offset <= len(transport):
        return row, None
    payload = transport[offset:]
    if flags & 0x12 == 0x02:
        row["event"] = "tcp_syn"
        return row, sequence
    if flags & 0x12 == 0x12:
        row["event"] = "tcp_syn_ack"
    elif flags & 0x01:
        row["event"] = "tcp_fin"
    elif dport == 80 and payload.startswith(b"GET "):
        row.update(protocol="HTTP", event="http_request",
                   detail=payload.split(b"\r\n", 1)[0].decode("ascii", errors="replace"))
    elif sport == 80 and payload.startswith(b"HTTP/1."):
        row.update(protocol="HTTP", event="http_response",
                   detail=payload.split(b"\r\n", 1)[0].decode("ascii", errors="replace"))
    return row, None


def analyze(path):
    rows = []
    starts = defaultdict(list)
    seen = set()
    for number, timestamp, frame in read_pcap(path):
        row, sequence = decode(number, timestamp, frame)
        rows.append(row)
        if sequence is None:
            continue
        group = row["src_ip"], row["dst_ip"], row["dst_port"]
        signature = (*group, row["src_port"], sequence)
        if signature in seen:
            row["event"] = "tcp_syn_repeat"
            continue
        seen.add(signature)
        starts[group].append((timestamp, row))

    print(f"Packets: {len(rows)}")
    counts = Counter(row["protocol"] for row in rows)
    print("Packet categories: " + ", ".join(f"{key}={counts[key]}" for key in sorted(counts)))
    print(f"Rule: {MIN_CONNECTIONS}+ unique initial TCP SYNs; "
          f"positive gaps within ±{TOLERANCE_US / 1_000_000:.3f} s of median")
    for (src, dst, port), entries in sorted(starts.items()):
        ordered = sorted(entries, key=lambda entry: entry[0])
        gaps = [right[0] - left[0] for left, right in zip(ordered, ordered[1:])]
        center = median(gaps) if gaps else 0
        regular = (len(ordered) >= MIN_CONNECTIONS
                   and all(gap > 0 and abs(gap - center) <= TOLERANCE_US for gap in gaps))
        seconds = ", ".join(f"{gap / 1_000_000:.3f}" for gap in gaps) or "none"
        print(f"{'FLAG' if regular else 'PASS'} {src} -> {dst}:{port} | "
              f"{len(ordered)} starts | gaps (s): {seconds}")
        if regular:
            for _, row in ordered:
                row["regular_connection"] = "yes"
                print(f"  #{row['packet']} {row['timestamp_utc']}")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--csv", type=Path, default=Path("output/timeline.csv"))
    args = parser.parse_args()
    try:
        rows = analyze(args.pcap)
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        with args.csv.open("w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, FIELDS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")
    print(f"Wrote {len(rows)} timeline rows to {args.csv}")


if __name__ == "__main__":
    main()
