# Network Forensics Incident Report

**Simulated lab · Allen Harris · Old Dominion University**

This defensive investigation asks whether a workstation's HTTP connections to an internal test server recur at regular intervals. The capture was generated entirely offline using fictional `.test` hostnames and RFC 5737 documentation addresses. The scripts only read and write local files.

## Quick start

Run from the repository root with Python 3.9 or newer. The generator and analyzer use the standard library.

```sh
python generate_pcap.py
python analyze_pcap.py data/simulated-lab.pcap
```

The generator reproduces the checked-in [PCAP](data/simulated-lab.pcap) byte for byte. The analyzer prints a summary and creates a [CSV timeline](output/timeline.csv) with one row per packet. Use `--output` on the generator and `--csv` on the analyzer to choose alternate paths.

## Sample output

```text
Packets: 84
Packet categories: DNS=4, HTTP=20, TCP=60
Rule: 4+ unique initial TCP SYNs; positive gaps within ±1.000 s of median
PASS 192.0.2.25 -> 198.51.100.80:80 | 4 starts | gaps (s): 39.000, 36.000, 87.000
FLAG 192.0.2.25 -> 203.0.113.40:80 | 6 starts | gaps (s): 30.000, 30.000, 30.000, 30.000, 30.000
  #13 2026-11-20T14:00:15.000000Z
  #21 2026-11-20T14:00:45.000000Z
```

[Full analysis output](output/analysis.txt) · [Incident report](docs/incident-report.md) · [One-page case study](docs/case-study.pdf)

## Detection rule

The analyzer groups initial TCP SYNs by source IP, destination IP, and destination port. Within each group it counts distinct starts, ignoring repeated SYNs with the same source port and initial sequence number. It sorts those starts by time and flags a group when it has at least **four** starts, all gaps are positive, and every consecutive gap is within **±1 second** of the median gap. Only the flagged SYN rows get `regular_connection=yes`.

A health check, inventory agent, or scheduled job can hit the same threshold by opening fresh connections on a timer. The simulated polling pattern is a triage lead. Confirming compromise would require corroborating endpoint and server evidence about the initiating process and whether its activity was authorized. Packet categories are exclusive. The HTTP count includes individual GET requests and HTTP response packets, and the TCP count covers transport packets such as SYNs, ACKs, and FINs. The parser targets this lab's classic little-endian Ethernet/IPv4 PCAP and single-packet HTTP messages.

## Verify the finding in Wireshark

1. Open `data/simulated-lab.pcap` via **File → Open**. In **View → Time Display Format**, select **UTC Date and Time of Day**.
2. Apply this display filter for the workstation's initial SYNs to the test server:

   ```wireshark
   ip.src == 192.0.2.25 && ip.dst == 203.0.113.40 && tcp.dstport == 80 && tcp.flags.syn == 1 && tcp.flags.ack == 0
   ```

3. Confirm the **No.** and **Time** columns show packets **13, 21, 37, 53, 61, 69**, from **14:00:15 UTC** to **14:02:45 UTC** on November 20, 2026. To check the gaps directly, select **View → Time Display Format → Seconds Since Previous Displayed Packet**. After the first displayed frame, each of the next five rows should show **30.000000** seconds. Expand **Frame**, **Internet Protocol Version 4**, and **Transmission Control Protocol** to check arrival time, source and destination IPs, source ports 42000–42005, destination port 80, and the SYN and ACK flag values.
4. Use `http.request && ip.dst == 203.0.113.40` to check **Host**, **Request Method**, and **Request URI**. Packet **16** shows `GET /status` with host `status.lab.test`. Use `dns` to inspect **Queries → Name** and **Answers → Address**, or `http.request && ip.dst == 198.51.100.80` to compare the routine portal traffic.

5. For comparison, change the destination in the SYN filter to `198.51.100.80`. The four portal SYNs are packets **5, 29, 45, and 77**. Their consecutive gaps are **39, 36, and 87 seconds**.
