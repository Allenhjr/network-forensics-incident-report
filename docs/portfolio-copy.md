# Portfolio copy

## Ready-to-paste Projects entry

**Network Forensics Incident Report** | Python, PCAP, TCP/IP | Simulated lab

- Built a reproducible offline Python workflow to generate and analyze an 84-packet simulated capture and export a packet-level UTC timeline for defensive triage.
- Identified six TCP connections spaced exactly 30 seconds apart, distinguished the pattern from irregular portal traffic, and documented packet-level evidence and the limits of timing-based detection.

## LinkedIn Featured description

A simulated network forensics investigation with a reproducible Python workflow and packet-level evidence. The case study traces six connections at 30-second intervals and explains how to investigate whether the pattern came from legitimate scheduled activity.

## 60-second interview explanation

This simulated lab asks whether a workstation is contacting an internal test server at regular intervals. The capture includes ordinary DNS lookups and web requests so there is a comparison group. The Python analyzer reads the capture offline, groups initial TCP SYNs by source IP, destination IP, and destination port, and exports a packet-level timeline. The rule requires at least four distinct starts and checks that every gap is within one second of the median. The test-server traffic had six starts exactly 30 seconds apart, while the portal traffic was irregular. An HTTP status check can run on a schedule, so I would treat the pattern as a lead. My next step would be to use endpoint telemetry to identify the initiating process and compare the timestamps with server logs and the owner's expected polling schedule.
