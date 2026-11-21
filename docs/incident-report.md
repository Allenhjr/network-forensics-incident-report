# Network Forensics Incident Report

**Simulated lab · November 20, 2026 · All timestamps UTC**

## Investigation question

Does workstation `192.0.2.25` repeatedly open HTTP connections to the fictional internal test server `status.lab.test` (`203.0.113.40:80`) on a regular schedule?

## Evidence

The [simulated PCAP](../data/simulated-lab.pcap) contains 84 Ethernet frames generated offline using RFC 5737 documentation addresses. The [analysis output](../output/analysis.txt) counts four DNS packets, 20 HTTP message packets, and 60 other TCP packets. The [CSV timeline](../output/timeline.csv) maps each observation to a PCAP frame number and UTC timestamp.

| Packet | UTC time | Observation |
| --- | --- | --- |
| 1–2 | 14:00:01.000–14:00:01.025 | Routine portal DNS query and reply |
| 3–4 | 14:00:04.000–14:00:04.025 | Test-server DNS query and reply |
| 8–9 | 14:00:08.060–14:00:08.090 | Portal `GET /welcome` and HTTP 200 response |
| 13 | 14:00:15.000 | First flagged SYN to the test server |
| 16–17 | 14:00:15.060–14:00:15.090 | Test-server `GET /status` and HTTP 200 response |
| 21 | 14:00:45.000 | Second flagged SYN |
| 37 | 14:01:15.000 | Third flagged SYN |
| 53 | 14:01:45.000 | Fourth flagged SYN |
| 61 | 14:02:15.000 | Fifth flagged SYN |
| 69 | 14:02:45.000 | Sixth flagged SYN |

## Findings and confidence

The workstation started six TCP connections to the test server at exactly 30-second intervals over 150 seconds. All six connections carried a `GET /status` and received HTTP 200. The rule requires at least four distinct SYNs for the same source IP, destination IP, and destination port, with every gap positive and within one second of the median. The portal's four starts (packets 5, 29, 45, and 77) had gaps of 39, 36, and 87 seconds and passed the rule.

Confidence is high in the observed cadence and low in any attribution of intent. Treat the regular pattern as suspicious pending validation. A monitoring agent or scheduled health check could produce the same behavior.

## Limitations and defensive follow-up

The capture is short and synthetic and contains no endpoint telemetry or server logs. The timing rule can miss irregular activity, mixed traffic within the same group, and activity on a persistent connection.

For a real alert, preserve the capture and hash, then correlate the six timestamps with endpoint network and process events. Identify the initiating executable, command line, parent process, and any scheduled task. Check whether the server owner expects `/status` polling at this cadence and compare the times against server access logs and peer-workstation baselines. Confirmation of compromise would require corroboration, such as endpoint evidence that an unauthorized process initiated the traffic along with evidence tying it to malicious execution or persistence.
