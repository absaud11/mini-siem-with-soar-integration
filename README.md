
TITAN SIEM is an educational Mini-SIEM with simulated SOAR capabilities.

It replays network-flow data from the CIC-IDS2017 dataset, applies rule-based behavioral detection, generates security alerts, and displays the results on a web dashboard.

## Main Features

- CIC-IDS2017 CSV replay
- Near real-time traffic simulation
- Behavioral attack detection
- Brute-force detection
- DoS / DDoS detection
- Web attack detection
- Port-scan detection
- Heartbleed detection
- Live SOC dashboard
- Simulated SOAR actions
- PDF incident reporting

## Architecture

```text
CIC-IDS2017 CSV Files
        |
        v
Python CSV Streamer
        |
        v
Detection Engine
        |
        v
Alerts / Statistics
        |
        v
Flask REST API
        |
     HTTP + JSON
        |
        v
Web Dashboard
        |
        v
SOAR Actions
