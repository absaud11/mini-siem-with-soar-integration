# TITAN SIEM Architecture

## System Flow

```mermaid
flowchart TD
    A[CIC-IDS2017 CSV Dataset] --> B[Python CSV Streamer]
    B --> C[Detection Engine]
    C --> D[Alerts and Statistics]
    D --> E[Flask REST API]
    E -->|HTTP / JSON| F[Web Dashboard]
    F -->|SOAR Request| E
    E --> G[SOAR Handler]

