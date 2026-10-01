import os
import time
import threading
import uuid
from typing import Dict, Any, List, Optional

from flask import Flask, jsonify, request, send_from_directory
import pandas as pd


class DataStreamer:
    """
    Streams CIC-IDS2017 CSV data and applies purely behavioral detection.
    IMPORTANT:
    - No IP addresses are hardcoded.
    - The Label column is NOT used for detection (only for display/analysis if desired).
    """

    def __init__(self, data_dir: str) -> None:
        self.data_dir = data_dir

        # 5 scenarios -> 5 files
        self.scenario_map: Dict[str, str] = {
            # Tuesday – FTP/SSH brute force
            "Tuesday": "Tuesday-WorkingHours.pcap_ISCX.csv",
            # Wednesday – DoS Hulk, GoldenEye, Slowloris, Heartbleed
            "Wednesday": "Wednesday-workingHours.pcap_ISCX.csv",
            # Thursday – Web attacks (brute force, XSS, SQLi)
            "Thursday": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
            # Friday – Port scan
            "Friday-PortScan": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            # Friday – DDoS LOIT
            "Friday-DDoS": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        }

        self.current_day: Optional[str] = None
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.lock = threading.Lock()

        # Rolling buffers
        self.events: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []

        # Simple stats
        self.stats: Dict[str, Any] = {
            "packets_processed": 0,
            "packets_dropped": 0,
            "active_threats": 0,
        }

        # SOAR state
        self.blocked_ips: set[str] = set()

        # Stateful behavioral tracking
        # For Port Scan: source_ip -> [(timestamp, dst_port), ...]
        self.port_activity: Dict[str, List[tuple[float, int]]] = {}

        # Alert aggregation: (src_ip, attack_name) -> last_alert_timestamp
        self.recent_alerts: Dict[tuple[str, str], float] = {}

    # --------------------------------------------------------------------- #
    # Public control methods
    # --------------------------------------------------------------------- #

    def start_scenario(self, day: str) -> None:
        """Stop current stream and start a new one from the selected scenario."""
        if day not in self.scenario_map:
            raise ValueError(f"Unknown scenario day: {day}")

        # Stop running thread (if any)
        with self.lock:
            if self.thread and self.thread.is_alive():
                self.stop_event.set()
                thread_to_join = self.thread
            else:
                thread_to_join = None

        if thread_to_join:
            thread_to_join.join()

        # Reset state and start new thread
        with self.lock:
            self.stop_event = threading.Event()
            self.events.clear()
            self.alerts.clear()
            self.stats = {
                "packets_processed": 0,
                "packets_dropped": 0,
                "active_threats": 0,
            }
            self.blocked_ips.clear()
            self.port_activity.clear()
            self.recent_alerts.clear()
            self.current_day = day

            csv_path = os.path.join(self.data_dir, self.scenario_map[day])

            self.thread = threading.Thread(
                target=self._run_stream,
                args=(csv_path,),
                daemon=True,
            )
            self.thread.start()

    def get_snapshot(self, limit: int = 200) -> Dict[str, Any]:
        """Return the latest snapshot for the dashboard."""
        with self.lock:
            events = self.events[-limit:].copy()
            alerts = self.alerts[-limit:].copy()
            stats = dict(self.stats)
            current_day = self.current_day
        return {
            "current_day": current_day,
            "events": events,
            "alerts": alerts,
            "stats": stats,
        }

    def handle_soar_action(
        self,
        action: str,
        target_ip: Optional[str],
        alert_id: Optional[str],
    ) -> Dict[str, Any]:
        """Simulate SOAR actions (BLOCK_IP etc.)."""

        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(
            f"[{ts}] SOAR action={action} target_ip={target_ip} alert_id={alert_id}",
            flush=True,
        )

        updated_status: Optional[str] = None

        with self.lock:
            if action == "BLOCK_IP" and target_ip:
                self.blocked_ips.add(target_ip)
                updated_status = "CONTAINED"

            # Mark the specific alert status
            for alert in self.alerts:
                if alert["id"] == alert_id:
                    if updated_status is None:
                        updated_status = "IN_PROGRESS"
                    alert["status"] = updated_status
                    break

            # Recompute active threats
            self.stats["active_threats"] = sum(
                1 for a in self.alerts if a.get("status") == "ACTIVE"
            )

        return {
            "timestamp": ts,
            "action": action,
            "target_ip": target_ip,
            "alert_id": alert_id,
            "message": "SOAR action executed (simulated). Check server logs for details.",
        }

    # --------------------------------------------------------------------- #
    # Internal helpers
    # --------------------------------------------------------------------- #

    def _run_stream(self, csv_path: str) -> None:
        """Stream a CSV row-by-row with a small delay between rows."""
        if not os.path.exists(csv_path):
            print(f"[ERROR] CSV path does not exist: {csv_path}", flush=True)
            return

        print(f"[INFO] Starting stream from {csv_path}", flush=True)

        try:
            for chunk in pd.read_csv(csv_path, chunksize=1):
                if self.stop_event.is_set():
                    break

                chunk.columns = [str(c).strip() for c in chunk.columns]
                row = chunk.iloc[0].to_dict()
                self._process_row(row)
                time.sleep(0.1)  # simulate near real-time
        except Exception as exc:
            print(f"[ERROR] Stream error: {exc}", flush=True)
        finally:
            print(f"[INFO] Stream stopped for {csv_path}", flush=True)

    def _process_row(self, row: Dict[str, Any]) -> None:
        """
        Process a single flow row:
        - Build normalized event
        - Apply behavioral heuristics
        - Respect SOAR blocking
        """
        now = time.time()
        row_map = {str(k).strip().lower(): v for k, v in row.items()}

        def get_field(candidates, default=None):
            for name in candidates:
                key = name.strip().lower()
                if key in row_map:
                    return row_map[key]
            return default

        def to_int(val) -> Optional[int]:
            try:
                if val is None or val == "":
                    return None
                return int(float(val))
            except (TypeError, ValueError):
                return None

        def to_float(val) -> Optional[float]:
            try:
                if val is None or val == "":
                    return None
                return float(val)
            except (TypeError, ValueError):
                return None

        src_ip = get_field(["Source IP", "Src IP", "src_ip"])
        dst_ip = get_field(["Destination IP", "Dst IP", "dst_ip"])
        raw_dst_port = get_field(["Destination Port", "Dst Port", "dst_port"])
        dst_port = to_int(raw_dst_port)
        protocol = get_field(["Protocol", "protocol"])

        # Label is read only for display / analysis (NOT for detection)
        label = get_field(["Label", "label"])

        total_fwd_pkts = to_int(
            get_field(
                [
                    "Total Fwd Packets",
                    "Tot Fwd Pkts",
                    "Fwd Packets",
                ]
            )
        )
        total_fwd_len = to_float(
            get_field(
                [
                    "Total Length of Fwd Packets",
                    "TotLen Fwd Pkts",
                    "Fwd Packet Length Total",
                ]
            )
        )
        flow_duration = to_float(
            get_field(
                [
                    "Flow Duration",
                    "Flow Duration(ms)",
                    "Flow Duration (ms)",
                ]
            )
        )

        timestamp_val = get_field(
            [
                "Timestamp",
                "Flow Timestamp",
                "StartTime",
                "Flow Start Time",
            ]
        )
        packet_time_str = (
            str(timestamp_val)
            if timestamp_val not in (None, "")
            else time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        )

        # Drop packets if source IP has been blocked by SOAR
        if src_ip and src_ip in self.blocked_ips:
            with self.lock:
                self.stats["packets_dropped"] += 1
            return

        # Update processed count
        with self.lock:
            self.stats["packets_processed"] += 1

        # Build event record
        event = {
            "id": str(uuid.uuid4()),
            "time": packet_time_str,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": raw_dst_port,
            "protocol": protocol,
            "label": label,  # NOTE: not used in detection, just for UI/analysis
            "scenario_day": self.current_day,
        }

        alerts_created: List[Dict[str, Any]] = []

        # -------------------- Behavioral Heuristics -------------------- #
        # 1) Brute Force (FTP/SSH) — Tuesday
        self._detect_bruteforce(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            total_fwd_pkts=total_fwd_pkts,
            protocol=protocol,
            now=now,
            alerts_created=alerts_created,
        )

        # 2) Volumetric DoS / DDoS — Wednesday & Friday DDoS
        self._detect_dos_ddos(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            total_fwd_pkts=total_fwd_pkts,
            protocol=protocol,
            now=now,
            alerts_created=alerts_created,
        )

        # 3) Heartbleed — Wednesday
        self._detect_heartbleed(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            now=now,
            alerts_created=alerts_created,
        )

        # 4) Web attacks (SQLi / XSS) — Thursday
        self._detect_web_attack(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            total_fwd_pkts=total_fwd_pkts,
            total_fwd_len=total_fwd_len,
            flow_duration=flow_duration,
            protocol=protocol,
            now=now,
            alerts_created=alerts_created,
        )

        # 5) Port scanning — Friday PortScan
        self._detect_port_scan(
            src_ip=src_ip,
            dst_port=dst_port,
            protocol=protocol,
            now=now,
            alerts_created=alerts_created,
        )

        # Commit event & alerts atomically
        with self.lock:
            self.events.append(event)
            if len(self.events) > 1000:
                self.events = self.events[-1000:]

            for alert in alerts_created:
                self.alerts.append(alert)
            if len(self.alerts) > 1000:
                self.alerts = self.alerts[-1000:]

            self.stats["active_threats"] = sum(
                1 for a in self.alerts if a.get("status") == "ACTIVE"
            )

    # --------------------------------------------------------------------- #
    # Detection rules
    # --------------------------------------------------------------------- #

    def _detect_bruteforce(
        self,
        src_ip: Any,
        dst_ip: Any,
        dst_port: Optional[int],
        total_fwd_pkts: Optional[int],
        protocol: Any,
        now: float,
        alerts_created: List[Dict[str, Any]],
    ) -> None:
        """
        Brute Force Detection (Tuesday Scenario)
        - Targeting FTP-Patator & SSH-Patator.
        - IF Destination Port is 21 (FTP) OR 22 (SSH)
          AND Total Fwd Packets > 20
        """
        if dst_port not in (21, 22):
            return
        if total_fwd_pkts is None or total_fwd_pkts <= 20:
            return

        attack_name = "Brute Force Attempt (SSH/FTP)"
        description = (
            "High number of forward packets on FTP/SSH flow, "
            "suggesting password brute force activity."
        )

        alert = self._raise_alert(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            severity="CRITICAL",
            attack_name=attack_name,
            description=description,
            now=now,
        )
        if alert:
            alerts_created.append(alert)

    def _detect_dos_ddos(
        self,
        src_ip: Any,
        dst_ip: Any,
        dst_port: Optional[int],
        total_fwd_pkts: Optional[int],
        protocol: Any,
        now: float,
        alerts_created: List[Dict[str, Any]],
    ) -> None:
        """
        DoS & DDoS Detection (Wednesday & Friday DDoS Scenarios)
        - Targeting DoS Hulk, GoldenEye, LOIT.
        - IF Destination Port is 80 (HTTP)
          AND Total Fwd Packets > 100
        """
        if dst_port != 80:
            return
        if total_fwd_pkts is None or total_fwd_pkts <= 100:
            return

        attack_name = "Volumetric DoS/DDoS Attack"
        description = (
            "Abnormally large HTTP flow (forward packets > 100) consistent "
            "with volumetric DoS/DDoS behavior."
        )

        alert = self._raise_alert(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            severity="CRITICAL",
            attack_name=attack_name,
            description=description,
            now=now,
        )
        if alert:
            alerts_created.append(alert)

    def _detect_heartbleed(
        self,
        src_ip: Any,
        dst_ip: Any,
        dst_port: Optional[int],
        protocol: Any,
        now: float,
        alerts_created: List[Dict[str, Any]],
    ) -> None:
        """
        Heartbleed Detection (Wednesday Scenario)
        - IF Destination Port is 444
        """
        if dst_port != 444:
            return

        attack_name = "Heartbleed Exploitation Attempt"
        description = (
            "Flow targeting TLS heartbeat port 444 indicative of Heartbleed "
            "exploit traffic in this dataset."
        )

        alert = self._raise_alert(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            severity="CRITICAL",
            attack_name=attack_name,
            description=description,
            now=now,
        )
        if alert:
            alerts_created.append(alert)

    def _detect_web_attack(
        self,
        src_ip: Any,
        dst_ip: Any,
        dst_port: Optional[int],
        total_fwd_pkts: Optional[int],
        total_fwd_len: Optional[float],
        flow_duration: Optional[float],
        protocol: Any,
        now: float,
        alerts_created: List[Dict[str, Any]],
    ) -> None:
        """
        Web Attack Detection (Thursday Scenario)
        - Targeting XSS, SQL Injection
        - IF Destination Port is 80
          AND Total Length of Fwd Packets > 500
          AND Total Fwd Packets < 20
        """
        if dst_port != 80:
            return
        if total_fwd_len is None or total_fwd_len <= 500:
            return
        if total_fwd_pkts is None or total_fwd_pkts >= 20:
            return

        attack_name = "Suspicious Web Payload (SQLi/XSS)"
        description = (
            "HTTP flow with relatively few packets but large payload size, "
            "consistent with injection-style attacks (SQLi/XSS)."
        )

        alert = self._raise_alert(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            severity="WARNING",
            attack_name=attack_name,
            description=description,
            now=now,
        )
        if alert:
            alerts_created.append(alert)

    def _detect_port_scan(
        self,
        src_ip: Any,
        dst_port: Optional[int],
        protocol: Any,
        now: float,
        alerts_created: List[Dict[str, Any]],
    ) -> None:
        """
        Port Scanning (Friday PortScan Scenario)
        - IF a single Source IP connects to > 5 unique ports within 2 seconds.
        """
        if not src_ip or dst_port is None:
            return

        window_seconds = 2.0
        min_unique_ports = 5

        with self.lock:
            history = self.port_activity.setdefault(str(src_ip), [])
            history.append((now, dst_port))
            cutoff = now - window_seconds
            history[:] = [(ts, p) for ts, p in history if ts >= cutoff]

            unique_ports = {p for _, p in history}
            if len(unique_ports) > min_unique_ports:
                attack_name = "Port Scanning Activity"
                description = (
                    f"Source has contacted {len(unique_ports)} unique ports "
                    f"in the last {window_seconds:.0f} seconds."
                )
                alert = self._raise_alert(
                    src_ip=src_ip,
                    dst_ip=None,
                    dst_port=-1,  # multiple ports
                    protocol=protocol,
                    severity="WARNING",
                    attack_name=attack_name,
                    description=description,
                    now=now,
                )
                if alert:
                    alerts_created.append(alert)

    # --------------------------------------------------------------------- #
    # Alert creation with aggregation
    # --------------------------------------------------------------------- #

    def _raise_alert(
        self,
        src_ip: Any,
        dst_ip: Any,
        dst_port: Optional[int],
        protocol: Any,
        severity: str,
        attack_name: str,
        description: str,
        now: float,
    ) -> Optional[Dict[str, Any]]:
        """
        Central alert creation with aggregation:
        - If (src_ip, attack_name) seen in last 5 seconds, suppress.
        """
        key_src = str(src_ip) if src_ip is not None else "UNKNOWN"
        key = (key_src, attack_name)
        last_ts = self.recent_alerts.get(key)

        if last_ts is not None and (now - last_ts) < 5.0:
            # Suppress duplicate alert to avoid flooding
            return None

        self.recent_alerts[key] = now

        now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))

        alert = {
            "id": str(uuid.uuid4()),
            "time": now_str,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "severity": severity,
            "attack_name": attack_name,
            "description": description,
            "scenario_day": self.current_day,
            "status": "ACTIVE",
            "layer": "BEHAVIORAL",
        }
        return alert


# ------------------------------------------------------------------------- #
# Flask application setup
# ------------------------------------------------------------------------- #

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

streamer = DataStreamer(data_dir=DATA_DIR)

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")


@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/api/events", methods=["GET"])
def api_events():
    try:
        limit = int(request.args.get("limit", "200"))
    except ValueError:
        limit = 200
    snapshot = streamer.get_snapshot(limit=limit)
    return jsonify(snapshot)


@app.route("/api/switch-scenario", methods=["POST"])
def api_switch_scenario():
    data = request.get_json(force=True, silent=True) or {}
    day = data.get("day")
    if not day:
        return jsonify({"error": "Missing 'day' in request body"}), 400

    try:
        streamer.start_scenario(day)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"message": f"Scenario switched to {day}", "day": day})


@app.route("/api/execute-soar", methods=["POST"])
def api_execute_soar():
    data = request.get_json(force=True, silent=True) or {}
    action = data.get("action")
    target_ip = data.get("target_ip")
    alert_id = data.get("alert_id")

    if not action:
        return jsonify({"error": "Missing 'action' in request body"}), 400

    result = streamer.handle_soar_action(
        action=action,
        target_ip=target_ip,
        alert_id=alert_id,
    )
    return jsonify(result)


if __name__ == "__main__":
    # Start Tuesday scenario by default
    try:
        streamer.start_scenario("Tuesday")
    except Exception as exc:
        print(f"[WARN] Could not start default scenario: {exc}", flush=True)

    app.run(host="127.0.0.1", port=5000, debug=False)
