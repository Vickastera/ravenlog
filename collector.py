import hashlib
import os

from analyzer import analyze_line
from database import init_db, save_event

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "sample_logs", "server.log")


def extract_timestamp(line):
    parts = line.split(" ", 2)
    if len(parts) >= 2:
        return f"{parts[0]} {parts[1]}"
    return "UNKNOWN"


def extract_severity(line):
    if "ERROR" in line:
        return "ERROR"
    elif "WARNING" in line:
        return "WARNING"
    else:
        return "INFO"


def build_fingerprint(line):
    return hashlib.sha256(line.strip().encode("utf-8")).hexdigest()


def process_logs():
    init_db()

    if not os.path.exists(LOG_FILE):
        print(f"[ERROR] Log file not found: {LOG_FILE}")
        return

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            result = analyze_line(line)

            if result:
                timestamp = extract_timestamp(line)
                severity = extract_severity(line)
                fingerprint = build_fingerprint(line)

                save_event(
                    timestamp=timestamp,
                    severity=severity,
                    source_ip=result["source_ip"],
                    event_type=result["event_type"],
                    message=result["message"],
                    fingerprint=fingerprint,
                )

                print(
                    f"[ALERTA] {result['event_type']} | "
                    f"{result['source_ip']} | {result['message']}"
                )


if __name__ == "__main__":
    process_logs()
