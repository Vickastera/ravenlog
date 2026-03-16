from analyzer import analyze_line
from database import init_db, save_event

LOG_FILE = "sample_logs/server.log"

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

def process_logs():
    init_db()

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            result = analyze_line(line)
            if result:
                timestamp = extract_timestamp(line)
                severity = extract_severity(line)

                save_event(
                    timestamp=timestamp,
                    severity=severity,
                    source_ip=result["source_ip"],
                    event_type=result["event_type"],
                    message=result["message"]
                )

                print(f"[ALERTA] {result['event_type']} | {result['source_ip']} | {result['message']}")

if __name__ == "__main__":
    process_logs()
