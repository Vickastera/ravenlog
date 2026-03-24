import re

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _extract_ip(line):
    match = IP_PATTERN.search(line)
    if match:
        return match.group(0)
    return "UNKNOWN"


def analyze_line(line):
    """
    Analyze a log line and return a normalized suspicious event payload.

    Returns:
        dict | None: Event data with source_ip, event_type and message.
    """
    normalized = line.strip()
    lower = normalized.lower()

    if "failed login" in lower:
        return {
            "source_ip": _extract_ip(normalized),
            "event_type": "failed_login",
            "message": "Multiple failed login attempts detected",
        }

    if "unauthorized access attempt" in lower and "/admin" in lower:
        return {
            "source_ip": _extract_ip(normalized),
            "event_type": "admin_probe",
            "message": "Unauthorized access attempt to /admin",
        }

    if "/wp-login.php" in lower:
        return {
            "source_ip": _extract_ip(normalized),
            "event_type": "wordpress_scan",
            "message": "Suspicious scan on /wp-login.php",
        }

    if "/phpmyadmin" in lower:
        return {
            "source_ip": _extract_ip(normalized),
            "event_type": "phpmyadmin_scan",
            "message": "Suspicious scan on /phpmyadmin",
        }

    return None
