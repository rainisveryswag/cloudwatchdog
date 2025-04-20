def detect_failed_logins(logs):
    alerts = []
    ip_count = {}

    for entry in logs:
        if entry.get("eventName") == "ConsoleLogin":
            success = entry.get("responseElements", {}).get("Success")
            ip = entry.get("sourceIPAddress")
            if success == "false":
                ip_count[ip] = ip_count.get(ip, 0) + 1

    for ip, count in ip_count.items():
        if count >= 2:
            alerts.append(f"Multiple failed logins from IP {ip}: {count} attempts")
    return alerts
