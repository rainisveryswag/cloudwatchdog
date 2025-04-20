def detect_data_exfiltration(logs):
    alerts = []

    for entry in logs:
        if entry.get("eventName") in ["GetObject", "DownloadDBLogFilePortion"]:
            user = entry.get("userIdentity", {}).get("userName", "Unknown")
            ip = entry.get("sourceIPAddress", "Unknown")
            resource = entry.get("requestParameters", {}).get("bucketName", "Unknown resource")

            alerts.append(f"Possible data exfiltration: {user} from {ip} accessed {resource} using {entry['eventName']}")

    return alerts
