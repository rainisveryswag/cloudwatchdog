def detect_privilege_escalation(logs):
    alerts = []

    for entry in logs:
        if entry.get("eventName") in ["PutUserPolicy", "AttachUserPolicy", "PutRolePolicy"]:
            user = entry.get("userIdentity", {}).get("userName", "Unknown")
            ip = entry.get("sourceIPAddress", "Unknown")
            alerts.append(f"Privilege escalation attempt by {user} from IP {ip} via {entry['eventName']}")

    return alerts
