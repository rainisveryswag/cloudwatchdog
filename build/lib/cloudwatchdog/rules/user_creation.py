def detect_iam_user_creation(logs):
    """
    Detects IAM user creation events in the cloud logs.

    Parameters:
    - logs: list of raw log entries

    Returns:
    - List of alert strings
    """
    alerts = []

    for entry in logs:
        if entry.get("eventName") in ["CreateUser", "CreateLoginProfile"]:
            creator = entry.get("userIdentity", {}).get("userName", "unknown")
            new_user = entry.get("requestParameters", {}).get("userName", "unknown")
            ip = entry.get("sourceIPAddress", "unknown")

            alerts.append(
                f"IAM user '{new_user}' was created by '{creator}' from IP {ip}"
            )

    return alerts
