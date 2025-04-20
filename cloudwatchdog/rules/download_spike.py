def detect_download_spike(logs, threshold=3):
    """
    Detects large numbers of download-related events from the same IP address.

    Parameters:
    - logs: list of raw log entries
    - threshold: number of downloads from a single IP to be considered suspicious

    Returns:
    - List of alert strings
    """
    alerts = []
    ip_downloads = {}

    for entry in logs:
        if entry.get("eventName") in ["GetObject", "DownloadDBLogFilePortion"]:
            ip = entry.get("sourceIPAddress", "unknown")
            ip_downloads[ip] = ip_downloads.get(ip, 0) + 1

    for ip, count in ip_downloads.items():
        if count >= threshold:
            alerts.append(
                f" Suspicious download spike: {count} file accesses from IP {ip}"
            )

    return alerts
