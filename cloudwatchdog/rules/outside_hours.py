from cloudwatchdog.utils.parser import parse_timestamp, normalize_log_entry

def detect_access_outside_business_hours(logs, start_hour=8, end_hour=18):
    """
    Detects access events that occur outside of defined business hours.
    
    Parameters:
    - logs: list of raw log entries
    - start_hour: beginning of business hours (24h format)
    - end_hour: end of business hours (24h format)

    Returns:
    - List of alert strings
    """
    alerts = []

    for raw in logs:
        entry = normalize_log_entry(raw)
        timestamp = parse_timestamp(entry["timestamp"])
        
        if timestamp:
            if timestamp.hour < start_hour or timestamp.hour >= end_hour:
                alerts.append(
                    f"Access outside business hours by '{entry['user']}' at {timestamp.time()} from IP {entry['ip']}"
                )

    return alerts
