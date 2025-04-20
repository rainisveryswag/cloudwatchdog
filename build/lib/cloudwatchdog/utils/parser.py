import json
from datetime import datetime

def load_logs(path):
    """
    Loads JSON logs from the given file path.
    Returns a list of log entries.
    """
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Error loading logs: {e}")
        return []

def parse_timestamp(timestamp_str):
    """
    Converts a timestamp string (e.g., '2025-04-18T10:00:00Z') into a datetime object.
    Returns None if the format is invalid.
    """
    try:
        return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None

def normalize_log_entry(entry):
    """
    Normalizes log fields to a standard format for easier use in detection rules.
    Returns a dictionary with default-safe values.
    """
    return {
        "event_name": entry.get("eventName", ""),
        "ip": entry.get("sourceIPAddress", "unknown"),
        "user": entry.get("userIdentity", {}).get("userName", "unknown"),
        "timestamp": entry.get("eventTime", ""),
        "success": entry.get("responseElements", {}).get("Success", None),
        "resource": entry.get("requestParameters", {}).get("bucketName", "unknown"),
    }
