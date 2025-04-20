import argparse
from .utils.parser import load_logs
from .rules.failed_logins import detect_failed_logins
from .rules.privilege_escalation import detect_privilege_escalation
from .rules.data_exfiltration import detect_data_exfiltration
from .rules.outside_hours import detect_access_outside_business_hours
from .rules.user_creation import detect_iam_user_creation
from .rules.download_spike import detect_download_spike


def save_alerts(alerts, path):
    try:
        with open(path, "w") as out:
            for alert in alerts:
                out.write(alert + "\n")
        print(f"Alerts saved to {path}")
    except Exception as e:
        print(f"Failed to write alerts: {e}")

def main():
    parser = argparse.ArgumentParser(description="🐾 CloudWatchdog - Cloud Log Threat Detection Tool")
    parser.add_argument("--input", type=str, required=True, help="Path to input log file (JSON format)")
    parser.add_argument("--export", type=str, default="alerts/alerts.txt", help="Path to export alerts")
    args = parser.parse_args()

    logs = load_logs(args.input)
    if not logs:
        print("No logs to analyze.")
        return

    all_alerts = []
    all_alerts.extend(detect_failed_logins(logs))
    all_alerts.extend(detect_privilege_escalation(logs))
    all_alerts.extend(detect_data_exfiltration(logs))
    all_alerts.extend(detect_access_outside_business_hours(logs))
    all_alerts.extend(detect_iam_user_creation(logs))
    all_alerts.extend(detect_download_spike(logs))

    if all_alerts:
        print("Alerts Found:")
        for alert in all_alerts:
            print(alert)
        save_alerts(all_alerts, args.export)
    else:
        print("No threats detected.")

if __name__ == "__main__":
    main()
