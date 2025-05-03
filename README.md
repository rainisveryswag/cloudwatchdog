# CloudWatchdog 🐾

**CloudWatchdog** is a lightweight and modular command-line tool for detecting suspicious or malicious activity in cloud infrastructure logs — especially for AWS and GCP-style logs.

It helps **security analysts**, **CTF players**, and **blue teamers** quickly identify risky behaviors such as unauthorized access, privilege escalation, user creation, or potential data exfiltration.

---

## Key Features

- Parses AWS-style JSON cloud logs
- Detects:
  - Access outside business hours
  - Sudden IAM user creation
  - Download spikes from a single IP
  - Privilege escalation (e.g., `PutUserPolicy`)
  - Failed login attempts
  - Suspicious file access patterns (data exfiltration)
- Exports alerts to a `.txt` file
- Easy to extend with custom detection rules
- Works as a real CLI tool: `cloudwatchdog --input logs.json`

---

## Supported Cloud Services

CloudWatchdog is optimized for **AWS CloudTrail**-style logs, but it works for **any structured JSON cloud logs** with the following fields:

- `eventName`
- `eventTime`
- `sourceIPAddress`
- `userIdentity.userName`
- `requestParameters.bucketName` (for S3-like storage)
- `responseElements.Success` (for login status)

---

## Installation

```bash
# 1. Clone the repo
git clone https://github.com/rainisveryswag/cloudwatchdog.git
cd cloudwatchdog

# 2. Set up a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
# 3. Install the tool

pip install .
```

##  Usage
Run the tool by specifying:

**--input** → path to a log file (JSON format)

**--export** → path to output file for alerts
```bash

cloudwatchdog --input logs/sample_logs.json --export alerts/alerts.txt
```
## Example Log Format
Here’s what your JSON logs should look like:
```
[
  {
    "eventName": "ConsoleLogin",
    "eventTime": "2025-04-20T23:45:00Z",
    "sourceIPAddress": "192.168.1.11",
    "userIdentity": {"userName": "admin"},
    "responseElements": {"Success": "false"}
  }
]
```
## Example Output
```
ALERTS FOUND:
Access outside business hours by 'admin' at 23:45:00 from IP 192.168.1.11
IAM user 'temp-user' was created by 'sec-admin' from IP 172.16.0.1
Suspicious download spike: 4 file accesses from IP 198.51.100.99
```
## Rules Included
- Rule	Description
- failed_logins	Detects multiple failed login attempts
- privilege_escalation	Flags risky API calls like PutUserPolicy
- data_exfiltration	Tracks excessive access to storage buckets
- outside_hours	Detects access outside working hours (8 AM–6 PM)
- user_creation	Detects new IAM user creation
- download_spike	Flags repeated file downloads from same IP

## License
This project is licensed under the MIT License.

# Author
Made with 💻 + ☕ by Yousra
Cybersecurity student | purple teamer 


