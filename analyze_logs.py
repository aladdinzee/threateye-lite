import os
import json
import re
from collections import Counter
from datetime import datetime,timedelta

# -------- CONFIG --------  
LOG_DIR = "/opt/threat_data/logs/archive"
ALERT_THRESHOLD_FAILED_LOGIN = 5
ALERT_THRESHOLD_SUDO = 2
ALERT_THRESHOLD_FILE_ACCESS = 2

USERS = ["guest_user", "analyst", "intern", "admin"]
PERMISSIONS = {
    "admin": ["read", "write", "execute", "sudo"],
    "analyst": ["read", "execute"],
    "intern": ["read"],
    "guest_user": []
}
ACTION_PERMISSIONS = {
    "FILE_ACCESS": "read",
    "FILE_COPY": "write",
    "SUDO_ATTEMPT": "sudo"
}


def get_yesterday_log():
    yesterday = datetime.now() - timedelta(days=1)
    log_file = f"insider_{yesterday.strftime('%Y-%m-%d')}.json"
    log_path = os.path.join(LOG_DIR,log_file)
    if os.path.exists(log_path):
        return log_path
    else:
        print(f"[INFO] No Log file found at name {yesterday.strftime('%Y-%m-%d')} ")
        return None

def parse_log(file_path):
    with open(file_path,"r") as f:
        try:
            logs = json.load(f)
        except json.JSONDecodeError:
            logs = []
    
    return logs

def detect_anomalies(logs):
    alerts = []

    login_attempt_counter = Counter()
    sudo_attempt_counter = Counter()
    file_access_counter = Counter()

    for entry in logs:
        user = entry.get("user")
        action = entry.get("action")
        details = entry.get("details")

        ip = "Unkown"

        if "from IP" in details:
            ip = details.split("from IP")[-1].strip()
        
        if action == "LOGIN_FAILED":
            login_attempt_counter[(user,ip)] += 1
        
        elif action == "SUDO_ATTEMPT":
            sudo_attempt_counter[user] += 1
        
        elif action in ["FILE_ACCESS","FILE_COPY"]:
            file_access_counter[user] += 1
        
        if action in ACTION_PERMISSIONS:
            required_permission = ACTION_PERMISSIONS[action]
            if required_permission not in PERMISSIONS.get(user,[]):
                alerts.append({
                    "type": "Unauthorized Action",
                    "user": user,
                    "action": action,
                    "details": details,
                    "message": f"{user} attempted {action} without permission!"
                })
    
    for (user,ip),count in login_attempt_counter.items():
        if count >= ALERT_THRESHOLD_FAILED_LOGIN:
            alerts.append({
                "type": "Possible Brute Force",
                "user": user,
                "ip": ip,
                "count": count,
                "message": f"{user} had {count} failed logins from {ip}"
            })
    
    for user,count in sudo_attempt_counter.items():
        if count >= ALERT_THRESHOLD_SUDO:
            alerts.append({
                "type": "Suspicious Sudo",
                "user": user,
                "count": count,
                "message": f"{user} attempted sudo {count} times"
            })
    
    for user,count in file_access_counter.items():
        if count >= ALERT_THRESHOLD_FILE_ACCESS:
            alerts.append({
                "type": "Suspicious File Activity",
                "user": user,
                "count": count,
                "message": f"{user} accessed/copied sensitive files {count} times"
            })
    
    return alerts
    
def generate_report(alerts):
    report = {
        "Total Alerts" : len(alerts),
        "Alerts" : alerts,
        "Timestamp" : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    report_file = "suspicious_activity_file_report.json"

    with open(report_file,"w") as f:
        json.dump(report,f,indent=4)
    
    print(f"[INFO] Report file generated : {report_file}")


if __name__ == "__main__":
    log_file = get_yesterday_log()

    if not log_file:
        print(f"[INFO] No Log File Found!")
    
    logs = parse_log(log_file)
    alerts = detect_anomalies(logs)


    if alerts:
        print("[ALERTS]")
        for alert in alerts:
            print(f"- {alert['message']}")
    else:
        print("[INFO] No Suspicious Activity Detected")
    
    generate_report(alerts)