import json
from datetime import datetime
import random
import time
import os

users = ["analyst","intern","admin","guest_user"]

actions = [
    {"action": "LOGIN_FAILED", "details": "N/A", "result": "DENIED"},
    {"action": "LOGIN_SUCCESS", "details": "N/A", "result": "SUCCESS"},
    {"action": "FILE_ACCESS", "details": "Attempted confidential.txt", "result": "DENIED"},
    {"action": "SUDO_ATTEMPT", "details": "Tried sudo rm -rf /etc/passwd", "result": "DENIED"},
    {"action": "FILE_COPY", "details": "Copied confidential.txt to /tmp", "result": "SUCCESS"}
]

ips = ["192.123.32.12","142.329.219.2","102.39.0.1"]

log_dir = "/opt/threat_data/logs"

os.makedirs(log_dir,exist_ok=True)

log_file = os.path.join(log_dir,f"insider_{datetime.now().strftime('%Y-%m-%d')}.json")

def generate_log_entry():
    user = random.choice(users)
    action = random.choice(actions)
    ip = random.choice(ips)
    timestamp = datetime.now().strftime("%Y-%m-%dT%H%M%S")

    log_entry = {
        "timestamp" : timestamp,
        "user" : user,
        "action" : action["action"],
        "details" : f"{action['details']} from IP {ip}",
        "result" : action["result"]
    }
    
    return log_entry

def write_log():
    logs = []

    try:
        with open(log_file,"r") as f:
            logs = json.load(f)
    
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []
    
    log_entry = generate_log_entry()
    logs.append(log_entry)

    with open(log_file,"w") as f:
        json.dump(logs,f,indent=4)
    
    print(log_entry)


if __name__ == "__main__":
    for i in range(10):
        write_log()
        time.sleep(5)
