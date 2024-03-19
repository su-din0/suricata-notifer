import json
import requests
import time

from datetime import datetime
from dateutil.parser import parse
from dateutil.tz import tzlocal

# Configuration for the alert channels
DISCORD_WEBHOOK_URL = ""

# Path to the log file
log_path = "/path/to/eve.json"

# Configurations
last_checked_line = 0 # 0 means that the file will be read from the beginning
waiting_time = 5 # 5 seconds
time_between_detection = 30 # 30 seconds
max_elapsed_time = 6000 # 10 minutes
detection_history = [] # List of detections

def sendToDiscord(
        signature: str,
        severity: int,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        timestamp: str,
    ):
    print("[*] Sending notification to Discord...")

    color = 16777215
    match severity:
        case 1:
            color = 16711680 # Red
        case 2:
            color = 15105570 # Orange
        case 3:
            color = 16705372 # Yellow
        case 4:
            color = 5763719 # Green
        case _:
            color = 16777215 # White

    src_dst = src_ip + ":" + str(src_port) + " ➜ " + dst_ip + ":" + str(dst_port)
    embed = {
        "embeds": [
            {
                "title": "Suricata Alert",
                "description": "An alert has been triggered by Suricata IDS.",
                "fields": [
                    {"name": "Signature", "value": signature},
                    {"name": "Severity", "value": severity},
                    {"name": "Timestamp", "value": timestamp},
                    {"name": "Source ➜ Destination", "value": src_dst},
                ],
                "color": color
            }
        ]
    }

    response = requests.post(DISCORD_WEBHOOK_URL, json=embed)

    if response.status_code == 204:
        print("[*] Notification sent successfully!")
    else:
        print("[*] Failed to send notification!")

def createOrUpdateHistory(
        timestamp: str,
        signature_id: int,
    ):
    for detection in detection_history:
        if detection["signature_id"] == signature_id:
            detection["timestamp"] = timestamp
            print("[*] Detection history updated!")
            return

    detection_history.append({
        "timestamp": timestamp,
        "signature_id": signature_id
    })

    print("[*] Detection history created!")

def fileExists():
    try:
        with open(log_path, "r") as file:
            return True
    except FileNotFoundError:
        return False
    
def shouldSendAlert(
        alert_timestamp: str,
        signature_id: int
    ):
    
    # If the history is empty, send the alert, because it's the first detection
    if len(detection_history) == 0:
        return True

    for detection in detection_history:
        # Check if the signature is already in the history
        if detection["signature_id"] == signature_id:
            
            # If the signature is in the history, check the timespan
            detection_time = parse(detection["timestamp"])
            current_time = parse(alert_timestamp)

            detection_timespan = (current_time - detection_time).total_seconds()
            if detection_timespan >= time_between_detection:
                return True
            else:
                return False

    # If the signature is not in the history, send the alert
    return True
    
def olderThan(seconds:int, timestamp:str):
    detection_time = parse(timestamp)
    current_time = datetime.now(tzlocal())

    if (current_time - detection_time).total_seconds() >= seconds:
        return True

def checkForDetections():
    print("[*] Reading log file...")
    global last_checked_line
    try:
        with open(log_path, "r") as file:
            lines = file.readlines()[last_checked_line:]
            for i in range(len(lines)):
                alert = json.loads(lines[i])

                # Check if the line is an alert
                if not "alert" in alert:
                    continue

                # Check if the alert is older than the max_elapsed_time
                if olderThan(
                        max_elapsed_time,
                        alert["timestamp"]
                    ):
                    continue

                # Check if the alert should be sent based on the history
                if not shouldSendAlert(
                        alert["timestamp"],
                        alert["alert"]["signature_id"]
                    ):
                    continue

                # Send the alert to the configured channel
                sendToDiscord(
                    alert["alert"]["signature"],
                    alert["alert"]["severity"],
                    alert["src_ip"],
                    alert["src_port"],
                    alert["dest_ip"],
                    alert["dest_port"],
                    alert["timestamp"]
                )

                # Update the detection history
                createOrUpdateHistory(
                    alert["timestamp"],
                    alert["alert"]["signature_id"]
                )

                last_checked_line = i+1
    except Exception as e:
        print("[*] An error occurred while reading log file: " + str(e))

def main():
    try:
        while True:
            checkForDetections()
            time.sleep(waiting_time)
    except KeyboardInterrupt:
        print("[*] Stopping notifier [*]")
    
if __name__ == "__main__":
    print("[*] Suricata IDS notifier started... [*]")
    if not fileExists():
        print("[*] Log file not found! Stoping notifier... [*]")
        exit()

    main()