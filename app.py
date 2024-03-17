import json
import requests
import time

# Paths
discord_webhook_url = ""
log_path = "/path/to/eve.json"

# Configurations
last_checked_line = 0
waiting_time = 5
detection_time = 30
detection_history = []

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

    response = requests.post(discord_webhook_url, json=embed)

    if response.status_code == 204:
        print("[*] Notification sent successfully!")
    else:
        print("[*] Failed to send notification!")

def pushToHistory(
        timestamp: str,
        signature_id: int,
    ):
    print("[*] Pushing to detection history...")
    detection_history.append({
        "timestamp": timestamp,
        "signature_id": signature_id
    })

def main():
    try:
        print("[*] Reading log file...")
        with open(log_path, "r") as file:
            for line in file:
                alert = json.loads(line)
                if not "alert" in alert:
                    continue

                sendToDiscord(
                    alert["alert"]["signature"],
                    alert["alert"]["severity"],
                    alert["src_ip"],
                    alert["src_port"],
                    alert["dest_ip"],
                    alert["dest_port"],
                    alert["timestamp"]
                )
                pushToHistory(
                    alert["timestamp"],
                    alert["alert"]["signature_id"]
                )
                time.sleep(1)

    except KeyboardInterrupt:
        print("[*] Exiting...")



if __name__ == "__main__":
    print("[*] Suricata IDS notifier started...")
    main()
