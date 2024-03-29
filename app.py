import json
import requests
import time
import smtplib

from datetime import datetime
from dateutil.parser import parse
from dateutil.tz import tzlocal
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# Configuration for the alert channels

# Discord
SEND_TO_DISCORD = False # Set to True to enable Discord notifications
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/00000" # Replace with your Discord webhook URL

# Slack
SEND_TO_SLACK = False # Set to True to enable Slack notifications
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/000000" # Replace with your Slack webhook URL

# Email
SEND_TO_EMAIL = False # Set to True to enable Email notifications
EMAIL_ADDRESS = "" # Replace with your email address
EMAIL_PASSWORD = "" # Replace with your email password
EMAIL_SMTP_SERVER = "" # Replace with your email SMTP server
EMAIL_SMTP_PORT = 587 # Replace with your email SMTP port
EMAIL_RECIPIENT = "" # Replace with the recipient email address

# Path to the log file
log_path = "/path/to/eve.json"

# Path to the notifer log file
own_log_path = "path/to/notifer_log.json"

# Configurations
last_checked_line = 0 # 0 means that the file will be read from the beginning
waiting_time = 5 # 5 seconds
time_between_detection = 30 # 30 seconds
max_elapsed_time = 3600 #  1 hour
detection_history = [] # List of detections

# Colors for the alerts
colors = {
    # For discord you must use the decimal value
    "discord": {
        1: 16711680,  # Red
        2: 15105570,  # Orange
        3: 16705372,  # Yellow
        4: 5763719,   # Green
        "default": 16777215  # White
    },
    # For slack you must use the hexadecimal value
    "slack": {
        1: "#FF0000",  # Red
        2: "#FFA500",  # Orange
        3: "#FFFF00",  # Yellow
        4: "#008000",  # Green
        "default": "#FFFFFF"  # White
    }
}

def matchSeverity(severity: int):
    match severity:
        case 1:
            return "High"
        case 2:
            return "Medium"
        case 3:
            return "Low"
        case 4:
            return "Informational"
        case _:
            return "Unknown"
        
def buildSD(src_ip: str, src_port: int, dst_ip: str, dst_port: int):
    result = ""
    if src_port != 0:
        result += src_ip + ":" + str(src_port)
    else:
        result += src_ip
    result += " ➜ "
    if dst_port != 0:
        result += dst_ip + ":" + str(dst_port)
    else:
        result += dst_ip

    return result

def printAndLog(message: str):
    print(message)
    with open(own_log_path, "a") as file:
        data = {
            "timestamp": datetime.now().isoformat(),
            "message": message
        }
        file.write(json.dumps(data) + "\n")

def createOrUpdateHistory(
        timestamp: str,
        signature_id: int,
    ):
    for detection in detection_history:
        if detection["signature_id"] == signature_id:
            detection["timestamp"] = timestamp
            printAndLog("[*] Detection history updated!")
            return

    detection_history.append({
        "timestamp": timestamp,
        "signature_id": signature_id
    })

    printAndLog("[*] Detection history created!")

def sendToDiscord(
        signature: str,
        severity: int,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        timestamp: str,
    ):

    if not SEND_TO_DISCORD:
        return

    printAndLog("[*] Sending notification to Discord...")

    color = colors["discord"].get(severity, colors["discord"]["default"])

    embed = {
        "embeds": [
            {
                "title": "Suricata Alert",
                "description": "An alert has been triggered by Suricata IDS.",
                "fields": [
                    {
                        "name": "Signature",
                        "value": signature
                    },
                    {
                        "name": "Severity",
                        "value": matchSeverity(severity)
                    },
                    {
                        "name": "Timestamp",
                        "value": timestamp
                    },
                    {
                        "name": "Source ➜ Destination",
                        "value": buildSD(src_ip, src_port, dst_ip, dst_port)
                    },
                ],
                "color": color
            }
        ]
    }

    response = requests.post(DISCORD_WEBHOOK_URL, json=embed)

    if response.status_code == 204:
        printAndLog("[*] Notification sent successfully!")
    else:
        printAndLog("[*] Failed to send notification!")

def sendToSlack(
        signature: str,
        severity: int,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        timestamp: str,
    ):

    if not SEND_TO_SLACK:
        return

    printAndLog("[*] Sending notification to Slack...")
    payload = {
        "text": "*An alert has been triggered by Suricata IDS.*",
        "attachments": [
            {
                "color": colors["slack"].get(severity, colors["slack"]["default"]),
                "fields": [
                    {
                        "title": "Signature",
                        "value": signature
                    },
                    {
                        "title": "Severity",
                        "value": matchSeverity(severity)
                    },
                    {
                        "title": "Timestamp",
                        "value": timestamp
                    },
                    {
                        "title": "Source ➜ Destination",
                        "value": buildSD(src_ip, src_port, dst_ip, dst_port)
                    },
                ],
                "actions": [
                    {
                        "type": "button",
                        "text": "Whois Source IP",
                        "url": f"https://whois.com/whois/{src_ip}"
                    },
                    {
                        "type": "button",
                        "text": "IP reputation",
                        "url": f"https://www.abuseipdb.com/check/{src_ip}"
                    }
                ]
            }
        ]
    }

    response = requests.post(SLACK_WEBHOOK_URL, json=payload)

    if response.status_code == 200:
        printAndLog("[*] Notification sent successfully!")
    else:
        printAndLog("[*] Failed to send notification!")

def sendToEmail(
        signature: str,
        severity: int,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        timestamp: str,
    ):

    if not SEND_TO_EMAIL:
        return
    
    printAndLog("[*] Sending notification to Email...")

    subject = f"Suricata Alert: {signature}"
    body = f"""
    An alert has been triggered by Suricata IDS.

    Signature: {signature}

    Severity: {matchSeverity(severity)}

    Timestamp: {timestamp}

    Source ➜ Destination: {buildSD(src_ip, src_port, dst_ip, dst_port)}
    """

    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = EMAIL_RECIPIENT
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    with smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        printAndLog("[*] Notification sent successfully!")

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

def checkForDetection():
    printAndLog("[*] Reading log file...")
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

                # Prepare the alert data
                alert_data = {
                    "signature": alert["alert"]["signature"],
                    "severity": alert["alert"]["severity"],
                    "src_ip": alert["src_ip"],
                    "src_port": alert["src_port"],
                    "dst_ip": alert["dest_ip"],
                    "dst_port": alert["dest_port"],
                    "timestamp": alert["timestamp"]
                }

                # Send the alert to the configured channels
                sendToDiscord(**alert_data)
                sendToSlack(**alert_data)
                sendToEmail(**alert_data)

                # Update the detection history
                createOrUpdateHistory(
                    alert["timestamp"],
                    alert["alert"]["signature_id"]
                )

                # Update the last checked line
                last_checked_line = i+1
    except Exception as e:
        printAndLog("[*] An error occurred while reading log file: " + str(e))

def InternetCheck():
    try:
        requests.get("https://www.google.com")
        return True
    except requests.ConnectionError:
        try:
            requests.get("https://www.cloudflare.com")
            return True
        except requests.ConnectionError:
            return False

# Main function
def main():
    try:
        while True:
            checkForDetection()
            time.sleep(waiting_time)
    except KeyboardInterrupt:
        printAndLog("[*] Stopping notifier [*]")
    
# Entry point
if __name__ == "__main__":
    printAndLog("[*] Suricata IDS notifier started... [*]")

    # Check if the log file exists
    if not fileExists():
        printAndLog("[*] Log file not found! Stoping notifier... [*]")
        exit()
    
    # Check if there is internet connection
    if not InternetCheck():
        printAndLog("[*] No internet connection! Stoping notifier... [*]")
        exit()

    # Check if at least one alert channel is configured
    if not SEND_TO_DISCORD and not SEND_TO_SLACK and not SEND_TO_EMAIL:
        printAndLog("[*] No alert channels configured! Stoping notifier... [*]")
        exit()

    # Start the notifier
    main()