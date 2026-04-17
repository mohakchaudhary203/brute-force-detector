import csv
from datetime import datetime
from collections import defaultdict

FAILED_THRESHOLD = 3
TIME_WINDOW_MINUTES = 5

def parse_time(t):
    return datetime.strptime(t, "%Y-%m-%d %H:%M:%S")

def load_logs():
    with open("logs.csv", "r") as f:
        return list(csv.DictReader(f))

def analyze():
    logs = load_logs()

    user_attempts = defaultdict(list)
    ip_users = defaultdict(set)

    alerts = []

    print("="*50)
    print("   ADVANCED BRUTE FORCE DETECTOR")
    print("="*50)

    # Store attempts
    for log in logs:
        user = log["user"]
        ip = log["ip"]
        status = log["status"]
        time = parse_time(log["timestamp"])

        user_attempts[user].append((time, status))

        if status == "FAILED":
            ip_users[ip].add(user)

    # 🔹 Rule 1: Rapid failed logins
    for user, attempts in user_attempts.items():
        failed_times = [t for t, s in attempts if s == "FAILED"]

        for i in range(len(failed_times)):
            window = [
                t for t in failed_times
                if 0 <= (t - failed_times[i]).total_seconds()/60 <= TIME_WINDOW_MINUTES
            ]

            if len(window) >= FAILED_THRESHOLD:
                alerts.append((user, "-", "Rapid failed logins", "HIGH"))
                break

    # 🔹 Rule 2: Success after failures
    for user, attempts in user_attempts.items():
        failures = 0
        for t, status in attempts:
            if status == "FAILED":
                failures += 1
            elif status == "SUCCESS" and failures >= FAILED_THRESHOLD:
                alerts.append((user, "-", "Success after multiple failures", "CRITICAL"))
                break

    # 🔹 Rule 3: IP attacking multiple users
    for ip, users in ip_users.items():
        if len(users) >= 3:
            alerts.append(("Multiple Users", ip, "IP targeting multiple accounts", "HIGH"))

    # 🔹 Remove duplicates
    unique_alerts = []
    seen = set()

    for a in alerts:
        key = (a[0], a[2])
        if key not in seen:
            unique_alerts.append(a)
            seen.add(key)

    alerts = unique_alerts

    # 🔹 Improved Risk Scoring (per user cap)
    risk_map = {"LOW":10, "MEDIUM":30, "HIGH":50, "CRITICAL":80}
    user_risk = {}

    for a in alerts:
        user = a[0]
        severity = a[3]
        score = risk_map[severity]

        if user not in user_risk or user_risk[user] < score:
            user_risk[user] = score

    total_risk = sum(user_risk.values())

    # 🔹 Output
    print("\n--- ALERTS ---\n")
    for a in alerts:
        print(f"User: {a[0]} | IP: {a[1]} | Issue: {a[2]} | Severity: {a[3]}")

    print("\n--- RISK SCORE ---\n")
    print(f"Total Risk Score: {total_risk}")

    # 🔹 Final Verdict
    if total_risk >= 150:
        print("\nFINAL STATUS: SYSTEM UNDER ATTACK 🔴")
    elif total_risk >= 80:
        print("\nFINAL STATUS: HIGH RISK 🟠")
    else:
        print("\nFINAL STATUS: NORMAL 🟢")

    # 🔹 Save report
    with open("report.txt", "w") as f:
        f.write("Brute Force Detection Report\n\n")
        for a in alerts:
            f.write(f"{a}\n")
        f.write(f"\nTotal Risk Score: {total_risk}\n")

    print("\nReport saved as report.txt\n")

if __name__ == "__main__":
    analyze()