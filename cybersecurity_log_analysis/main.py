
import csv
import os
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
from collections import Counter

# ---------------------------------
# 1. Read the CSV dataset
# ---------------------------------

file_name = "login_logs.csv"

timestamps = []
ip_addresses = []
usernames = []
statuses = []

with open(file_name, "r") as file:
    reader = csv.DictReader(file)

    for row in reader:
        timestamps.append(
            datetime.strptime(
                row["timestamp"], "%Y-%m-%d %H:%M:%S"
            )
        )
        ip_addresses.append(row["ip_address"])
        usernames.append(row["username"])
        statuses.append(row["status"].strip().capitalize())

print("\n===== CYBERSECURITY LOG ANALYSIS =====")

# ---------------------------------
# 2. Calculate login statistics
# ---------------------------------

total_logs = len(statuses)

success_count = statuses.count("Success")
failed_count = statuses.count("Failed")

print("\nTotal Login Attempts:", total_logs)
print("Successful Logins:", success_count)
print("Failed Logins:", failed_count)

# ---------------------------------
# 3. Analyze IP addresses
# ---------------------------------

unique_ips = sorted(set(ip_addresses))

failed_by_ip = {}
total_by_ip = {}

for ip in unique_ips:
    total_by_ip[ip] = ip_addresses.count(ip)

    failed_by_ip[ip] = sum(
        1 for i in range(total_logs)
        if ip_addresses[i] == ip
        and statuses[i] == "Failed"
    )

# ---------------------------------
# 4. Detect suspicious IP addresses
# ---------------------------------

threshold = 5

suspicious_ips = [
    ip for ip in unique_ips
    if failed_by_ip[ip] >= threshold
]

print("\n===== SUSPICIOUS IP ADDRESSES =====")

if suspicious_ips:
    for ip in suspicious_ips:
        print(
            ip, "-",
            failed_by_ip[ip],
            "failed login attempts"
        )
else:
    print("No suspicious IP addresses found.")

# ---------------------------------
# 5. Identify most active IP
# ---------------------------------

most_active_ip = max(
    total_by_ip,
    key=total_by_ip.get
)

print("\nMost Active IP:", most_active_ip)
print("Total Attempts:", total_by_ip[most_active_ip])

# ---------------------------------
# 6. Calculate statistics using NumPy
# ---------------------------------

login_array = np.array(
    [success_count, failed_count]
)

print("\n===== NUMPY ANALYSIS =====")

print("Average attempts per IP:",
      np.mean(list(total_by_ip.values())))

print("Maximum failed attempts:",
      np.max(list(failed_by_ip.values())))

print("Minimum failed attempts:",
      np.min(list(failed_by_ip.values())))

# ---------------------------------
# 7. Prepare graph folder
# ---------------------------------

os.makedirs("graphs", exist_ok=True)

# ---------------------------------
# GRAPH 1: Successful vs Failed Logins
# ---------------------------------

plt.figure(figsize=(7, 5))

plt.bar(
    ["Successful", "Failed"],
    login_array
)

plt.title("Login Attempt Analysis")
plt.xlabel("Login Status")
plt.ylabel("Number of Attempts")

plt.savefig("graphs/login_status.png")
plt.show()

# ---------------------------------
# GRAPH 2: Failed Attempts by IP
# ---------------------------------

plt.figure(figsize=(9, 5))

plt.bar(
    unique_ips,
    [failed_by_ip[ip] for ip in unique_ips]
)

plt.axhline(
    y=threshold,
    linestyle="--",
    label="Suspicious Threshold"
)

plt.title("Failed Login Attempts by IP")
plt.xlabel("IP Address")
plt.ylabel("Failed Attempts")
plt.xticks(rotation=45)
plt.legend()
plt.tight_layout()

plt.savefig("graphs/failed_logins.png")
plt.show()

# ---------------------------------
# GRAPH 3: Login Activity by Hour
# ---------------------------------

hours = [time.hour for time in timestamps]

hour_counts = np.bincount(hours, minlength=24)

plt.figure(figsize=(9, 5))

plt.plot(
    range(24),
    hour_counts,
    marker="o"
)

plt.title("Login Activity by Hour")
plt.xlabel("Hour of the Day")
plt.ylabel("Number of Login Attempts")
plt.xticks(range(24))
plt.grid()

plt.savefig("graphs/hourly_activity.png")
plt.show()

# ---------------------------------
# GRAPH 4: IP Activity Distribution
# ---------------------------------

plt.figure(figsize=(8, 6))

plt.pie(
    [total_by_ip[ip] for ip in unique_ips],
    labels=unique_ips,
    autopct="%1.1f%%",
    startangle=90
)

plt.title("Login Activity Distribution by IP")

plt.savefig("graphs/ip_distribution.png")
plt.show()

# ---------------------------------
# 8. Final Security Report
# ---------------------------------

print("\n===== FINAL SECURITY REPORT =====")

print("Total Records:", total_logs)
print("Successful Logins:", success_count)
print("Failed Logins:", failed_count)
print("Unique IP Addresses:", len(unique_ips))
print("Suspicious IP Addresses:", len(suspicious_ips))

print("\nGenerated Graphs:")
print("1. login_status.png")
print("2. failed_logins.png")
print("3. hourly_activity.png")
print("4. ip_distribution.png")

print("\nSecurity Analysis Completed!")
