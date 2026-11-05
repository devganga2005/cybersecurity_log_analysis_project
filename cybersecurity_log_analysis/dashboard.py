
import tkinter as tk
from tkinter import ttk, messagebox
import csv
import os
import numpy as np

from datetime import datetime
from collections import Counter

import matplotlib
matplotlib.use("TkAgg")

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


# ==========================================
# CONFIGURATION
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(BASE_DIR, "login_logs.csv")

THRESHOLD = 5

BG = "#101827"
PANEL = "#1B2638"
CARD = "#243247"
TEXT = "#F1F5F9"
MUTED = "#A0AEC0"
GREEN = "#22C55E"
RED = "#EF4444"
BLUE = "#38BDF8"
ORANGE = "#F59E0B"


# ==========================================
# READ AND ANALYZE DATA
# ==========================================

def analyze_logs():

    timestamps = []
    ip_addresses = []
    statuses = []

    with open(CSV_FILE, "r", newline="") as file:

        reader = csv.DictReader(file)

        required = {"timestamp", "ip_address", "status"}

        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError("CSV file is missing required columns.")

        for row in reader:

            timestamp = datetime.strptime(
                row["timestamp"].strip(),
                "%Y-%m-%d %H:%M:%S"
            )

            ip = row["ip_address"].strip()

            status = row["status"].strip().capitalize()

            if not ip or status not in ("Success", "Failed"):
                continue

            timestamps.append(timestamp)
            ip_addresses.append(ip)
            statuses.append(status)

    if not statuses:
        raise ValueError("No valid login records found.")

    success = statuses.count("Success")
    failed = statuses.count("Failed")

    unique_ips = sorted(set(ip_addresses))

    failed_by_ip = {
        ip: sum(
            1 for i in range(len(ip_addresses))
            if ip_addresses[i] == ip and statuses[i] == "Failed"
        )
        for ip in unique_ips
    }

    total_by_ip = Counter(ip_addresses)

    suspicious = {
        ip: count
        for ip, count in failed_by_ip.items()
        if count >= THRESHOLD
    }

    hours = [t.hour for t in timestamps]

    hourly_activity = np.bincount(hours, minlength=24)

    return {
        "timestamps": timestamps,
        "ips": ip_addresses,
        "statuses": statuses,
        "success": success,
        "failed": failed,
        "total": len(statuses),
        "unique_ips": len(unique_ips),
        "failed_by_ip": failed_by_ip,
        "total_by_ip": total_by_ip,
        "suspicious": suspicious,
        "hourly": hourly_activity
    }


# ==========================================
# MAIN DASHBOARD WINDOW
# ==========================================

root = tk.Tk()

root.title("Cybersecurity Log Analysis Dashboard")
root.geometry("1250x850")
root.minsize(950, 700)
root.configure(bg=BG)


# ==========================================
# HEADER
# ==========================================

header = tk.Frame(root, bg=BG)
header.pack(fill="x", padx=25, pady=15)

title = tk.Label(
    header,
    text="CYBERSECURITY MONITOR",
    font=("Arial", 23, "bold"),
    bg=BG,
    fg=TEXT
)
title.pack(side="left")

subtitle = tk.Label(
    header,
    text="LOG ANALYSIS & THREAT DETECTION",
    font=("Arial", 10),
    bg=BG,
    fg=BLUE
)
subtitle.pack(side="left", padx=20, pady=8)


# ==========================================
# STATUS BAR
# ==========================================

status_label = tk.Label(
    header,
    text="● SYSTEM READY",
    font=("Arial", 10, "bold"),
    bg=BG,
    fg=GREEN
)
status_label.pack(side="right")


# ==========================================
# KPI CARDS
# ==========================================

kpi_frame = tk.Frame(root, bg=BG)
kpi_frame.pack(fill="x", padx=20, pady=10)

def create_card(parent, title, color):

    card = tk.Frame(
        parent,
        bg=CARD,
        padx=15,
        pady=15,
        highlightbackground="#34445C",
        highlightthickness=1
    )

    label = tk.Label(
        card,
        text=title,
        font=("Arial", 10, "bold"),
        bg=CARD,
        fg=MUTED
    )
    label.pack(anchor="w")

    value = tk.Label(
        card,
        text="0",
        font=("Arial", 25, "bold"),
        bg=CARD,
        fg=color
    )
    value.pack(anchor="w", pady=8)

    return card, value


card1, total_value = create_card(
    kpi_frame, "TOTAL ATTEMPTS", BLUE
)

card2, success_value = create_card(
    kpi_frame, "SUCCESSFUL LOGINS", GREEN
)

card3, failed_value = create_card(
    kpi_frame, "FAILED LOGINS", RED
)

card4, suspicious_value = create_card(
    kpi_frame, "SUSPICIOUS IPs", ORANGE
)

for card in [card1, card2, card3, card4]:
    card.pack(side="left", expand=True, fill="x", padx=7)


# ==========================================
# MAIN CONTENT AREA
# ==========================================

content = tk.Frame(root, bg=BG)
content.pack(fill="both", expand=True, padx=20, pady=10)

# LEFT: CHARTS

chart_panel = tk.Frame(content, bg=PANEL)
chart_panel.pack(
    side="left",
    fill="both",
    expand=True,
    padx=(0, 10)
)

chart_title = tk.Label(
    chart_panel,
    text="SECURITY ANALYTICS",
    font=("Arial", 13, "bold"),
    bg=PANEL,
    fg=TEXT
)
chart_title.pack(anchor="w", padx=15, pady=10)


# Matplotlib figure

fig = Figure(
    figsize=(8, 6),
    dpi=100,
    facecolor=PANEL
)

ax1 = fig.add_subplot(221)
ax2 = fig.add_subplot(222)
ax3 = fig.add_subplot(223)
ax4 = fig.add_subplot(224)

axes = [ax1, ax2, ax3, ax4]

for ax in axes:
    ax.set_facecolor(CARD)
    ax.tick_params(colors=TEXT, labelsize=7)
    ax.title.set_color(TEXT)
    ax.xaxis.label.set_color(TEXT)
    ax.yaxis.label.set_color(TEXT)
    for spine in ax.spines.values():
        spine.set_color("#53647A")

fig.tight_layout(pad=3)


canvas = FigureCanvasTkAgg(
    fig,
    master=chart_panel
)

canvas.get_tk_widget().pack(
    fill="both",
    expand=True,
    padx=8,
    pady=8
)


# ==========================================
# RIGHT: SECURITY ALERTS
# ==========================================

alert_panel = tk.Frame(
    content,
    bg=PANEL,
    width=330
)

alert_panel.pack(
    side="right",
    fill="y"
)

alert_panel.pack_propagate(False)

alert_title = tk.Label(
    alert_panel,
    text="SECURITY ALERTS",
    font=("Arial", 13, "bold"),
    bg=PANEL,
    fg=TEXT
)

alert_title.pack(anchor="w", padx=15, pady=12)


alert_description = tk.Label(
    alert_panel,
    text="IPs with 5 or more failed attempts",
    font=("Arial", 9),
    bg=PANEL,
    fg=MUTED
)

alert_description.pack(anchor="w", padx=15, pady=3)


# Table style

style = ttk.Style()

style.theme_use("clam")

style.configure(
    "Treeview",
    background=CARD,
    foreground=TEXT,
    fieldbackground=CARD,
    rowheight=30,
    font=("Arial", 9)
)

style.configure(
    "Treeview.Heading",
    background="#34445C",
    foreground=TEXT,
    font=("Arial", 9, "bold")
)

style.map(
    "Treeview",
    background=[("selected", "#2563EB")]
)


table = ttk.Treeview(
    alert_panel,
    columns=("IP", "Failed"),
    show="headings",
    height=10
)

table.heading("IP", text="IP ADDRESS")
table.heading("Failed", text="FAILED")

table.column("IP", width=190)
table.column("Failed", width=80, anchor="center")

table.pack(
    fill="x",
    padx=10,
    pady=10
)


alert_message = tk.Label(
    alert_panel,
    text="Waiting for analysis...",
    bg=PANEL,
    fg=GREEN,
    font=("Arial", 10, "bold"),
    wraplength=280,
    justify="left"
)

alert_message.pack(anchor="w", padx=15, pady=15)


# ==========================================
# CHART UPDATE FUNCTION
# ==========================================

def update_charts(data):

    for ax in axes:
        ax.clear()
        ax.set_facecolor(CARD)
        ax.tick_params(colors=TEXT, labelsize=7)

        for spine in ax.spines.values():
            spine.set_color("#53647A")

    # Chart 1: Login status

    ax1.bar(
        ["Success", "Failed"],
        [data["success"], data["failed"]],
        color=[GREEN, RED]
    )

    ax1.set_title("LOGIN STATUS", fontsize=10)
    ax1.set_ylabel("Attempts", color=TEXT)

    # Chart 2: Failed logins by IP

    failed_data = data["failed_by_ip"]

    top_ips = sorted(
        failed_data,
        key=failed_data.get,
        reverse=True
    )[:8]

    ax2.bar(
        top_ips,
        [failed_data[ip] for ip in top_ips],
        color=ORANGE
    )

    ax2.axhline(
        THRESHOLD,
        color=RED,
        linestyle="--",
        linewidth=1
    )

    ax2.set_title("FAILED LOGINS BY IP", fontsize=10)
    ax2.tick_params(axis="x", rotation=45)

    # Chart 3: Hourly activity

    ax3.plot(
        range(24),
        data["hourly"],
        marker="o",
        color=BLUE
    )

    ax3.set_title("HOURLY LOGIN ACTIVITY", fontsize=10)
    ax3.set_xlabel("Hour", color=TEXT)
    ax3.set_ylabel("Attempts", color=TEXT)
    ax3.set_xticks(range(0, 24, 3))
    ax3.grid(alpha=0.2)

    # Chart 4: IP distribution

    ip_data = data["total_by_ip"].most_common(6)

    labels = [item[0] for item in ip_data]
    values = [item[1] for item in ip_data]

    if labels:
        ax4.pie(
            values,
            labels=labels,
            autopct="%1.0f%%",
            textprops={"color": TEXT, "fontsize": 7}
        )

    ax4.set_title("IP ACTIVITY DISTRIBUTION", fontsize=10)

    fig.tight_layout(pad=3)
    canvas.draw()


# ==========================================
# REFRESH DASHBOARD
# ==========================================

def refresh_dashboard():

    try:

        data = analyze_logs()

        # Update KPI cards

        total_value.config(text=str(data["total"]))
        success_value.config(text=str(data["success"]))
        failed_value.config(text=str(data["failed"]))
        suspicious_value.config(
            text=str(len(data["suspicious"]))
        )

        # Update alert table

        for item in table.get_children():
            table.delete(item)

        for ip, count in sorted(
            data["suspicious"].items(),
            key=lambda item: item[1],
            reverse=True
        ):

            table.insert(
                "",
                "end",
                values=(ip, count)
            )

        # Update alert message

        if data["suspicious"]:

            alert_message.config(
                text="WARNING: Suspicious login activity detected!",
                fg=RED
            )

        else:

            alert_message.config(
                text="No suspicious IP addresses detected.",
                fg=GREEN
            )

        # Update charts

        update_charts(data)

        status_label.config(
            text="● ANALYSIS COMPLETE",
            fg=GREEN
        )

        print("Dashboard refreshed successfully.")

    except FileNotFoundError:

        messagebox.showerror(
            "Dataset Error",
            "login_logs.csv was not found."
        )

    except Exception as error:

        messagebox.showerror(
            "Analysis Error",
            str(error)
        )


# ==========================================
# REFRESH BUTTON
# ==========================================

button = tk.Button(
    root,
    text="↻ REFRESH DASHBOARD",
    command=refresh_dashboard,
    bg="#2563EB",
    fg="white",
    activebackground="#1D4ED8",
    activeforeground="white",
    font=("Arial", 11, "bold"),
    relief="flat",
    padx=20,
    pady=10,
    cursor="hand2"
)

button.pack(pady=10)


# ==========================================
# FOOTER
# ==========================================

footer = tk.Label(
    root,
    text="Cybersecurity Log Analysis System | BCA Minor Project",
    font=("Arial", 9),
    bg=BG,
    fg=MUTED
)

footer.pack(pady=8)


# Load data when application starts

refresh_dashboard()

root.mainloop()
