
import tkinter as tk
from tkinter import ttk, messagebox
import csv
import os
import numpy as np
from datetime import datetime
from collections import Counter
from collections import deque
import matplotlib
matplotlib.use("TkAgg")

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


# ==========================================
# 1. CONFIGURATION
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(BASE_DIR, "login_logs.csv")

THRESHOLD = 5

BG = "#101827"
PANEL = "#1B2638"
CARD = "#243247"
WHITE = "#F1F5F9"
MUTED = "#A0AEC0"
GREEN = "#22C55E"
RED = "#EF4444"
BLUE = "#38BDF8"
ORANGE = "#F59E0B"

# Demo credentials only
USERS = {
    "admin": "admin123",
    "student": "student123"
}


# ==========================================
# 2. CREATE CSV IF NOT AVAILABLE
# ==========================================

def initialize_csv():

    if not os.path.exists(CSV_FILE):

        with open(CSV_FILE, "w", newline="") as file:

            writer = csv.writer(file)

            writer.writerow([
                "timestamp",
                "ip_address",
                "username",
                "status"
            ])


# ==========================================
# 3. SAVE LOGIN ATTEMPT
# ==========================================

def save_login(username, ip, status):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open(CSV_FILE, "a", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            ip,
            username,
            status
        ])


# ==========================================
# 4. READ LOGIN LOGS
# ==========================================

def analyze_logs():

    records = []

    with open(CSV_FILE, "r", newline="") as file:

        reader = csv.DictReader(file)

        required = {
            "timestamp",
            "ip_address",
            "username",
            "status"
        }

        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError("Invalid CSV file format.")

        for row in reader:

            try:

                timestamp = datetime.strptime(
                    row["timestamp"].strip(),
                    "%Y-%m-%d %H:%M:%S"
                )

                ip = row["ip_address"].strip()
                username = row["username"].strip()
                status = row["status"].strip().capitalize()

                if not ip or status not in ("Success", "Failed"):
                    continue

                records.append({
                    "timestamp": timestamp,
                    "ip": ip,
                    "username": username,
                    "status": status
                })

            except (ValueError, AttributeError):
                continue

    if not records:
        return {
            "records": [],
            "total": 0,
            "success": 0,
            "failed": 0,
            "unique_ips": 0,
            "suspicious": {},
            "hourly": np.zeros(24, dtype=int),
            "failed_by_ip": {},
            "total_by_ip": Counter()
        }

    statuses = [r["status"] for r in records]
    ips = [r["ip"] for r in records]

    success = statuses.count("Success")
    failed = statuses.count("Failed")

    total_by_ip = Counter(ips)

    failed_by_ip = {}

    for ip in set(ips):

        failed_by_ip[ip] = sum(
            1 for r in records
            if r["ip"] == ip and r["status"] == "Failed"
        )

    suspicious = {
        ip: count
        for ip, count in failed_by_ip.items()
        if count >= THRESHOLD
    }

    hours = [
        r["timestamp"].hour for r in records
    ]

    hourly = np.bincount(hours, minlength=24)

    return {
        "records": records,
        "total": len(records),
        "success": success,
        "failed": failed,
        "unique_ips": len(set(ips)),
        "suspicious": suspicious,
        "hourly": hourly,
        "failed_by_ip": failed_by_ip,
        "total_by_ip": total_by_ip
    }


# ==========================================
# 5. MAIN WINDOW
# ==========================================

root = tk.Tk()

root.title("CyberShield - Cybersecurity Monitoring System")
root.geometry("1250x850")
root.minsize(1000, 700)
root.configure(bg=BG)


# ==========================================
# 6. HEADER
# ==========================================

header = tk.Frame(root, bg=BG)

header.pack(fill="x", padx=25, pady=15)

tk.Label(
    header,
    text="🛡 CYBERSHIELD",
    font=("Arial", 22, "bold"),
    bg=BG,
    fg=BLUE
).pack(side="left")

tk.Label(
    header,
    text="LOGIN SECURITY & THREAT MONITORING",
    font=("Arial", 10, "bold"),
    bg=BG,
    fg=MUTED
).pack(side="left", padx=20, pady=10)


# ==========================================
# 7. NOTEBOOK / TABS
# ==========================================

style = ttk.Style()

style.theme_use("clam")

style.configure(
    "TNotebook",
    background=BG,
    borderwidth=0
)

style.configure(
    "TNotebook.Tab",
    background=CARD,
    foreground=WHITE,
    padding=[22, 10],
    font=("Arial", 10, "bold")
)

style.map(
    "TNotebook.Tab",
    background=[("selected", "#2563EB")],
    foreground=[("selected", "white")]
)

notebook = ttk.Notebook(root)

notebook.pack(
    fill="both",
    expand=True,
    padx=20,
    pady=10
)

login_tab = tk.Frame(notebook, bg=BG)

dashboard_tab = tk.Frame(notebook, bg=BG)

notebook.add(login_tab, text="LOGIN PORTAL")

notebook.add(dashboard_tab, text="SECURITY DASHBOARD")


# ==========================================
# 8. LOGIN PORTAL
# ==========================================

login_container = tk.Frame(
    login_tab,
    bg=BG
)

login_container.place(
    relx=0.5,
    rely=0.48,
    anchor="center"
)

login_card = tk.Frame(
    login_container,
    bg=PANEL,
    padx=40,
    pady=30,
    highlightbackground="#34445C",
    highlightthickness=1
)

login_card.pack()

tk.Label(
    login_card,
    text="🔐",
    font=("Arial", 38),
    bg=PANEL,
    fg=BLUE
).pack(pady=5)

tk.Label(
    login_card,
    text="SECURE LOGIN",
    font=("Arial", 23, "bold"),
    bg=PANEL,
    fg=WHITE
).pack()

tk.Label(
    login_card,
    text="Enter your credentials to access the system",
    font=("Arial", 10),
    bg=PANEL,
    fg=MUTED
).pack(pady=8)


# Username

tk.Label(
    login_card,
    text="USERNAME",
    font=("Arial", 10, "bold"),
    bg=PANEL,
    fg=WHITE
).pack(anchor="w", pady=(15, 5))

username_entry = tk.Entry(
    login_card,
    width=35,
    font=("Arial", 12),
    bg=CARD,
    fg=WHITE,
    insertbackground=WHITE,
    relief="flat"
)

username_entry.pack(ipady=10)


# Password

tk.Label(
    login_card,
    text="PASSWORD",
    font=("Arial", 10, "bold"),
    bg=PANEL,
    fg=WHITE
).pack(anchor="w", pady=(15, 5))

password_entry = tk.Entry(
    login_card,
    width=35,
    font=("Arial", 12),
    bg=CARD,
    fg=WHITE,
    insertbackground=WHITE,
    show="*",
    relief="flat"
)

password_entry.pack(ipady=10)


# Simulated IP

tk.Label(
    login_card,
    text="SIMULATED IP ADDRESS",
    font=("Arial", 10, "bold"),
    bg=PANEL,
    fg=WHITE
).pack(anchor="w", pady=(15, 5))

ip_entry = tk.Entry(
    login_card,
    width=35,
    font=("Arial", 12),
    bg=CARD,
    fg=WHITE,
    insertbackground=WHITE,
    relief="flat"
)

ip_entry.insert(0, "192.0.2.10")

ip_entry.pack(ipady=10)


# Login result message

login_message = tk.Label(
    login_card,
    text="SYSTEM READY - WAITING FOR LOGIN",
    font=("Arial", 10, "bold"),
    bg=PANEL,
    fg=BLUE
)

login_message.pack(pady=18)


# ==========================================
# 9. DASHBOARD VARIABLES
# ==========================================

kpi_values = {}

for name in [
    "TOTAL ATTEMPTS",
    "SUCCESSFUL",
    "FAILED",
    "SUSPICIOUS IPs"
]:

    kpi_values[name] = None


# ==========================================
# 10. DASHBOARD HEADER
# ==========================================

dash_header = tk.Frame(
    dashboard_tab,
    bg=BG
)

dash_header.pack(
    fill="x",
    padx=15,
    pady=12
)

tk.Label(
    dash_header,
    text="SECURITY OVERVIEW",
    font=("Arial", 18, "bold"),
    bg=BG,
    fg=WHITE
).pack(side="left")

system_status = tk.Label(
    dash_header,
    text="● MONITORING ACTIVE",
    font=("Arial", 10, "bold"),
    bg=BG,
    fg=GREEN
)

system_status.pack(side="right")


# ==========================================
# 11. KPI CARDS
# ==========================================

kpi_frame = tk.Frame(
    dashboard_tab,
    bg=BG
)

kpi_frame.pack(
    fill="x",
    padx=10,
    pady=5
)


def create_kpi(parent, title, color):

    card = tk.Frame(
        parent,
        bg=CARD,
        padx=15,
        pady=12,
        highlightbackground="#34445C",
        highlightthickness=1
    )

    tk.Label(
        card,
        text=title,
        font=("Arial", 9, "bold"),
        bg=CARD,
        fg=MUTED
    ).pack(anchor="w")

    value = tk.Label(
        card,
        text="0",
        font=("Arial", 23, "bold"),
        bg=CARD,
        fg=color
    )

    value.pack(anchor="w", pady=5)

    return card, value


colors = [BLUE, GREEN, RED, ORANGE]

for i, name in enumerate(kpi_values):

    card, value = create_kpi(
        kpi_frame,
        name,
        colors[i]
    )

    card.pack(
        side="left",
        expand=True,
        fill="x",
        padx=5
    )

    kpi_values[name] = value


# ==========================================
# 12. CHART AND ALERT AREA
# ==========================================

main_area = tk.Frame(
    dashboard_tab,
    bg=BG
)

main_area.pack(
    fill="both",
    expand=True,
    padx=10,
    pady=10
)


# Charts

chart_panel = tk.Frame(
    main_area,
    bg=PANEL
)

chart_panel.pack(
    side="left",
    fill="both",
    expand=True,
    padx=(0, 10)
)

tk.Label(
    chart_panel,
    text="LOGIN ACTIVITY ANALYTICS",
    font=("Arial", 12, "bold"),
    bg=PANEL,
    fg=WHITE
).pack(anchor="w", padx=12, pady=8)


fig = Figure(
    figsize=(8, 5),
    dpi=90,
    facecolor=PANEL
)

ax1 = fig.add_subplot(221)
ax2 = fig.add_subplot(222)
ax3 = fig.add_subplot(223)
ax4 = fig.add_subplot(224)

axes = [ax1, ax2, ax3, ax4]


def style_axis(ax):

    ax.set_facecolor(CARD)

    ax.tick_params(
        colors=WHITE,
        labelsize=7
    )

    ax.title.set_color(WHITE)

    for spine in ax.spines.values():
        spine.set_color("#53647A")


for ax in axes:
    style_axis(ax)


fig.tight_layout(pad=2.5)

canvas = FigureCanvasTkAgg(
    fig,
    master=chart_panel
)

canvas.get_tk_widget().pack(
    fill="both",
    expand=True,
    padx=5,
    pady=5
)


# ==========================================
# 13. ALERT PANEL
# ==========================================

alert_panel = tk.Frame(
    main_area,
    bg=PANEL,
    width=290
)

alert_panel.pack(
    side="right",
    fill="y"
)

alert_panel.pack_propagate(False)

tk.Label(
    alert_panel,
    text="🚨 SECURITY ALERTS",
    font=("Arial", 12, "bold"),
    bg=PANEL,
    fg=RED
).pack(anchor="w", padx=12, pady=12)


alert_table = ttk.Treeview(
    alert_panel,
    columns=("IP", "Count"),
    show="headings",
    height=7
)

style.configure(
    "Treeview",
    background=CARD,
    foreground=WHITE,
    fieldbackground=CARD,
    rowheight=27,
    font=("Arial", 9)
)

style.configure(
    "Treeview.Heading",
    background="#34445C",
    foreground=WHITE
)

alert_table.heading("IP", text="IP ADDRESS")
alert_table.heading("Count", text="FAILURES")

alert_table.column("IP", width=150)
alert_table.column("Count", width=80, anchor="center")

alert_table.pack(
    fill="x",
    padx=8,
    pady=5
)


tk.Label(
    alert_panel,
    text="RECENT LOGIN ACTIVITY",
    font=("Arial", 11, "bold"),
    bg=PANEL,
    fg=WHITE
).pack(anchor="w", padx=12, pady=(15, 5))


activity_table = ttk.Treeview(
    alert_panel,
    columns=("User", "Status"),
    show="headings",
    height=8
)

activity_table.heading("User", text="USERNAME")
activity_table.heading("Status", text="RESULT")

activity_table.column("User", width=125)
activity_table.column("Status", width=90)

activity_table.pack(
    fill="both",
    expand=True,
    padx=8,
    pady=5
)


# ==========================================
# 14. REFRESH DASHBOARD
# ==========================================


def refresh_dashboard():

    try:

        # Read the latest CSV records
        data = analyze_logs()

        # =================================
        # UPDATE DASHBOARD STATISTICS
        # =================================

        kpi_values["TOTAL ATTEMPTS"].config(
            text=str(data["total"])
        )

        kpi_values["SUCCESSFUL"].config(
            text=str(data["success"])
        )

        kpi_values["FAILED"].config(
            text=str(data["failed"])
        )

        kpi_values["SUSPICIOUS IPs"].config(
            text=str(len(data["suspicious"]))
        )

        # =================================
        # UPDATE SUSPICIOUS IP TABLE
        # =================================

        for item in alert_table.get_children():
            alert_table.delete(item)

        for ip, count in sorted(
            data["suspicious"].items(),
            key=lambda x: x[1],
            reverse=True
        ):

            alert_table.insert(
                "",
                "end",
                values=(ip, count)
            )

        # =================================
        # UPDATE RECENT LOGIN ACTIVITY
        # =================================

        for item in activity_table.get_children():
            activity_table.delete(item)

        for record in reversed(data["records"][-10:]):

            activity_table.insert(
                "",
                "end",
                values=(
                    record["username"],
                    record["status"]
                ),
                tags=(record["status"],)
            )

        # =================================
        # CLEAR OLD GRAPHS
        # =================================

        for ax in axes:
            ax.clear()
            style_axis(ax)

        # =================================
        # GRAPH 1: LOGIN STATUS
        # =================================

        login_counts = [
            data["success"],
            data["failed"]
        ]

        ax1.bar(
            ["Successful", "Failed"],
            login_counts,
            color=[GREEN, RED],
            width=0.5
        )

        ax1.set_title(
            "LOGIN STATUS",
            color=WHITE,
            fontsize=10,
            fontweight="bold"
        )

        ax1.set_ylabel("Attempts", color=WHITE)

        ax1.set_ylim(
            0,
            max(login_counts + [1]) * 1.25
        )

        # Show values above bars
        for i, value in enumerate(login_counts):

            ax1.text(
                i,
                value,
                str(value),
                color=WHITE,
                ha="center",
                va="bottom"
            )

        # =================================
        # GRAPH 2: FAILED LOGINS BY IP
        # =================================

        failed_data = data["failed_by_ip"]

        top_ips = sorted(
            failed_data,
            key=failed_data.get,
            reverse=True
        )[:7]

        values = [
            failed_data[ip]
            for ip in top_ips
        ]

        ax2.bar(
            top_ips,
            values,
            color=[
                RED if value >= THRESHOLD else ORANGE
                for value in values
            ]
        )

        ax2.axhline(
            y=THRESHOLD,
            color=RED,
            linestyle="--",
            label="Alert Threshold"
        )

        ax2.set_title(
            "FAILED LOGINS BY IP",
            fontsize=10,
            fontweight="bold"
        )

        ax2.tick_params(
            axis="x",
            rotation=45
        )

        ax2.legend(
            fontsize=7,
            facecolor=CARD,
            labelcolor=WHITE
        )

        # =================================
        # GRAPH 3: HOURLY LOGIN ACTIVITY
        # =================================

        hourly_data = data["hourly"]

        ax3.plot(
            range(24),
            hourly_data,
            marker="o",
            linewidth=2,
            color=BLUE
        )

        ax3.fill_between(
            range(24),
            hourly_data,
            alpha=0.2,
            color=BLUE
        )

        ax3.set_title(
            "HOURLY LOGIN ACTIVITY",
            fontsize=10,
            fontweight="bold"
        )

        ax3.set_xlabel("Hour", color=WHITE)

        ax3.set_ylabel("Attempts", color=WHITE)

        ax3.set_xticks(range(0, 24, 3))

        ax3.grid(alpha=0.2)

        # =================================
        # GRAPH 4: IP DISTRIBUTION
        # =================================

        ip_data = data["total_by_ip"].most_common(6)

        if ip_data:

            labels = [
                item[0] for item in ip_data
            ]

            values = [
                item[1] for item in ip_data
            ]

            ax4.pie(
                values,
                labels=labels,
                autopct="%1.1f%%",
                startangle=90,
                textprops={
                    "color": WHITE,
                    "fontsize": 7
                }
            )

        else:

            ax4.text(
                0.5,
                0.5,
                "No login data",
                color=WHITE,
                ha="center",
                va="center"
            )

        ax4.set_title(
            "IP DISTRIBUTION",
            fontsize=10,
            fontweight="bold"
        )

        # =================================
        # DISPLAY UPDATED GRAPHS
        # =================================

        fig.tight_layout(pad=2.5)

        canvas.draw()

        system_status.config(
            text="● LIVE DATA UPDATED",
            fg=GREEN
        )

    except Exception as error:

        messagebox.showerror(
            "Dashboard Error",
            str(error)
        )


# ==========================================
# 15. LOGIN FUNCTION
# ==========================================

def attempt_login():

    username = username_entry.get().strip()
    password = password_entry.get()
    ip = ip_entry.get().strip()

    if not username or not password or not ip:

        messagebox.showwarning(
            "Missing Information",
            "Please enter username, password and IP address."
        )

        return

    if any(char in ip for char in ",\r\n"):

        messagebox.showwarning(
            "Invalid IP",
            "Enter a single simulated IP address."
        )

        return

    # Check credentials

    if USERS.get(username) == password:

        result = "Success"

        login_message.config(
            text="✓ LOGIN SUCCESSFUL - ACCESS GRANTED",
            fg=GREEN
        )

    else:

        result = "Failed"

        login_message.config(
            text="✗ LOGIN FAILED - ACCESS DENIED",
            fg=RED
        )

    # Save the attempt

    save_login(
        username,
        ip,
        result
    )

    # Update dashboard immediately

    refresh_dashboard()

    # Check suspicious activity

    data = analyze_logs()

    if ip in data["suspicious"]:

        messagebox.showwarning(
            "SECURITY ALERT",
            "Suspicious activity detected!\n\n"
            "IP Address: " + ip + "\n"
            "Failed Attempts: " +
            str(data["suspicious"][ip]) +
            "\n\nPossible brute-force activity."
        )

    elif result == "Success":

        messagebox.showinfo(
            "Access Granted",
            "Welcome, " + username + "!\n\n"
            "Login successful."
        )

    else:

        messagebox.showerror(
            "Access Denied",
            "Incorrect username or password."
        )

    # Clear password

    password_entry.delete(0, tk.END)

    # Switch to dashboard

    notebook.select(dashboard_tab)


# ==========================================
# 16. LOGIN BUTTON
# ==========================================

login_button = tk.Button(
    login_card,
    text="SIGN IN  →",
    command=attempt_login,
    font=("Arial", 12, "bold"),
    bg="#2563EB",
    fg=WHITE,
    activebackground="#1D4ED8",
    activeforeground=WHITE,
    relief="flat",
    cursor="hand2"
)

login_button.pack(
    fill="x",
    pady=10,
    ipady=9
)


# Enter key also triggers login

root.bind("<Return>", lambda event: attempt_login())


# ==========================================
# 17. DEMO CREDENTIALS
# ==========================================

tk.Label(
    login_card,
    text="DEMO: admin / admin123\n"
         "DEMO: student / student123",
    font=("Arial", 9),
    bg=PANEL,
    fg=MUTED,
    justify="center"
).pack(pady=10)


# ==========================================
# 18. START APPLICATION
# ==========================================

initialize_csv()

refresh_dashboard()

def auto_refresh():

    refresh_dashboard()

    # Refresh every 3 seconds
    root.after(3000, auto_refresh)


# Start automatic monitoring
root.after(3000, auto_refresh)

# ---------------- LIVE ACTIVITY GRAPH ----------------

MAX_POINTS = 30

time_points = deque(maxlen=MAX_POINTS)
success_points = deque(maxlen=MAX_POINTS)
failed_points = deque(maxlen=MAX_POINTS)

login_counter = 0

# Create graph
live_fig = Figure(figsize=(7, 3), dpi=100)
live_ax = live_fig.add_subplot(111)

live_ax.set_title("LIVE LOGIN ACTIVITY")
live_ax.set_xlabel("Recent Login Attempts")
live_ax.set_ylabel("Number of Logins")
live_ax.set_ylim(0, 1)
live_ax.grid(True)

success_line, = live_ax.plot(
    [], [], marker="o", label="Successful Logins"
)

failed_line, = live_ax.plot(
    [], [], marker="o", label="Failed Logins"
)

live_ax.legend()

live_canvas = FigureCanvasTkAgg(
    live_fig,
    master=dashboard_tab
)

live_canvas.get_tk_widget().pack(
    fill="both",
    expand=True,
    padx=10,
    pady=10
)


def update_live_graph():

    global login_counter

    # Read latest login records
    data = analyze_logs()

    total_success = data["success"]
    total_failed = data["failed"]

    login_counter += 1

    time_points.append(login_counter)
    success_points.append(total_success)
    failed_points.append(total_failed)

    # Update graph
    success_line.set_data(
        list(time_points),
        list(success_points)
    )

    failed_line.set_data(
        list(time_points),
        list(failed_points)
    )

    # Scrolling X-axis
    if len(time_points) > 1:
        live_ax.set_xlim(
            max(0, time_points[0] - 1),
            time_points[-1] + 1
        )

    # Adjust Y-axis automatically
    highest_value = max(
        max(success_points),
        max(failed_points),
        1
    )

    live_ax.set_ylim(0, highest_value + 2)

    live_canvas.draw_idle()

    # Update every second
    root.after(1000, update_live_graph)


# Start live graph
root.after(1000, update_live_graph)


root.mainloop()
