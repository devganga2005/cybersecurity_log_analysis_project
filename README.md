# 🔐 Cybersecurity Log Analysis System

A Python-based cybersecurity monitoring project that analyzes login activity, detects suspicious login attempts, and visualizes security events through an interactive dashboard.

The project simulates a basic Security Operations Center (SOC) monitoring system using Python, NumPy, Matplotlib, and Tkinter.

## 📌 Project Overview

The Cybersecurity Log Analysis System monitors login attempts and analyzes authentication activities to identify potentially suspicious behavior.

It records successful and failed login attempts, tracks login activity by IP address, identifies suspicious IP addresses, and displays the results through graphical visualizations.

The application also includes a simulated login portal connected to a security dashboard, allowing users to observe how login events affect security monitoring.

## ✨ Features

- **Interactive Login Portal:** Simulates user authentication with correct and incorrect credentials.
- **Login Activity Monitoring:** Records login timestamps, usernames, IP addresses, and login status.
- **Failed Login Detection:** Identifies IP addresses with repeated failed login attempts.
- **Real-Time Dashboard Updates:** Updates dashboard information when new login attempts occur.
- **Live Scrolling Activity Graph:** Visualizes successful and failed login activity over time.
- **Data Visualization:** Displays login statistics through multiple graphs.
- **Security Alerts:** Highlights suspicious IP addresses based on repeated failed login attempts.
- **CSV Log Management:** Stores login records in a CSV file for further analysis.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Tkinter | Graphical User Interface (GUI) |
| NumPy | Numerical and data analysis operations |
| Matplotlib | Data visualization and graphs |
| CSV | Login log storage |

## 📊 Dashboard Visualizations

The security dashboard includes:

1. **Login Status Chart:** Displays successful and failed login attempts.
2. **Failed Login by IP:** Shows failed login attempts associated with different IP addresses.
3. **Hourly Activity Graph:** Displays login activity according to the hour.
4. **IP Distribution Chart:** Shows the distribution of login attempts across IP addresses.
5. **Live Scrolling Activity Graph:** Displays login activity as the dashboard receives updates.

## 📁 Project Structure

```text
Cybersecurity_Log_Analysis/
│
├── app.py
│   └── Main application with login portal
│       and interactive security dashboard
│
├── login_logs.csv
│   └── Stores login activity records
│
├── requirements.txt
│   └── Required Python libraries
│
└── README.md
    └── Project documentation
```

## ⚙️ Installation and Setup

### 1. Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with your actual GitHub repository URL.

### 2. Open the Project Folder

```bash
cd Cybersecurity_Log_Analysis
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python app.py
```

## 🔑 Demo Login Credentials

The application uses predefined demo credentials.

| Username | Password |
|---|---|
| admin | admin123 |
| student | student123 |

You can enter incorrect credentials to simulate failed login attempts.

## 🚨 Suspicious Login Detection

The application identifies IP addresses that generate repeated failed login attempts.

For example:

- An IP address attempts to log in multiple times.
- The system records each failed authentication attempt.
- When an IP address reaches the configured threshold of five failed attempts, a security warning is displayed.

This feature demonstrates a basic approach to detecting suspicious authentication activity.

## 📄 Dataset Description

The application maintains login records in `login_logs.csv`.

| Column | Description |
|---|---|
| timestamp | Date and time of login attempt |
| ip_address | IP address entered for the login attempt |
| username | Username used during authentication |
| status | Success or Failed |

Example:

```csv
timestamp,ip_address,username,status
2026-11-05 10:30:00,192.0.2.10,admin,Success
2026-11-05 10:32:00,198.51.100.5,user1,Failed
```

## 🎯 Learning Outcomes

Through this project, the following concepts are demonstrated:

- Understanding basic cybersecurity and login monitoring.
- Applying Python programming concepts in a practical project.
- Working with CSV files for storing and retrieving data.
- Performing data analysis using Python.
- Creating graphical interfaces using Tkinter.
- Visualizing security-related data using Matplotlib.
- Understanding failed login detection and suspicious activity monitoring.
- Developing an interactive dashboard for security analysis.

## 🔮 Future Enhancements

The project can be extended with:

- Integration with real system authentication logs.
- Automatic IP address monitoring.
- Advanced anomaly detection using Machine Learning.
- Email or desktop notifications for suspicious activities.
- Geographical IP address visualization.
- Database integration using MySQL or SQLite.
- Improved authentication and user management.
- More advanced SOC monitoring features.

## ⚠️ Limitations and Disclaimer

This is an educational cybersecurity project developed for learning and demonstration purposes.

- Login authentication is simulated using predefined credentials.
- IP addresses are manually entered and are not automatically captured from network connections.
- Suspicious activity detection uses a basic failed-login threshold.
- The application is not a production-ready security monitoring solution.

Do not use the demo credentials or this simulated authentication mechanism to protect real accounts or systems.

## 👩‍💻 Author

**Devganga P Nambiar**

BCA Student | Python | Cybersecurity | Data Analysis

---

⭐ If you find this project interesting, consider giving the repository a star!

**Developed as a minor academic project to explore Python programming, data analysis, visualization, and basic cybersecurity monitoring.**
