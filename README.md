# Brute Force & Failed Login Attack Detector

## 📌 Overview
A Python-based SOC tool that detects brute force attacks by analyzing login failures and identifying suspicious authentication patterns using time-based detection and risk scoring.

---

## 🚀 Features
- Detects rapid failed login attempts within a short time window  
- Identifies successful login after multiple failures (possible compromise)  
- Detects IP targeting multiple user accounts  
- Generates severity-based alerts (HIGH / CRITICAL)  
- Calculates overall risk score  
- Provides final system attack status  
- Saves detailed report to file  

---

## 🧠 Detection Logic

### 🔹 Rapid Failed Logins
Multiple failed login attempts within a short time period indicate possible brute force attack.

### 🔹 Success After Failures
A successful login after multiple failures may indicate account compromise.

### 🔹 IP Targeting Multiple Users
One IP attempting multiple accounts suggests automated attack behavior.

---

## 📁 Project Structure
brute-force-detector/
│── detector.py  
│── logs.csv  
│── README.md  
│── .gitignore  

---

## ▶️ How to Run

```bash
python detector.py