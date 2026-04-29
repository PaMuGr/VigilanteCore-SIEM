# 🛡️ VigilanteCore: Sentinel & SOAR Mini-SIEM

**VigilanteCore** It is a real-time log monitoring system (Sentinel) with automated response capabilities (SOAR) and threat intelligence. Developed as an intensive 3-day project to understand the fundamentals of defensive cybersecurity.

## Main features
* **Sentinel Monitoring (Real-time):** Active log listening via live tailing.
* **Hybrid Detection:** Correlation of events across different services (SSH and Web) to identify persistent attackers.
* **Flexible Rules Engine:** JSON-based system for adding new detections without modifying the source code.
* **SOAR Enrichment:** Automatic IP reputation querying using the AbuseIPDB API.
* **ChatOps Notifications:** Critical alerts sent directly to a Discord channel via webhooks.
* **IPS (Intrusion Prevention) Module:** Automatic firewall blocking capability (iptables for Linux / Logic for macOS).

## Technology Stack
* **Language:** Python 3.x
* **Libraries:** `requests`, `python-dotenv`, `re` (Regex).
* **Integrations:** AbuseIPDB API, Discord Webhooks.

## Project Structure
* `main.py`: The core of the system (Sentinel Loop).
* `core/`: Logic modules (Parser, Engine, Intel, Notifier, Blocker).
* `rules/`: Attack definitions in JSON format.
* `logs/`: Log files for monitoring.
* `alerts/`: Forensic report repository in JSON format.


## What I Learned in This Project
This project was a personal challenge to master the pillars of defensive security:
1. **Data Normalization:** How to transform plain, messy text into useful structured data using advanced Regex.
2. **Event Correlation:** Understanding that an attack doesn't always occur on a single service; the importance of connecting the dots.
3. **Response Automation:** Reducing reaction time (MTTR) through external integrations.
4. **Modular Architecture:** Designing software that is easy to extend (e.g., adding a new blocker or a new notification channel).
5. **Development Security:** Managing virtual environments and protecting sensitive credentials.
