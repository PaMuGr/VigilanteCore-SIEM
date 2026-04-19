# VigilanteCore: Personal Learning Log
This document serves as a technical breakdown of the concepts, architectures, and logic implemented during the development of VigilanteCore.

## 1. Security Operations Fundamentals

### SOC (Security Operations Center)

SOC: Centralized unit that deals with security issues on an organizational and technical level.

- MTTD (Mean Time To Detect): Measures the time from the start of an incident to its discovery by the system.

### IDS vs. IPS

IDS (Intrusion Detection System): System that monitors network traffic or system logs for malicious activity and alerts an administrator.

IPS (Intrusion Prevention System): An evolution of IDS that not only detects but also takes action to prevent the threat.

### SOAR (Security Orchestration, Automation, and Response)

Orchestrates different tools (like Discord for alerts and AbuseIPDB for intelligence) to automate the incident response workflow.

## 2. Log Analysis & Data Normalization

Logs can be Structured (like JSON) or Unstructured (like standard Linux system logs). Data normalization is the process of converting unstructured text into a structured format.

### Regex Anatomy (Named Groups)

We use Named Groups to immediately map search results into a Python Dictionary.

Syntax: (?P<name>...).

```(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})```: This pattern looks for four sets of 1–3 digits separated by literal dots.

Sensitivity: Regex is extremely sensitive; an extra space at the end of a log line can cause a pattern mismatch, leading to missed detections.

### Log Structure

Metadata: Fixed information such as the timestamp, hostname, and Process ID (PID).

Data/Message: The variable part of the log detailing the actual event (e.g., "Failed password").

Core Fields: For this project, we standardized logs into timestamp, src_ip, user, and event_type.

## 3. Detection Strategies

### Atomic (Stateless) Detection

- Detects a threat based on a single log line.

### Stateful & Threshold Detection

- Requires memory to track events over time.

### Correlated Detection

- Identifies patterns across different services.
- Hybrid Tracking: By tracking an IP across both SSH and Web logs, we can identify attackers who are probing multiple vectors simultaneously.

## 4. System Architecture & Performance

### Streaming and Memory Management

- Reading a large log file with file.read() would load the entire file into RAM, potentially crashing the system.

- Streaming: We process logs line-by-line to minimize RAM consumption.

### Live Tailing & Daemons

- Daemon: A background process that stays "listening" to the end of a file as the OS writes to it.

- Live Tailing Logic:

    - Open the file and move to the end (SEEK_END) to ignore old data.

    - Use an infinite while True loop to wait for new lines.

    - If no new line appears, the script "sleeps" for a second to save CPU resources before checking again.

### Persistence vs. Volatility

- Volatile Memory (RAM): Where the threat_counter lives. It is fast but disappears if the program closes.

- Persistent Memory (Disk): JSON files or databases. Slower than RAM but provides a historical record.

- Detection Timestamps: We record the exact moment we detected the threat, not just the log's timestamp, to maintain forensic evidence.

## 5. Threat Intelligence

- intel.py: A dedicated module for Threat Intelligence.

- AbuseIPDB: An external service used to check the reputation of an IP address.

- This module allows the SOAR workflow to provide context, such as determining if an IP has a "100% probability of being a hacker" before taking action.