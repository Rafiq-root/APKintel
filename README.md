# APK Intelligence CLI

A pure Python, terminal-based static analysis and threat scoring engine for Android applications (.apk). 

## Overview
This tool orchestrates the `jadx` decompiler to reverse-engineer APKs and uses multi-threaded regular expressions to extract network indicators of compromise (IOCs), trackers, and high-risk permissions. Extracted data is cross-referenced against a localized, dynamically updatable SQLite database containing Open-Source Threat Intelligence (OSINT).

## Features
* Automated APK decompilation via `jadx`.
* Multi-threaded extraction of domains, IPs, APIs, and trackers.
* Offline OSINT threat database with automated internet fetching capabilities (URLhaus, FeodoTracker).
* Deterministic risk scoring engine.
* Color-coded terminal reporting and JSON/CSV data export.
* Built-in domain allowlist to prevent false positives.

## Prerequisites
* Python 3.10+
* `jadx` (Command-line decompiler)
  * Linux install: `sudo apt install jadx`

## Installation
1. Clone the repository:
   `git clone https://github.com/YOUR_USERNAME/APKintel.git`
2. Enter the directory:
   `cd APKintel`
3. Install the required Python formatting library:
   `pip install -r requirements.txt`

## Usage
**Step 1: Build and update the local threat database**
`python3 apkintel.py --update-db`

**Step 2: Analyze an APK**
`python3 apkintel.py path/to/target.apk`

**Export Results:**
`python3 apkintel.py path/to/target.apk --export-json results.json`
