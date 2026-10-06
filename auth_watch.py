#!/usr/bin/env python3
"""AuthLogWatch - flags possible SSH brute-force activity in a Linux auth.log file."""

import sys
import re
from collections import defaultdict

THRESHOLD = 5  # Failed logins from a single IP needed to trigger an alert
IP_PATTERN = re.compile(r"from (\d{1,3}(?:\.\d{1,3}){3})")  # Grabs the IPv4 after "from"


def main():
    # Step 1: Make sure the user supplied a log file path
    if len(sys.argv) != 2:
        print("Usage: python3 auth_watch.py <path_to_auth.log>")
        sys.exit(1)

    log_path = sys.argv[1]
    failed_attempts = defaultdict(int)  # Dictionary: {ip_address: failure_count}

    # Step 2: Open the log file safely and read it line by line
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as log_file:
            for line in log_file:
                # Step 3: Only look at failed SSH password attempts
                if "Failed password" in line:
                    # Step 4: Extract the source IP and increase its counter
                    match = IP_PATTERN.search(line)
                    if match:
                        failed_attempts[match.group(1)] += 1
    except FileNotFoundError:
        print(f"Error: file '{log_path}' not found.")
        sys.exit(1)

    # Step 5: Print a summary, sorted so the worst offenders appear first
    print(f"[*] Scanned {log_path}: {len(failed_attempts)} IP(s) with failed logins\n")
    for ip, count in sorted(failed_attempts.items(), key=lambda item: item[1], reverse=True):
        # Step 6: Alert if this IP meets or exceeds the brute-force threshold
        if count >= THRESHOLD:
            print(f"[ALERT] {ip} - {count} failed attempts (possible brute-force)")
        else:
            print(f"[INFO]  {ip} - {count} failed attempt(s)")


if __name__ == "__main__":
    main()
