# AuthLogWatch

A lightweight Python tool that scans Linux `auth.log` files for failed SSH logins and flags IP addresses showing signs of **brute-force activity**. It's built to mirror a common Tier-1 SOC triage task.

---

## Overview

Brute-force attacks against SSH are among the most common threats facing internet-facing Linux servers. Attackers try many username and password combinations from a single IP address, hoping one works.

**AuthLogWatch** automates the first step a SOC analyst takes when investigating this:

- Find every failed SSH password attempt
- Group the attempts by source IP
- Flag any IP that crosses a set threshold so it can be investigated or blocked

It uses only the Python standard library (`sys`, `re`, `collections`), so there's nothing to install.

---

## How It Works

1. **Input check.** The script makes sure a log file path was passed on the command line.
2. **Read line by line.** It opens the file and reads one line at a time, so large logs don't use much memory.
3. **Filter.** It skips every line that doesn't contain `"Failed password"`.
4. **Extract the IP.** A regular expression pulls out the IPv4 address that follows the word `from`.
5. **Count.** A dictionary (`defaultdict(int)`) keeps a running total of failures for each IP.
6. **Triage.** IPs with **5 or more** failures are printed as `[ALERT]`. All others are printed as `[INFO]`. Results are sorted with the worst offenders first.

```
auth.log ──► filter "Failed password" ──► extract IP ──► count per IP ──► threshold check ──► ALERT / INFO
```

You can change the threshold by editing `THRESHOLD` at the top of `auth_watch.py`.

---

## How to Run

**Requirements:** Python 3.6 or later

```bash
# Clone the repository
git clone https://github.com/<your-username>/AuthLogWatch.git
cd AuthLogWatch

# Run against the included sample log
python3 auth_watch.py auth.log

# Run against a real system log (Linux, usually needs sudo)
sudo python3 auth_watch.py /var/log/auth.log
```

> On Windows, use `python` instead of `python3`.

---

## Sample Output

```
[*] Scanned auth.log: 2 IP(s) with failed logins

[ALERT] 203.0.113.45 - 6 failed attempts (possible brute-force)
[INFO]  198.51.100.23 - 1 failed attempt(s)
```

**Analyst interpretation:**

- `203.0.113.45` made 6 failed attempts in about 12 seconds against `admin`, `root`, `test` and `oracle`. That rapid cycling through common default accounts is a classic brute-force pattern. Next steps would be to check whether any login from this IP succeeded, look up the IP's reputation, and consider blocking it.
- `198.51.100.23` failed once and then logged in successfully as `bob`. This is most likely a mistyped password, so it's low priority.

> The sample data uses reserved documentation IP ranges (RFC 5737), so it contains no real addresses.

---

## Possible Improvements

- Detect successful logins from IPs that were previously flagged (a possible compromise)
- Add time-window detection (e.g., 5 failures within 60 seconds)
- Export results to CSV or JSON for a SIEM
- Support IPv6 addresses

---

## CV Bullet Point

> Developed **AuthLogWatch**, a Python log-analysis tool that parses Linux `auth.log` files with regex, aggregates failed SSH login attempts per source IP, and automatically flags brute-force activity based on configurable thresholds, simulating Tier-1 SOC alert triage.

---

## License

MIT
