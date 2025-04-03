# Project 1 — Network Log Analysis

This Python project analyzes authentication and firewall logs to extract login times, failed login attempts, and IP addresses that were both blocked and used for invalid logins.

## How to Run

1. Place all your log files inside a folder named `log/` in the same directory as the script.

2. Make sure your log files follow these naming patterns:
   - Authentication logs: `auth.log`, `auth.log.1`, `auth.log.2`, etc.
   - Firewall logs: `ufw.log`, `ufw.log.1`, etc.

3. Run the script using the command below:


## main.py

```python
import os
import re

def get_user_auth_times(user_id):
    auth_times = []
    for filename in os.listdir("log"):
        if filename.startswith("auth.log"):
            with open(os.path.join("log", filename), "r") as f:
                for line in f:
                    if f"session opened for user {user_id}" in line:
                        match = re.match(r"(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})", line)
                        if match:
                            auth_times.append(match.group(1))
    return auth_times

def get_invalid_logins():
    invalids = {}
    pattern = re.compile(r"Invalid user (\S+) from")
    for filename in os.listdir("log"):
        if filename.startswith("auth.log"):
            with open(os.path.join("log", filename), "r") as f:
                for line in f:
                    match = pattern.search(line)
                    if match:
                        user = match.group(1)
                        invalids[user] = invalids.get(user, 0) + 1
    return invalids

def compare_invalid_IPs():
    auth_ips = set()
    fw_ips = set()

    auth_pattern = re.compile(r"Invalid user \S+ from (\d+\.\d+\.\d+\.\d+)")
    fw_pattern = re.compile(r"\[UFW BLOCK\].*SRC=(\d+\.\d+\.\d+\.\d+)")

    for filename in os.listdir("log"):
        path = os.path.join("log", filename)
        if filename.startswith("auth.log"):
            with open(path, "r") as f:
                for line in f:
                    match = auth_pattern.search(line)
                    if match:
                        auth_ips.add(match.group(1))
        elif filename.startswith("ufw.log"):
            with open(path, "r") as f:
                for line in f:
                    match = fw_pattern.search(line)
                    if match:
                        fw_ips.add(match.group(1))
    return auth_ips & fw_ips

if __name__ == "__main__":
    print(get_user_auth_times("tylermoore"))
    print(get_invalid_logins())
    print(compare_invalid_IPs())
