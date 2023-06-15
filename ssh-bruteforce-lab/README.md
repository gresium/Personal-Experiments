# SSH Brute Force Attack – Complete Log Analysis (CentOS)

This repository contains a full forensic investigation of an SSH brute-force attack targeting a CentOS server.  
The analysis includes username extraction, invalid user identification, cross-referencing with system accounts, security recommendations, and continuous monitoring practices.

#  1. Overview

A CentOS server experienced a high-volume brute-force attack against SSH.  
This analysis was performed in Kali Linux using log files provided in the `secure` format.

The main objectives were:
- Extract all attempted usernames  
- Identify invalid usernames  
- Cross-reference usernames with `/etc/passwd`  
- Interpret the attack  
- Recommend hardening and monitoring strategies  

#  2. Project Contents (All Inside This README)

This README includes:

- All commands used  
- All scripts used  
- All analysis steps  
- All findings  
- All recommendations  
- Full write-up  
- Everything required for Simplilearn submission  


# 3. Tools & Environment

- **Kali Linux**
- **Bash utilities**: grep, awk, sort, uniq
- **CentOS SSH logs** (`secure`, `secure-20240804`)
- **Shell scripting** for system user comparison

#  4. Log Preparation

Move into log directory:

bash
cd ~/Downloads/bruteforce/securelogs
ls

You should see something like:
secure
secure-20240804

# 5. Extract Valid Usernames (Failed SSH Attempts)
Command:
grep "Failed password for" secure* | grep -v "invalid user" | awk '{print $9}' > usernames.log

Verify:
cat usernames.log
Result:
Multiple brute-force attempts targeting root.

# 6. Extract Invalid Usernames (Non-existent Accounts)
Command:
grep "Invalid user" secure* | awk '{print $8}' | sort -u > abc.txt
Verify:
cat abc.txt
Result:
Hundreds of random usernames:
tom
ubuntu
uniadmin
zookeeper
oracle
ftpuser
...
Indicates automated botnet activity.

# 7. Cross-Reference With System Accounts
Script used:
#!/bin/bash

while read user; do
    if grep -q "^$user:" /etc/passwd; then
        echo "EXISTS: $user"
    else
        echo "NOT FOUND: $user"
    fi
done < abc.txt
Make executable:
chmod +x testtheusers_1.sh
Run:
./testtheusers_1.sh
Result:
All usernames returned:
NOT FOUND: <username>

Only root exists as a real system account

#  8. Attack Interpretation (Forensic Summary)
The attack was:
 High-volume automated SSH brute force
Many login failures in short time.
 Targeted primarily at root
Indicates privilege escalation attempts.
 Used massive dictionary of fake usernames
Matches typical global SSH botnet behavior.
 No internal users compromised
Only root exists locally.
 Attack severity: HIGH
Targeting root via SSH is extremely dangerous.

# 9. Security Recommendations (Not executed on your system)
1. Disable root login over SSH
PermitRootLogin no
2. Disable password-based authentication
PasswordAuthentication no
Use SSH keys only.
3. Enable Fail2Ban
Block IPs after repeated failures.
4. Restrict SSH to trusted IPs only
Firewall rules.
5. Change default SSH port
Reduces noise from automated scanners.
6. Implement SSH MFA
Additional protection layer.

# 10. Continuous Monitoring Recommendations
Use Splunk, ELK, or Logwatch for SSH alerts
Enable alerts on repeated failed logins
GeoIP lookup for suspicious attacker IPs
Weekly security reports
Regular SSH configuration audits

# Short Description 
This project analyzed SSH authentication logs from a CentOS system targeted by a brute-force attack.
Using grep and awk, both valid and invalid usernames were extracted from multiple secure log files.
A large number of invalid usernames indicated automated botnet activity.
Repeated login attempts against the root user confirmed high-severity targeted brute forcing.
A cross-reference script validated that none of the attempted usernames existed on the system except root.
Security recommendations included disabling root login, enforcing SSH keys, enabling Fail2Ban, restricting SSH to trusted IPs, and enabling MFA.
Continuous monitoring was recommended using ELK/Splunk with alerting rules.
Attack Conclusion:
This was a large-scale SSH brute-force attack aimed at gaining privileged access.

# Author
Gresa Hisa (@gresium)
AI & Cybersecurity Engineer
GitHub: https://github.com/gresium
