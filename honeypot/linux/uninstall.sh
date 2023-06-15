#!/usr/bin/env bash
# Remove the honeypot service from Linux.  Run as root:  sudo bash linux/uninstall.sh
# Logs in /var/log/honeypot are left in place (they are evidence); delete them by hand.

set -euo pipefail
if [[ $EUID -ne 0 ]]; then
    echo "Please run as root: sudo bash linux/uninstall.sh" >&2
    exit 1
fi

systemctl disable --now honeypot.service 2>/dev/null || true
rm -f /etc/systemd/system/honeypot.service
systemctl daemon-reload
rm -rf /opt/honeypot
echo "Removed the service and /opt/honeypot."
echo "Left in place: /etc/honeypot (config), /var/log/honeypot (logs),"
echo "               /var/lib/honeypot (honeytokens + decoy files)."
echo "Remove them manually if you want: rm -rf /etc/honeypot /var/log/honeypot /var/lib/honeypot"
echo "Remove the service user with: sudo userdel honeypot"
