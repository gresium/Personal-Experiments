#!/usr/bin/env bash
#
# Install the honeypot as a systemd service on Linux.
# Run as root:  sudo bash linux/install.sh
#
# It installs to /opt/honeypot, config to /etc/honeypot, logs to /var/log/honeypot,
# runs as a dedicated 'honeypot' user, and starts a hardened systemd service.

set -euo pipefail

APP_DIR=/opt/honeypot
CFG_DIR=/etc/honeypot
LOG_DIR=/var/log/honeypot
STATE_DIR=/var/lib/honeypot
SVC_USER=honeypot
UNIT=/etc/systemd/system/honeypot.service

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root: sudo bash linux/install.sh" >&2
    exit 1
fi

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Creating service user '$SVC_USER'"
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    # System account, no home login, no shell.
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi

echo "==> Installing application to $APP_DIR"
install -d -m 0755 "$APP_DIR"
install -m 0755 "$SRC_DIR/honeypot.py" "$APP_DIR/honeypot.py"
install -m 0755 "$SRC_DIR/honeytokens.py" "$APP_DIR/honeytokens.py"
install -m 0644 "$SRC_DIR/tokens.py" "$APP_DIR/tokens.py"
install -m 0644 "$SRC_DIR/alerts.py" "$APP_DIR/alerts.py"
install -m 0644 "$SRC_DIR/protocols.py" "$APP_DIR/protocols.py"

echo "==> Installing config to $CFG_DIR"
install -d -m 0755 "$CFG_DIR"
if [[ -f "$CFG_DIR/config.json" ]]; then
    echo "    config.json already exists, leaving it untouched"
else
    # Point the log and state dirs at their service locations.
    sed -e 's#"log_dir": null#"log_dir": "/var/log/honeypot"#' \
        -e 's#"state_dir": null#"state_dir": "/var/lib/honeypot"#' \
        "$SRC_DIR/config.example.json" > "$CFG_DIR/config.json"
    chmod 0644 "$CFG_DIR/config.json"
fi

echo "==> Creating log directory $LOG_DIR"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$LOG_DIR"

echo "==> Creating state directory $STATE_DIR (honeytokens + decoy files)"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$STATE_DIR"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$STATE_DIR/decoys"

echo "==> Installing systemd unit"
install -m 0644 "$SRC_DIR/linux/honeypot.service" "$UNIT"

echo "==> Enabling and starting the service"
systemctl daemon-reload
systemctl enable --now honeypot.service

echo
echo "Done. The honeypot is running as a hardened systemd service."
echo "  Status:   systemctl status honeypot"
echo "  Logs:     journalctl -u honeypot -f   (and JSON in $LOG_DIR/honeypot.log)"
echo "  Config:   $CFG_DIR/config.json   (edit, then: systemctl restart honeypot)"
echo "  Stop:     systemctl stop honeypot"
echo "  Remove:   bash linux/uninstall.sh"
echo
echo "Default ports are 2222 (ssh), 2323 (telnet), 8080 (http)."
echo "Open them in your firewall if you want remote hosts to reach the honeypot, e.g.:"
echo "  sudo ufw allow 2222/tcp && sudo ufw allow 2323/tcp && sudo ufw allow 8080/tcp"
echo
echo "Plant honeytokens (run as the service user so files land with the right owner):"
echo "  sudo -u $SVC_USER python3 $APP_DIR/honeytokens.py -c $CFG_DIR/config.json new web --label 'canary in budget.xlsx' --base-url http://YOUR-HONEYPOT:8080"
echo "  sudo -u $SVC_USER python3 $APP_DIR/honeytokens.py -c $CFG_DIR/config.json list"
echo "New tokens are picked up automatically; no restart needed."
echo
echo "To impersonate the REAL ports (22/23/80) without running as root, redirect them:"
echo "  sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222"
echo "Make sure your real SSH is moved to another port first, or you will lock yourself out."
