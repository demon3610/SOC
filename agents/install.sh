#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: install.sh must run as root (sudo)"
    exit 1
fi

API_KEY=""
API_BASE="http://localhost:8000"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --api-key) API_KEY="$2"; shift 2 ;;
        --api-base) API_BASE="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$API_KEY" ]]; then
    echo "Error: --api-key is required"
    exit 1
fi

HOSTNAME=$(hostname)
OS=$(grep -m1 PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || uname -s)
IP=$(ip -4 route get 1 2>/dev/null | awk '{
        for (i = 1; i <= NF; i++)
            if ($i == "src") { print $(i + 1); exit }
    }')
if [[ -z "$IP" ]] || [[ "$IP" == "0.0.0.0" ]]; then
    IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
FINGERPRINT=$(cat /etc/machine-id 2>/dev/null || echo "unknown")

ENROLL_BODY=$(cat <<EOF
{
  "api_key": "$API_KEY",
  "hostname": "$HOSTNAME",
  "os_type": "$OS",
  "ip_address": "$IP",
  "fingerprint_seed": "$FINGERPRINT"
}
EOF
)

ENROLL_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_BASE/agents/enroll" \
  -H "Content-Type: application/json" \
  -d "$ENROLL_BODY")

HTTP_CODE=$(echo "$ENROLL_RESP" | tail -1)
BODY=$(echo "$ENROLL_RESP" | sed '$d')

if [[ "$HTTP_CODE" == "409" ]]; then
    DETAIL=$(echo "$BODY" | jq -r '.detail')
    echo "Already enrolled to a different system: $DETAIL"
    exit 1
elif [[ "$HTTP_CODE" == "200" ]]; then
    AGENT_TOKEN=$(echo "$BODY" | jq -r '.agent_token')
    AGENT_ID=$(echo "$BODY" | jq -r '.agent_id')
else
    echo "Enrollment failed (HTTP $HTTP_CODE): $BODY"
    exit 1
fi

mkdir -p /etc/soc-agent
mkdir -p /opt/soc-agent

cat > /etc/soc-agent/config.json <<EOF
{
  "api_key": "$API_KEY",
  "api_base": "$API_BASE",
  "agent_token": "$AGENT_TOKEN",
  "agent_id": $AGENT_ID,
  "flush_interval_seconds": 1,
  "heartbeat_interval_seconds": 30
}
EOF

# ── Remove the legacy bash agent (heartbeat + journalctl loops) ──
systemctl disable --now soc-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/soc-agent.service /etc/soc-agent/agent.sh

# ── Carry the acknowledged cursor across the upgrade so nothing is resent ──
if [[ -f /etc/soc-agent/cursor ]] && [[ ! -f /etc/soc-agent/journal_cursor ]]; then
    mv /etc/soc-agent/cursor /etc/soc-agent/journal_cursor
fi

# ── Install the Python journal watcher ──
echo "Downloading journal watcher..."
curl -fsSL "$API_BASE/agents/journal_watcher.py" -o /opt/soc-agent/journal_watcher.py
chmod +x /opt/soc-agent/journal_watcher.py

if ! python3 -c "import requests" 2>/dev/null; then
    echo "Installing python requests..."
    python3 -m pip install --break-system-packages requests 2>/dev/null \
        || python3 -m pip install requests
fi

# ── Enable process-execution auditing (auditd) ──
# Every command executed by a real user session is recorded as an execve
# audit record; the journal watcher tails /var/log/audit/audit.log for them.
if ! command -v auditctl &> /dev/null; then
    echo "Installing auditd..."
    apt-get install -y auditd 2>/dev/null || yum install -y auditd 2>/dev/null || true
fi
if command -v auditctl &> /dev/null; then
    mkdir -p /etc/audit/rules.d
    cat > /etc/audit/rules.d/soc-exec.rules <<'EOF'
-a always,exit -F arch=b64 -S execve -k soc_exec
-a always,exit -F arch=b32 -S execve -k soc_exec
EOF
    auditctl -R /etc/audit/rules.d/soc-exec.rules 2>/dev/null || true
    systemctl enable auditd 2>/dev/null || true
    systemctl restart auditd 2>/dev/null || true
fi

# ── Register the journal watcher service ──
if command -v systemctl &> /dev/null; then
    cat > /etc/systemd/system/soc-agent-journal.service <<EOF
[Unit]
Description=SOC Agent Journal Watcher
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/soc-agent/journal_watcher.py "$API_BASE" "$AGENT_TOKEN"
Restart=always
RestartSec=5
SupplementaryGroups=systemd-journal
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload && systemctl enable --now soc-agent-journal.service
else
    echo "Warning: systemctl not found — start manually:"
    echo "  python3 /opt/soc-agent/journal_watcher.py $API_BASE $AGENT_TOKEN"
fi

echo "SOC Agent installed successfully on $HOSTNAME"
