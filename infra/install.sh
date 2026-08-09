#!/usr/bin/env bash
# Pentest Agent single-machine installer
# Usage: curl -sSL https://get.pentestagent.io/install.sh | bash
#        or: ./install.sh --offline --data-dir=/custom/path

set -euo pipefail

INSTALL_DIR="${PA_INSTALL_DIR:-/opt/pentest-agent}"
DATA_DIR="${PA_DATA_DIR:-/var/lib/pentest-agent}"
LOG_DIR="/var/log/pentest-agent"
CONFIG_DIR="/etc/pentest-agent"
USER="pentest-agent"

echo "=== Pentest Agent Installer ==="
echo "Install dir: $INSTALL_DIR"
echo "Data dir: $DATA_DIR"

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

# Check dependencies
echo "Checking dependencies..."
command -v python3 >/dev/null 2>&1 || { echo "Python 3.11+ required"; exit 1; }
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [[ $(echo "$PY_VER < 3.11" | bc -l 2>/dev/null || echo 0) -eq 1 ]]; then
    echo "Python 3.11+ required, found $PY_VER"
    exit 1
fi

command -v node >/dev/null 2>&1 || { echo "Node.js 20+ required"; exit 1; }

# Create system user (non-root)
if ! id "$USER" &>/dev/null; then
    echo "Creating system user $USER..."
    if [[ "$OS" == "linux" ]]; then
        sudo useradd -r -s /bin/false -d "$DATA_DIR" "$USER"
    else
        sudo dscl . -create /Users/$USER
        sudo dscl . -create /Users/$USER UserShell /usr/bin/false
    fi
fi

# Create directories
echo "Creating directories..."
sudo mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR" "$CONFIG_DIR"
sudo chown -R "$USER:$USER" "$DATA_DIR" "$LOG_DIR"

# Copy/download application files (in real deployment, fetch from release tarball)
echo "Installing application..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "$SCRIPT_DIR/../backend" ]]; then
    # Local dev install
    sudo cp -r "$SCRIPT_DIR/../backend" "$INSTALL_DIR/"
    sudo cp -r "$SCRIPT_DIR/../frontend" "$INSTALL_DIR/"
    sudo cp -r "$SCRIPT_DIR/../engines" "$INSTALL_DIR/"
    sudo cp -r "$SCRIPT_DIR/../knowledge_base" "$INSTALL_DIR/"
else
    echo "Production install: download release tarball (not implemented in MVP)"
    exit 1
fi

# Install Python dependencies
echo "Installing Python dependencies..."
cd "$INSTALL_DIR/backend"
python3 -m venv venv
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

# Build frontend
echo "Building frontend..."
cd "$INSTALL_DIR/frontend"
npm install --silent
npm run build

# Generate JWT secret
JWT_SECRET=$(openssl rand -hex 32)
cat > "$CONFIG_DIR/config.yaml" <<EOF
jwt_secret: "$JWT_SECRET"
data_dir: "$DATA_DIR"
log_dir: "$LOG_DIR"
EOF
sudo chmod 600 "$CONFIG_DIR/config.yaml"

# Install systemd service (Linux only)
if [[ "$OS" == "linux" ]] && command -v systemctl &>/dev/null; then
    echo "Installing systemd service..."
    sudo tee /etc/systemd/system/pentest-agent.service >/dev/null <<EOF
[Unit]
Description=Pentest Agent Backend
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR/backend
Environment="PA_DATA_DIR=$DATA_DIR"
Environment="PA_JWT_SECRET=$JWT_SECRET"
ExecStart=$INSTALL_DIR/backend/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable pentest-agent
    sudo systemctl start pentest-agent
    echo "Service started. Check status: sudo systemctl status pentest-agent"
fi

# Print access info
echo ""
echo "=========================================="
echo "Installation complete!"
echo "Backend: http://localhost:8000"
echo "Frontend: Serve $INSTALL_DIR/frontend/dist with your web server"
echo ""
echo "Initial admin credentials will be printed in the backend log on first start."
echo "View logs: sudo journalctl -u pentest-agent -f"
echo "=========================================="
