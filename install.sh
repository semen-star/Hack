#!/bin/bash
# Bitkillers Installer - Fixed Version

echo "🚀 Installing Bitkillers Pentest Platform..."

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_HOME="$HOME"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[INSTALL]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    warning "Installing as root. Desktop entries will be created in system directories."
    USER_HOME="/root"
fi

# Make main script executable
log "Setting executable permissions..."
chmod +x "$APP_DIR/bitkillers.sh"

# Create necessary directories
log "Creating directories..."
mkdir -p "$APP_DIR/static/css" "$APP_DIR/static/js" "$APP_DIR/templates" "$APP_DIR/core"

# Create icon if not exists
if [ ! -f "$APP_DIR/bitkillers.png" ]; then
    log "Creating application icon..."
    # Try to create icon with ImageMagick
    if command -v convert &> /dev/null; then
        convert -size 64x64 xc:navy -fill cyan -pointsize 20 -gravity center -annotate +0+0 "BK" "$APP_DIR/bitkillers.png" 2>/dev/null && \
        log "Icon created successfully"
    else
        warning "ImageMagick not available. Creating placeholder icon."
        # Create simple SVG icon as fallback
        cat > "$APP_DIR/bitkillers.svg" << 'EOF'
<svg width="64" height="64" xmlns="http://www.w3.org/2000/svg">
  <rect width="64" height="64" fill="#000080"/>
  <text x="32" y="40" font-family="Arial" font-size="20" fill="white" text-anchor="middle">BK</text>
</svg>
EOF
        # Try to convert SVG to PNG if possible
        if command -v convert &> /dev/null && [ -f "$APP_DIR/bitkillers.svg" ]; then
            convert "$APP_DIR/bitkillers.svg" "$APP_DIR/bitkillers.png" 2>/dev/null
        fi
    fi
fi

# Determine icon path
ICON_PATH="$APP_DIR/bitkillers.png"
if [ ! -f "$ICON_PATH" ]; then
    ICON_PATH=""
    warning "No icon file found. Application will use default icon."
fi

# Create desktop entries
create_desktop_entries() {
    log "Creating desktop entries..."
    
    # User applications directory
    USER_APPS="$USER_HOME/.local/share/applications"
    USER_DESKTOP="$USER_HOME/Desktop"
    
    # System applications directory (if root)
    SYSTEM_APPS="/usr/share/applications"
    
    # Create user directories
    mkdir -p "$USER_APPS" 2>/dev/null || true
    mkdir -p "$USER_DESKTOP" 2>/dev/null || true
    
    # Create user desktop file
    USER_DESKTOP_FILE="$USER_APPS/bitkillers.desktop"
    cat > "$USER_DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Bitkillers 2025
GenericName=Penetration Testing Platform
Comment=Professional Security Assessment Tool
Exec=gnome-terminal --working-directory="$APP_DIR" -- bash -c "./bitkillers.sh start; read -p 'Press Enter to close...'"
Path=$APP_DIR
Icon=$ICON_PATH
Categories=Security;Development;
Terminal=false
StartupNotify=true
Keywords=security;pentest;hacking;vulnerability
EOF

    chmod +x "$USER_DESKTOP_FILE"
    log "User desktop entry created: $USER_DESKTOP_FILE"
    
    # Copy to desktop if directory exists
    if [ -d "$USER_DESKTOP" ]; then
        cp "$USER_DESKTOP_FILE" "$USER_DESKTOP/"
        log "Desktop shortcut created: $USER_DESKTOP/bitkillers.desktop"
    else
        warning "Desktop directory not found: $USER_DESKTOP"
    fi
    
    # Create system-wide entry if running as root and directory is writable
    if [ "$EUID" -eq 0 ] && [ -w "$SYSTEM_APPS" ]; then
        SYSTEM_DESKTOP_FILE="$SYSTEM_APPS/bitkillers.desktop"
        cp "$USER_DESKTOP_FILE" "$SYSTEM_DESKTOP_FILE"
        log "System desktop entry created: $SYSTEM_DESKTOP_FILE"
    fi
    
    # Create simple launcher script as backup
    LAUNCHER_SCRIPT="$APP_DIR/launch-bitkillers.sh"
    cat > "$LAUNCHER_SCRIPT" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
echo "Starting Bitkillers..."
./bitkillers.sh start
echo "Application should be available at: http://localhost:5000"
echo "Press Ctrl+C to stop the application"
echo "Press Enter to close this window..."
read
EOF

    chmod +x "$LAUNCHER_SCRIPT"
    log "Launcher script created: $LAUNCHER_SCRIPT"
    
    # Create desktop shortcut for launcher script
    if [ -d "$USER_DESKTOP" ]; then
        cat > "$USER_DESKTOP/Launch_Bitkillers.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Launch Bitkillers
Comment=Start Bitkillers Pentest Platform
Exec=gnome-terminal -- "$LAUNCHER_SCRIPT"
Icon=$ICON_PATH
Categories=Security;
Terminal=false
StartupNotify=true
EOF
        chmod +x "$USER_DESKTOP/Launch_Bitkillers.desktop"
        log "Alternative launcher created: $USER_DESKTOP/Launch_Bitkillers.desktop"
    fi
}

# Update desktop database
update_desktop_database() {
    log "Updating desktop database..."
    
    if command -v update-desktop-database &> /dev/null; then
        # Update user database
        if [ -d "$USER_HOME/.local/share/applications" ]; then
            update-desktop-database "$USER_HOME/.local/share/applications" 2>/dev/null && \
            log "User desktop database updated"
        fi
        
        # Update system database if root
        if [ "$EUID" -eq 0 ] && command -v sudo &> /dev/null; then
            sudo update-desktop-database 2>/dev/null && \
            log "System desktop database updated"
        fi
    else
        warning "update-desktop-database not available"
    fi
}

# Install dependencies
install_dependencies() {
    log "Checking dependencies..."
    
    # Check if virtual environment exists
    if [ ! -d "$APP_DIR/alphaseek_env" ]; then
        log "Creating virtual environment..."
        python3 -m venv "$APP_DIR/alphaseek_env"
    fi
    
    # Activate and install requirements
    log "Installing Python dependencies..."
    source "$APP_DIR/alphaseek_env/bin/activate"
    
    # Upgrade pip first
    pip install --upgrade pip
    
    # Install requirements
    if [ -f "$APP_DIR/requirements.txt" ]; then
        pip install -r "$APP_DIR/requirements.txt"
    else
        # Install core dependencies
        pip install flask flask-socketio python-socketio python-nmap requests
    fi
    
    log "Python dependencies installed"
}

# Main installation
main() {
    log "Starting Bitkillers installation..."
    echo "Installation directory: $APP_DIR"
    echo "User home: $USER_HOME"
    echo ""
    
    # Install dependencies
    install_dependencies
    
    # Create desktop entries
    create_desktop_entries
    
    # Update desktop database
    update_desktop_database
    
    echo ""
    log "✅ Installation complete!"
    echo ""
    echo "🎯 ${GREEN}Quick Start:${NC}"
    echo "   Desktop: Double-click 'Bitkillers 2025' or 'Launch Bitkillers'"
    echo "   Terminal: cd $APP_DIR && ./bitkillers.sh start"
    echo ""
    echo "🌐 ${GREEN}Access:${NC} http://localhost:5000"
    echo ""
    echo "📋 ${GREEN}Files created:${NC}"
    echo "   - $USER_HOME/.local/share/applications/bitkillers.desktop"
    echo "   - $USER_HOME/Desktop/bitkillers.desktop (if desktop exists)"
    echo "   - $USER_HOME/Desktop/Launch_Bitkillers.desktop (if desktop exists)"
    echo "   - $APP_DIR/launch-bitkillers.sh"
    echo ""
    echo "🛠️ ${GREEN}Management:${NC}"
    echo "   ./bitkillers.sh start    # Start application"
    echo "   ./bitkillers.sh stop     # Stop application"
    echo "   ./bitkillers.sh status   # Check status"
    echo "   ./bitkillers.sh logs     # View logs"
    echo ""
}

# Run installation
main
