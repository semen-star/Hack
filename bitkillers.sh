#!/bin/bash
# Bitkillers Pentest Platform Launcher
# Version: 2025.1.0

APP_NAME="Bitkillers"
APP_VERSION="2025.1.0"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$APP_DIR/alphaseek_env"
LOG_FILE="$APP_DIR/bitkillers.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

# ASCII Art
show_banner() {
    echo -e "${PURPLE}"
    cat << "EOF"
    
╔═══╗╔╗╔╗╔═══╗╔╗─╔╗╔═══╗╔════╗╔═══╗╔═══╗╚══╗╔╗╔═══╗╔═══╗
║╔═╗║║║║║║╔═╗║║║─║║║╔═╗║║╔╗╔╗║║╔═╗║║╔══╝──╔╝║║║╔═╗║║╔══╝
║║─╚╝║║║║║║─║║║╚═╝║║║─║║╚╝║║╚╝║║─║║║╚══╗─╔╝╔╝║║║─║║║╚══╗
║║─╔╗║║║║║╚═╝║║╔═╗║║╚═╝║──║║──║╚═╝║║╔══╝╔╝╔╝─║║║─║║║╔══╝
║╚═╝║║╚╝║║╔═╗║║║─║║║╔═╗║──║║──║╔═╗║║╚══╗╔╝╔╝──║╚═╝║║╚══╗
╚═══╝╚══╝╚╝─╚╝╚╝─╚╝╚╝─╚╝──╚╝──╚╝─╚╝╚═══╝╚═╝───╚═══╝╚═══╝
                                                                                                                         
EOF
    echo -e "${NC}"
    echo -e "${CYAN}           Professional Pentest Platform v${APP_VERSION}${NC}"
    echo -e "${YELLOW}               Hackathon ALPIX 2025${NC}"
    echo -e "${GREEN}        https://localhost:5000${NC}"
    echo ""
}

# Check dependencies
check_dependencies() {
    log "Checking system dependencies..."
    
    local missing_deps=()
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    # Check nmap
    if ! command -v nmap &> /dev/null; then
        missing_deps+=("nmap")
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        missing_deps+=("python3-pip")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        error "Missing dependencies: ${missing_deps[*]}"
        log "Installing missing dependencies..."
        
        if command -v apt &> /dev/null; then
            # Debian/Ubuntu
            sudo apt update
            sudo apt install -y "${missing_deps[@]}"
        elif command -v yum &> /dev/null; then
            # CentOS/RHEL
            sudo yum install -y "${missing_deps[@]}"
        elif command -v pacman &> /dev/null; then
            # Arch
            sudo pacman -Sy --noconfirm "${missing_deps[@]}"
        else
            error "Cannot automatically install dependencies. Please install manually: ${missing_deps[*]}"
            exit 1
        fi
    fi
    
    log "All dependencies satisfied"
}

# Setup virtual environment
setup_venv() {
    if [ ! -d "$VENV_DIR" ]; then
        log "Creating virtual environment..."
        python3 -m venv "$VENV_DIR"
    fi
    
    log "Activating virtual environment..."
    source "$VENV_DIR/bin/activate"
    
    # Install/upgrade pip
    log "Upgrading pip..."
    pip install --upgrade pip
    
    # Install requirements
    if [ -f "$APP_DIR/requirements.txt" ]; then
        log "Installing Python dependencies..."
        pip install -r "$APP_DIR/requirements.txt"
    else
        log "Installing core dependencies..."
        pip install flask flask-socketio python-socketio python-nmap requests
    fi
}

# Check if app is already running
check_running() {
    if pgrep -f "python.*app.py" > /dev/null; then
        warning "Bitkillers is already running!"
        read -p "Do you want to stop it and restart? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            stop_app
        else
            info "App is already running at: http://localhost:5000"
            exit 0
        fi
    fi
}

# Stop the application
stop_app() {
    log "Stopping Bitkillers..."
    pkill -f "python.*app.py" && log "Bitkillers stopped" || warning "No running instance found"
}

# Start the application
start_app() {
    log "Starting Bitkillers..."
    
        # Проверяем права
    if [ ! -x "$APP_DIR/app.py" ]; then
        log "Fixing permissions..."
        chmod +x "$APP_DIR/app.py"
        chmod -R 755 "$APP_DIR"
    fi

    # Проверяем что app.py существует
    if [ ! -f "$APP_DIR/app.py" ]; then
        error "app.py not found in $APP_DIR"
        error "Please make sure you're in the correct directory"
        exit 1
    fi
    
    # Активируем виртуальное окружение
    source "$VENV_DIR/bin/activate"
    
    # Устанавливаем Python path
    export PYTHONPATH="$APP_DIR"
    
    # Переходим в директорию приложения
    cd "$APP_DIR"
    
    # Проверяем что Python доступен
    if ! command -v python &> /dev/null; then
        error "Python not found in virtual environment"
        exit 1
    fi
    
    log "Starting Flask application..."
    
    # Запускаем приложение и получаем PID
    nohup python app.py >> "$LOG_FILE" 2>&1 &
    local pid=$!
    
    # Даем время на запуск
    sleep 5
    
    # Проверяем что процесс запустился
    if ps -p $pid > /dev/null 2>&1; then
        log "✅ Bitkillers started successfully (PID: $pid)"
        echo "$pid" > "$APP_DIR/bitkillers.pid"
        
        # Проверяем что приложение отвечает
        sleep 2
        if curl -s http://localhost:5000 > /dev/null 2>&1; then
            log "🌐 Application is available at: ${GREEN}http://localhost:5000${NC}"
        else
            warning "Application started but not responding on port 5000"
            log "Check log file for details: $LOG_FILE"
        fi
    else
        error "❌ Failed to start Bitkillers"
        error "Check log file: $LOG_FILE"
        error "Last log entries:"
        tail -10 "$LOG_FILE" | while read line; do
            error "  $line"
        done
        exit 1
    fi
}

# Open in browser
open_browser() {
    sleep 2
    if command -v xdg-open &> /dev/null; then
        info "Opening browser..."
        xdg-open "http://localhost:5000" > /dev/null 2>&1 &
    elif command -v gnome-open &> /dev/null; then
        gnome-open "http://localhost:5000" > /dev/null 2>&1 &
    else
        info "Please open manually: http://localhost:5000"
    fi
}

# Status check
status_app() {
    if pgrep -f "python.*app.py" > /dev/null; then
        local pid=$(pgrep -f "python.*app.py")
        log "Bitkillers is running (PID: $pid)"
        info "Access at: http://localhost:5000"
    else
        log "Bitkillers is not running"
    fi
}

# Show logs
show_logs() {
    if [ -f "$LOG_FILE" ]; then
        tail -50 "$LOG_FILE"
    else
        log "No log file found"
    fi
}

# Create desktop entry
create_desktop_entry() {
    log "Creating desktop entries..."
    
    USER_APPS="$HOME/.local/share/applications"
    USER_DESKTOP="$HOME/Desktop"
    ICON_PATH="$APP_DIR/bitkillers.png"
    
    # Create directories
    mkdir -p "$USER_APPS" 2>/dev/null || true
    mkdir -p "$USER_DESKTOP" 2>/dev/null || true
    
    # Create desktop file
    DESKTOP_FILE="$USER_APPS/bitkillers.desktop"
    cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Bitkillers
Comment=Professional Pentest Platform
Exec=gnome-terminal --working-directory="$APP_DIR" -- bash -c "./bitkillers.sh start; read -p 'Press Enter to close...'"
Path=$APP_DIR
Icon=$ICON_PATH
Categories=Security;
Terminal=false
StartupNotify=true
EOF

    chmod +x "$DESKTOP_FILE"
    
    # Copy to desktop
    if [ -d "$USER_DESKTOP" ]; then
        cp "$DESKTOP_FILE" "$USER_DESKTOP/"
        log "Desktop shortcut created"
    fi
    
    # Update desktop database
    if command -v update-desktop-database &> /dev/null; then
        update-desktop-database "$USER_APPS" 2>/dev/null
    fi
    
    log "Desktop entries created successfully"
}

# Main function
main() {
    case "${1:-start}" in
        "start")
            show_banner
            check_dependencies
            check_running
            setup_venv
            start_app
            open_browser
            ;;
        "stop")
            show_banner
            stop_app
            ;;
        "restart")
            show_banner
            stop_app
            sleep 2
            setup_venv
            start_app
            ;;
        "status")
            status_app
            ;;
        "logs")
            show_logs
            ;;
        "install")
            show_banner
            create_desktop_entry
            log "Bitkillers installed successfully!"
            ;;
        "update")
            show_banner
            stop_app
            setup_venv
            start_app
            ;;
        *)
            echo "Usage: $0 {start|stop|restart|status|logs|install|update}"
            echo ""
            echo "Commands:"
            echo "  start   - Start Bitkillers (default)"
            echo "  stop    - Stop Bitkillers"
            echo "  restart - Restart Bitkillers"
            echo "  status  - Show status"
            echo "  logs    - Show recent logs"
            echo "  install - Create desktop entry"
            echo "  update  - Update and restart"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
