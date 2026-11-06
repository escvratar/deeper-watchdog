#!/bin/sh
# Deeper Watchdog without Docker (Linux, macOS, routers with Python 3).
#   ./run.sh                  start (the first start asks for Deeper's address and passwords)
#   ./run.sh setup            change the address and passwords
#   ./run.sh install-service  start with the system (systemd, else cron @reboot)
#   ./run.sh remove-service   stop starting with the system
#   ./run.sh status           is it running, where is the web UI
cd "$(dirname "$0")" || exit 1
DIR=$(pwd)
export DATA_DIR="$DIR/data"
SVC=deeper-watchdog

PY=
for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then PY=$(command -v "$c"); break; fi
done
if [ -z "$PY" ]; then
    echo "Нужен Python 3.8 или новее."
    echo "  Ubuntu/Debian: sudo apt install python3     Fedora: sudo dnf install python3"
    echo "  Alpine: apk add python3     OpenWrt/Entware: opkg install python3"
    echo "  macOS: https://www.python.org/downloads/"
    exit 1
fi

port() { sed -n 's/^WEB_PORT=//p' "$DIR/.env" 2>/dev/null | tail -1 | grep . || echo 8787; }
running_service() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet "$SVC" 2>/dev/null || systemctl --user is-active --quiet "$SVC" 2>/dev/null
    else return 1
    fi
}

case "${1:-}" in
setup)
    exec "$PY" "$DIR/deeper_watchdog.py" --setup
    ;;
install-service)
    [ -f "$DIR/.env" ] || "$PY" "$DIR/deeper_watchdog.py" --setup || exit 1
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        unit="[Unit]
Description=Deeper Watchdog
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$DIR
Environment=DATA_DIR=$DIR/data
ExecStart=$PY -u $DIR/deeper_watchdog.py --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=default.target"
        if [ "$(id -u)" = 0 ]; then
            printf '%s\n' "$unit" | sed 's/^WantedBy=default.target/WantedBy=multi-user.target/' > /etc/systemd/system/$SVC.service
            systemctl daemon-reload && systemctl enable --now $SVC && echo "✓ Служба $SVC включена и запущена (журнал: journalctl -u $SVC -f)"
        else
            mkdir -p "$HOME/.config/systemd/user"
            printf '%s\n' "$unit" > "$HOME/.config/systemd/user/$SVC.service"
            systemctl --user daemon-reload && systemctl --user enable --now $SVC || exit 1
            # Without linger the user's services stop at logout
            loginctl enable-linger "$(id -un)" 2>/dev/null || echo "! Чтобы Watchdog работал без входа в систему: sudo loginctl enable-linger $(id -un)"
            echo "✓ Служба $SVC включена и запущена (журнал: journalctl --user -u $SVC -f)"
        fi
    else
        line="@reboot cd '$DIR' && ./run.sh >> '$DIR/data/watchdog.log' 2>&1"
        ( crontab -l 2>/dev/null | grep -v "$DIR/data/watchdog.log"; echo "$line" ) | crontab - \
            && echo "✓ Запуск при загрузке добавлен в cron. Сейчас запускаю в фоне..." || exit 1
        mkdir -p "$DIR/data"
        nohup ./run.sh >> "$DIR/data/watchdog.log" 2>&1 &
    fi
    echo "  Веб-интерфейс: http://<IP этого устройства>:$(port)/"
    ;;
remove-service)
    if command -v systemctl >/dev/null 2>&1; then
        if [ -f /etc/systemd/system/$SVC.service ]; then
            systemctl disable --now $SVC; rm -f /etc/systemd/system/$SVC.service; systemctl daemon-reload
        fi
        if [ -f "$HOME/.config/systemd/user/$SVC.service" ]; then
            systemctl --user disable --now $SVC; rm -f "$HOME/.config/systemd/user/$SVC.service"; systemctl --user daemon-reload
        fi
    fi
    crontab -l 2>/dev/null | grep -q "$DIR/data/watchdog.log" && crontab -l | grep -v "$DIR/data/watchdog.log" | crontab -
    echo "✓ Автозапуск выключен"
    ;;
status)
    if running_service; then echo "✓ Работает как служба $SVC"; else echo "Служба не запущена"; fi
    echo "Веб-интерфейс: http://127.0.0.1:$(port)/"
    ;;
"")
    if running_service; then
        echo "Watchdog уже работает как служба: http://127.0.0.1:$(port)/ (остановить: ./run.sh remove-service)"
        exit 0
    fi
    if [ ! -f "$DIR/.env" ]; then
        "$PY" "$DIR/deeper_watchdog.py" --setup || exit 1
        echo "Автозапуск вместе с системой: ./run.sh install-service"
        echo
    fi
    open=
    [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] || [ "$(uname -s)" = Darwin ] && open=--open-browser
    echo "Запускаю Deeper Watchdog: http://127.0.0.1:$(port)/ (остановить: Ctrl+C)"
    exec "$PY" -u "$DIR/deeper_watchdog.py" --daemon $open
    ;;
*)
    sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
