#!/bin/sh
# Deeper Watchdog: installs, updates or removes the Docker container on this machine
# (Ubuntu/Debian/other Linux, Synology DSM, QNAP, Xiaomi and other routers with Docker). busybox sh is enough.
#
#   sh dw-install.sh [install|update|uninstall|status]
#
# Asks everything in the terminal. Without a terminal (scripts, the Android app) set DW_* variables and DW_YES=1:
#   DW_DEEPER_HOST DW_DEEPER_PASS DW_WEB_PASSWORD DW_PORT DW_DIR DW_TZ DW_SUDO_PASS DW_INSTALL_DOCKER=1 DW_PURGE=1
# DW_STDIN_CONFIG=1 reads them from stdin as DW_KEY=value lines ending with END (passwords stay off the command line).
# DW_MACHINE=1 prints @@STEP/@@OK/@@INFO/@@WARN/@@ERR/@@URL/@@DONE lines for programs.

IMAGE=${DW_IMAGE:-ghcr.io/escvratar/deeper-watchdog:latest}
NAME=${DW_NAME:-deeper-watchdog}
REPO=https://github.com/escvratar/deeper-watchdog
PATH="$PATH:/usr/local/bin:/usr/local/sbin:/usr/sbin:/sbin:/opt/bin:/opt/sbin"
umask 077

if [ "${DW_STDIN_CONFIG:-}" = 1 ]; then
    while IFS= read -r line; do
        case "$line" in
            END) break ;;
            DW_*=*) k=${line%%=*}; v=${line#*=}
                    case "$k" in *[!A-Z0-9_]*) ;; *) eval "$k=\$v" ;; esac ;;
        esac
    done
fi
MODE=${1:-${DW_MODE:-}}
DW_DEEPER_HOST=${DW_DEEPER_HOST:-} DW_DEEPER_PASS=${DW_DEEPER_PASS:-} DW_WEB_PASSWORD=${DW_WEB_PASSWORD:-}
DW_PORT=${DW_PORT:-} DW_DIR=${DW_DIR:-} DW_TZ=${DW_TZ:-} DW_SUDO_PASS=${DW_SUDO_PASS:-}
DW_YES=${DW_YES:-} DW_MACHINE=${DW_MACHINE:-} DW_INSTALL_DOCKER=${DW_INSTALL_DOCKER:-} DW_PURGE=${DW_PURGE:-}

# ---------- output ----------
B= G= R= Y= D= N=
if [ -t 1 ] && [ -z "$DW_MACHINE" ]; then
    E=$(printf '\033'); B="$E[1m" G="$E[32m" R="$E[31m" Y="$E[33m" D="$E[2m" N="$E[0m"
fi
say()  { if [ -n "$DW_MACHINE" ]; then echo "@@$1 $2"; else printf "$3" "$2"; fi; }
step() { say STEP "$*" "\n$B▸ %s$N\n"; }
ok()   { say OK "$*" "  $G✓$N %s\n"; }
info() { say INFO "$*" "    %s\n"; }
warn() { say WARN "$*" "  $Y!$N %s\n"; }
die()  { say ERR "$*" "\n  $R✗ %s$N\n"; shift_hint; cleanup; exit 1; }
HINT=
shift_hint() { [ -n "$HINT" ] && info "$HINT"; HINT=; }
TMPS=
cleanup() {
    [ -n "$TTY" ] && stty echo <"$TTY" 2>/dev/null
    for f in $TMPS; do rm -f "$f"; done
    # The wrappers copy this script to /tmp: it removes itself (it may hold passwords)
    [ -n "${DW_SELF:-}" ] && rm -f "$DW_SELF"
}
trap 'cleanup; exit 130' INT TERM
trap cleanup EXIT

# ---------- questions ----------
TTY=
if [ -z "$DW_YES" ] && [ -z "$DW_MACHINE" ] && (true </dev/tty) 2>/dev/null; then TTY=/dev/tty; fi
HIDE=
if [ -n "$TTY" ]; then
    if command -v stty >/dev/null 2>&1; then HIDE=stty
    elif (echo | read -rs x) 2>/dev/null; then HIDE=read
    fi
fi

ask() {  # ask VAR "Question" [default]
    eval "cur=\${$1:-}"; [ -n "$cur" ] || cur=${3:-}
    if [ -n "$TTY" ]; then
        printf "  %s%s: " "$2" "${cur:+ $D[$cur]$N}"
        IFS= read -r a <"$TTY" || a=
        [ -n "$a" ] && cur=$a
    fi
    eval "$1=\$cur"
}
ask_secret() {  # ask_secret VAR "Question" [hint when empty]
    eval "cur=\${$1:-}"
    if [ -n "$TTY" ]; then
        if [ -n "$cur" ]; then printf "  %s $D[Enter: оставить прежний]$N: " "$2"; else printf "  %s%s: " "$2" "${3:+ $D[$3]$N}"; fi
        case "$HIDE" in
            stty) stty -echo <"$TTY" 2>/dev/null; IFS= read -r a <"$TTY" || a=; stty echo <"$TTY" 2>/dev/null; echo ;;
            read) IFS= read -rs a <"$TTY" || a=; echo ;;
            *) IFS= read -r a <"$TTY" || a= ;;
        esac
        [ -n "$a" ] && cur=$a
    fi
    eval "$1=\$cur"
}
yesno() {  # yesno "Question" y|n -> 0 for yes
    if [ -z "$TTY" ]; then [ "$2" = y ]; return; fi
    if [ "$2" = y ]; then printf "  %s [Д/н]: " "$1"; else printf "  %s [д/Н]: " "$1"; fi
    IFS= read -r a <"$TTY" || a=
    case "$a" in
        "") [ "$2" = y ] ;;
        Д*|д*|Y*|y*|1) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------- root, docker ----------
SUDO_PW= ROOT_OK=
as_root() {  # as root once get_root has succeeded, else as the user
    if [ "$(id -u)" = 0 ] || [ -z "$ROOT_OK" ]; then "$@"
    elif [ -n "$SUDO_PW" ]; then printf '%s\n' "$SUDO_PW" | sudo -S -p '' "$@"
    else sudo "$@" </dev/null
    fi
}
get_root() {
    [ -n "$ROOT_OK" ] && return 0
    [ "$(id -u)" = 0 ] && { ROOT_OK=1; return 0; }
    command -v sudo >/dev/null 2>&1 || die "Нужны права администратора: войдите как root (или установите sudo)"
    if sudo -n true 2>/dev/null; then ROOT_OK=1; return 0; fi
    SUDO_PW=$DW_SUDO_PASS
    n=0
    while :; do
        if [ -z "$SUDO_PW" ]; then
            [ -n "$TTY" ] || die "Нужен пароль sudo пользователя $(id -un)"
            ask_secret SUDO_PW "Пароль пользователя $(id -un) (для sudo)"
        fi
        err=$(printf '%s\n' "$SUDO_PW" | sudo -S -p '' true 2>&1) && { ROOT_OK=1; return 0; }
        case "$err" in
            *sudoers*|*"not allowed"*)
                HINT="Synology: пользователь должен быть в группе administrators. Linux: sudo usermod -aG sudo $(id -un) (от root)"
                die "Пользователю $(id -un) не разрешён sudo" ;;
        esac
        n=$((n + 1)); SUDO_PW=
        [ -n "$TTY" ] && [ $n -lt 3 ] || die "sudo не принял пароль"
        warn "Пароль не подошёл, попробуйте ещё раз"
    done
}

DOCKER= DK_ROOT=
dk() { if [ -n "$DK_ROOT" ]; then as_root "$DOCKER" "$@"; else "$DOCKER" "$@" </dev/null; fi; }

find_docker() {
    DOCKER=$(command -v docker 2>/dev/null)
    if [ -z "$DOCKER" ]; then
        for c in /usr/local/bin/docker /usr/bin/docker /opt/bin/docker /snap/bin/docker \
                 /mnt/*/mi_docker/docker-binaries/docker /data/*/mi_docker/docker-binaries/docker \
                 /share/CACHEDEV*_DATA/.qpkg/container-station/bin/docker /var/packages/ContainerManager/target/usr/bin/docker \
                 /var/packages/Docker/target/usr/bin/docker; do
            [ -x "$c" ] && { DOCKER=$c; break; }
        done
    fi
    [ -n "$DOCKER" ]
}

PLAT=linux
detect_platform() {
    ARCH=$(uname -m)
    if [ -f /etc/synoinfo.conf ]; then PLAT=synology
    elif [ -f /etc/config/qpkg.conf ]; then PLAT=qnap
    elif [ -d /usr/share/xiaoqiang ]; then PLAT=xiaomi
    elif [ -f /etc/openwrt_release ]; then PLAT=openwrt
    elif [ -x /opt/bin/opkg ] && [ -d /opt/etc ]; then PLAT=entware
    elif [ "$(uname -s)" = Darwin ]; then PLAT=mac
    fi
    case "$PLAT" in
        synology) PNAME="Synology DSM" ;; qnap) PNAME="QNAP" ;; xiaomi) PNAME="роутер Xiaomi" ;;
        openwrt) PNAME="OpenWrt" ;; entware) PNAME="роутер с Entware" ;; mac) PNAME="macOS" ;;
        *) PNAME=$( (. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}") ) ;;
    esac
}

no_docker_help() {
    case "$PLAT" in
        synology) HINT="DSM → Центр пакетов → установите «Container Manager» (на старых DSM «Docker»), затем запустите установщик снова" ;;
        qnap) HINT="App Center → установите «Container Station», затем запустите установщик снова" ;;
        xiaomi) HINT="Веб-интерфейс роутера → Дополнительно → Docker: включите (нужен USB-диск), затем запустите установщик снова. Или используйте portable-версию на компьютере" ;;
        openwrt|entware) HINT="Установите пакеты docker и dockerd (opkg install docker dockerd) или используйте portable-версию (Python) на компьютере" ;;
        mac) HINT="Установите Docker Desktop: https://www.docker.com/products/docker-desktop/ и запустите его" ;;
        *) HINT="Docker можно поставить командой: curl -fsSL https://get.docker.com | sudo sh" ;;
    esac
}

install_docker() {
    case "$PLAT" in synology|qnap|xiaomi|openwrt|entware|mac) return 1 ;; esac
    if [ -z "$DW_INSTALL_DOCKER" ]; then
        [ -n "$TTY" ] || return 1
        yesno "Docker не установлен. Установить его сейчас (официальный скрипт get.docker.com)?" y || return 1
    fi
    get_root
    info "Устанавливаю Docker, это займёт 1–5 минут..."
    f=/tmp/get-docker.$$.sh; TMPS="$TMPS $f"
    if command -v curl >/dev/null 2>&1; then curl -fsSL https://get.docker.com -o "$f"
    elif command -v wget >/dev/null 2>&1; then wget -qO "$f" https://get.docker.com
    else warn "Нет curl и wget: не могу скачать установщик Docker"; return 1
    fi || { warn "Не удалось скачать get.docker.com (нет интернета?)"; return 1; }
    as_root sh "$f" >/tmp/get-docker.$$.log 2>&1 || {
        tail -5 /tmp/get-docker.$$.log | while IFS= read -r l; do info "$l"; done
        rm -f /tmp/get-docker.$$.log; warn "Установка Docker не удалась"; return 1; }
    rm -f /tmp/get-docker.$$.log
    as_root systemctl enable --now docker >/dev/null 2>&1 || as_root service docker start >/dev/null 2>&1
    find_docker
}

start_docker_daemon() {
    get_root
    info "Docker установлен, но не запущен: запускаю..."
    case "$PLAT" in
        synology) as_root synopkg start ContainerManager >/dev/null 2>&1 || as_root synopkg start Docker >/dev/null 2>&1 ;;
        *) as_root systemctl start docker >/dev/null 2>&1 || as_root service docker start >/dev/null 2>&1 \
               || as_root /etc/init.d/dockerd start >/dev/null 2>&1 || as_root /etc/init.d/docker start >/dev/null 2>&1 \
               || as_root /etc/init.d/mi_docker start >/dev/null 2>&1 ;;
    esac
    i=0; while [ $i -lt 20 ]; do as_root "$DOCKER" info >/dev/null 2>&1 && return 0; sleep 2; i=$((i + 1)); done
    return 1
}

setup_docker() {
    step "Docker"
    if ! find_docker; then
        no_docker_help
        install_docker || die "Docker не найден"
        HINT=
    fi
    if "$DOCKER" info >/dev/null 2>&1 </dev/null; then DK_ROOT=
    else
        get_root
        DK_ROOT=1
        as_root "$DOCKER" info >/dev/null 2>&1 || start_docker_daemon || {
            HINT="Запустите Docker (на NAS: пакет Container Manager / Container Station; на роутере: включите Docker в веб-интерфейсе) и повторите"
            die "Docker не запущен и запустить его не удалось"; }
    fi
    ok "Docker $(dk version --format '{{.Server.Version}}' 2>/dev/null) ($DOCKER)"
}

# ---------- network helpers ----------
http_ok() {  # http_ok URL -> 0 if anything answered over HTTP
    if command -v curl >/dev/null 2>&1; then
        c=$(curl -s -o /dev/null -m 6 -w '%{http_code}' "$1" 2>/dev/null); [ -n "$c" ] && [ "$c" != 000 ]
    elif command -v wget >/dev/null 2>&1; then
        out=$(wget -T 6 -t 1 -O /dev/null "$1" 2>&1); [ $? = 0 ] && return 0
        case "$out" in *"HTTP/"*|*"error 4"*|*"error 5"*|*"server returned error"*|*" 40"[0-9]*) return 0 ;; esac; return 1
    elif command -v nc >/dev/null 2>&1; then
        h=${1#http://}; h=${h%%/*}; p=80; case "$h" in *:*) p=${h##*:}; h=${h%:*} ;; esac
        nc -z -w 6 "$h" "$p" 2>/dev/null
    else return 0
    fi
}
port_busy() {
    { netstat -ltn 2>/dev/null || ss -ltn 2>/dev/null; } | awk '{print $4}' | grep -q "[:.]$1\$"
}
lan_ips() {
    { if command -v ip >/dev/null 2>&1; then ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1
      else ifconfig 2>/dev/null | sed -n 's/.*inet \(addr:\)\{0,1\}\([0-9.]*\).*/\2/p'; fi; } \
      | grep -v '^127\.' | grep -v '^172\.1[7-9]\.' | grep -v '^172\.2[0-9]\.' | awk '!s[$0]++' | head -3
}

detect_tz() {
    [ -n "$DW_TZ" ] && return
    if [ -f /etc/timezone ]; then DW_TZ=$(head -1 /etc/timezone)
    elif [ -L /etc/localtime ]; then DW_TZ=$(ls -l /etc/localtime | sed -n 's|.*zoneinfo/||p')
    elif [ -f /etc/synoinfo.conf ]; then DW_TZ=$(sed -n 's/^timezone="\(.*\)"/\1/p' /etc/synoinfo.conf)
    fi
    case "$DW_TZ" in */*) ;; *) DW_TZ=Europe/Moscow ;; esac
}

default_dir() {
    case "$PLAT" in
        synology) for v in /volume1 /volume2; do [ -d "$v" ] && { echo "$v/docker/deeper-watchdog"; return; }; done ;;
        qnap) for v in /share/Container /share/CACHEDEV1_DATA; do [ -d "$v" ] && { echo "$v/deeper-watchdog"; return; }; done ;;
        xiaomi|openwrt)
            # The router's own flash is tiny: data goes to the USB disk next to Docker
            for m in /mnt/usb-* /mnt/sd* /mnt/*; do
                [ -d "$m/mi_docker" ] && { echo "$m/deeper-watchdog"; return; }
            done
            for m in /mnt/usb-* /mnt/sd*; do [ -d "$m" ] && { echo "$m/deeper-watchdog"; return; }; done ;;
    esac
    if [ "$(id -u)" = 0 ] || [ -n "$DK_ROOT" ]; then echo /opt/deeper-watchdog; else echo "$HOME/deeper-watchdog"; fi
}

# ---------- the container ----------
exists() { [ -n "$(dk ps -aq --filter "name=^/${1:-$NAME}\$" 2>/dev/null)" ]; }
state() { dk inspect -f '{{.State.Status}}' "$NAME" 2>/dev/null; }
state_ru() {
    case "$(state)" in
        running) echo "работает" ;; exited) echo "остановлен" ;; restarting) echo "перезапускается" ;;
        paused) echo "на паузе" ;; created) echo "создан, не запущен" ;; *) state ;;
    esac
}
mount_dir() { dk inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$NAME" 2>/dev/null; }
host_port() { dk inspect -f '{{range $p, $c := .HostConfig.PortBindings}}{{if eq $p "8787/tcp"}}{{(index $c 0).HostPort}}{{end}}{{end}}' "$NAME" 2>/dev/null; }

pull() {
    step "Загрузка образа $IMAGE"
    case "$ARCH" in
        x86_64|amd64|aarch64|arm64|armv7l|armv7*|armv8*) ;;
        *) HINT="Образ собран для x86_64, arm64 и armv7. Здесь $ARCH: используйте portable-версию на компьютере (нужен только Python)"
           die "Архитектура $ARCH не поддерживается Docker-образом" ;;
    esac
    n=0
    while :; do
        if dk pull "$IMAGE" >/tmp/dw-pull.$$ 2>&1; then rm -f /tmp/dw-pull.$$; break; fi
        n=$((n + 1))
        if [ $n -ge 3 ]; then
            tail -3 /tmp/dw-pull.$$ | while IFS= read -r l; do info "$l"; done; rm -f /tmp/dw-pull.$$
            HINT="Проверьте интернет на этом устройстве и доступ к ghcr.io (если заблокирован: прокси/VPN для Docker)"
            die "Не удалось скачать образ"
        fi
        warn "Не получилось, повтор через 5 с..."; sleep 5
    done
    ok "Образ загружен"
}

run_container() {  # run_container ENV_FILE DATA_DIR PORT [extra args...]
    envf=$1 data=$2 port=$3; shift 3
    dk run -d --name "$NAME" --restart unless-stopped -p "$port:8787" --env-file "$envf" -v "$data:/data" \
        --log-opt max-size=10m --log-opt max-file=3 "$@" "$IMAGE" >/tmp/dw-run.$$ 2>&1 && { rm -f /tmp/dw-run.$$; return 0; }
    # Some Docker builds (routers) refuse the log options: once more without them
    if grep -qi "log" /tmp/dw-run.$$; then
        dk rm -f "$NAME" >/dev/null 2>&1
        dk run -d --name "$NAME" --restart unless-stopped -p "$port:8787" --env-file "$envf" -v "$data:/data" \
            "$@" "$IMAGE" >/tmp/dw-run.$$ 2>&1 && { rm -f /tmp/dw-run.$$; return 0; }
    fi
    tail -3 /tmp/dw-run.$$ | while IFS= read -r l; do info "$l"; done; rm -f /tmp/dw-run.$$
    return 1
}

wait_up() {  # wait_up PORT -> 0 when the web UI answers
    step "Запуск"
    i=0
    while [ $i -lt 45 ]; do
        st=$(state)
        case "$st" in
            exited|dead) break ;;
        esac
        if http_ok "http://127.0.0.1:$1/"; then ok "Веб-интерфейс отвечает"; return 0; fi
        sleep 2; i=$((i + 1))
    done
    warn "Watchdog не отвечает (контейнер: $(state_ru)). Последние строки журнала:"
    dk logs --tail 15 "$NAME" 2>&1 | while IFS= read -r l; do info "$l"; done
    return 1
}

check_login() {  # 0 = logged in, 1 = wrong password, 2 = unknown
    i=0
    while [ $i -lt 30 ]; do
        log=$(dk logs --tail 200 "$NAME" 2>&1)
        case "$log" in
            *"Authentication successful"*) return 0 ;;
            *"Login failed"*) return 1 ;;
            *"Failed to fetch tunnels"*|*"urlopen error"*) return 3 ;;
        esac
        sleep 2; i=$((i + 1))
    done
    return 2
}

write_env() {  # write_env FILE: our settings, other lines of an older file kept
    tmp=$(mktemp 2>/dev/null || echo "/tmp/dw-env-new.$$"); TMPS="$TMPS $tmp"
    {
        echo "# Deeper Watchdog. Остальные настройки задаются в веб-интерфейсе"
        echo "DEEPER_HOST=$DW_DEEPER_HOST"
        [ -n "$DW_DEEPER_PASS" ] && echo "DEEPER_PASS=$DW_DEEPER_PASS"
        [ -n "$DW_WEB_PASSWORD" ] && echo "WEB_PASSWORD=$DW_WEB_PASSWORD"
        echo "TZ=$DW_TZ"
        [ -f "$1" ] && as_root cat "$1" | grep -v -e '^#' -e '^DEEPER_HOST=' -e '^DEEPER_PASS=' -e '^WEB_PASSWORD=' -e '^TZ='
    } > "$tmp"
    as_root cp "$tmp" "$1" && as_root chmod 600 "$1" || { rm -f "$tmp"; die "Не удалось записать $1"; }
    rm -f "$tmp"
}

env_get() { [ -f "$1" ] && [ ! -r "$1" ] && get_root; as_root cat "$1" 2>/dev/null | sed -n "s/^$2=//p" | tail -1; }

show_urls() {
    port=$1
    ips=$(lan_ips)
    [ -z "$DW_MACHINE" ] && echo
    if [ -n "$ips" ]; then
        for ip in $ips; do
            say URL "http://$ip:$port/" "  $B$G➜  Откройте: %s$N\n"
        done
    else
        say URL "http://<IP-этого-устройства>:$port/" "  $B$G➜  Откройте: %s$N\n"
    fi
}

firewall() {  # Asks before opening the port; without a terminal only says how
    port=$1
    if command -v ufw >/dev/null 2>&1 && LC_ALL=C as_root ufw status 2>/dev/null | grep -q "Status: active"; then
        if ! LC_ALL=C as_root ufw status | grep -q "^$port"; then
            if [ -z "$TTY" ]; then warn "Включён брандмауэр ufw: чтобы открыть Watchdog с других устройств, выполните: sudo ufw allow $port/tcp"
            elif yesno "Включён брандмауэр ufw. Открыть порт $port, чтобы Watchdog открывался с телефона и других устройств?" y; then
                as_root ufw allow "$port/tcp" >/dev/null 2>&1 && ok "Порт $port открыт в ufw"
            fi
        fi
    elif command -v firewall-cmd >/dev/null 2>&1 && as_root firewall-cmd --state >/dev/null 2>&1; then
        if ! as_root firewall-cmd --list-ports | grep -q "$port/tcp"; then
            if [ -z "$TTY" ]; then warn "Включён firewalld: чтобы открыть Watchdog с других устройств, откройте порт: firewall-cmd --permanent --add-port=$port/tcp"
            elif yesno "Включён firewalld. Открыть порт $port?" y; then
                as_root firewall-cmd --permanent --add-port="$port/tcp" >/dev/null 2>&1 && as_root firewall-cmd --reload >/dev/null 2>&1 \
                    && ok "Порт $port открыт в firewalld"
            fi
        fi
    fi
}

# ---------- modes ----------
do_install() {
    step "Настройка"
    if [ -n "$TTY" ]; then
        info "Enter оставляет значение в скобках. Пароли при вводе не видны."
    fi
    # Deeper Connect
    [ -n "$DW_DEEPER_HOST" ] || DW_DEEPER_HOST=34.34.34.34
    while :; do
        ask DW_DEEPER_HOST "IP-адрес Deeper Connect" 34.34.34.34
        if http_ok "http://$DW_DEEPER_HOST/"; then ok "Deeper Connect отвечает ($DW_DEEPER_HOST)"; break; fi
        warn "Deeper Connect по адресу $DW_DEEPER_HOST не отвечает с этого устройства"
        info "Устройство должно быть в одной сети с Deeper. Адрес — тот, что открывается в браузере для входа в Deeper"
        [ -n "$TTY" ] || break
        yesno "Ввести адрес заново?" y || break
        DW_DEEPER_HOST=
    done
    while :; do
        ask_secret DW_DEEPER_PASS "Пароль администратора Deeper Connect"
        [ -n "$DW_DEEPER_PASS" ] && break
        warn "Без пароля Watchdog не сможет управлять туннелями (можно задать позже в веб-интерфейсе)"
        [ -n "$TTY" ] || break
        yesno "Ввести пароль?" y || break
    done
    # The web UI
    [ -n "$DW_PORT" ] || DW_PORT=8787
    while :; do
        ask DW_PORT "Порт веб-интерфейса" 8787
        case "$DW_PORT" in ''|*[!0-9]*) warn "Нужно число"; DW_PORT=8787; [ -n "$TTY" ] && continue; die "Неверный порт" ;; esac
        if port_busy "$DW_PORT" && ! { exists && [ "$(host_port)" = "$DW_PORT" ]; }; then
            warn "Порт $DW_PORT уже занят другой программой"
            [ -n "$TTY" ] || die "Порт $DW_PORT занят: задайте другой"
            DW_PORT=$((DW_PORT + 1)); continue
        fi
        break
    done
    if [ -n "$TTY" ]; then
        info "Пароль входа в веб-интерфейс Watchdog (не пароль Deeper). Можно не задавать сейчас: его попросит первая открытая страница"
        while :; do
            ask_secret DW_WEB_PASSWORD "Пароль веб-интерфейса" "Enter: задать в браузере"
            [ -z "$DW_WEB_PASSWORD" ] && break
            if [ ${#DW_WEB_PASSWORD} -lt 4 ]; then warn "Нужно хотя бы 4 символа"; DW_WEB_PASSWORD=; continue; fi
            p2=; ask_secret p2 "Повторите пароль"
            [ "$p2" = "$DW_WEB_PASSWORD" ] && break
            warn "Пароли не совпали"; DW_WEB_PASSWORD=
        done
    fi
    detect_tz
    ask DW_TZ "Часовой пояс" "$DW_TZ"
    # Where
    [ -n "$DW_DIR" ] || DW_DIR=$(default_dir)
    ask DW_DIR "Папка для настроек и журнала" "$DW_DIR"
    case "$DW_DIR" in /*) ;; *) DW_DIR="$(pwd)/$DW_DIR" ;; esac

    step "Проверка места"
    mkdir -p "$DW_DIR/data" 2>/dev/null || { get_root; as_root mkdir -p "$DW_DIR/data"; } || die "Не удалось создать папку $DW_DIR"
    [ -w "$DW_DIR" ] && { [ ! -f "$DW_DIR/.env" ] || [ -w "$DW_DIR/.env" ]; } || get_root
    free=$(df -Pk "$DW_DIR" 2>/dev/null | awk 'NR==2 {print $4}')
    if [ -n "$free" ] && [ "$free" -lt 150000 ] 2>/dev/null; then
        warn "Свободно только $((free / 1024)) МБ в $DW_DIR (нужно около 150 МБ для образа и журнала)"
    else
        ok "Папка $DW_DIR"
    fi
    write_env "$DW_DIR/.env"
    ok "Настройки записаны в $DW_DIR/.env (доступ только владельцу)"

    pull
    if exists; then
        step "Замена прежнего контейнера"
        dk rm -f "$NAME" >/dev/null 2>&1 && ok "Прежний контейнер удалён (данные сохранены)"
    fi
    run_container "$DW_DIR/.env" "$DW_DIR/data" "$DW_PORT" || die "Контейнер не запустился"
    ok "Контейнер $NAME создан, автозапуск включён"
    wait_up "$DW_PORT" || die "Watchdog не запустился"

    if [ -n "$DW_DEEPER_PASS" ]; then
        step "Вход в Deeper Connect"
        while :; do
            check_login; r=$?
            [ $r = 0 ] && { ok "Watchdog вошёл в Deeper Connect"; break; }
            if [ $r = 2 ]; then warn "Пока не видно входа в Deeper: проверьте журнал в веб-интерфейсе через пару минут"; break; fi
            if [ $r = 3 ]; then
                warn "Контейнер не может связаться с Deeper Connect ($DW_DEEPER_HOST), хотя само устройство его видит"
                info "Обычно мешает брандмауэр между Docker и сетью или неверный адрес. Адрес можно поменять в веб-интерфейсе: Настройки → Deeper Connect"
                break
            fi
            warn "Deeper Connect не принял пароль"
            [ -n "$TTY" ] || { info "Исправьте его в веб-интерфейсе: Настройки → Deeper Connect → Пароль"; break; }
            yesno "Ввести пароль Deeper заново?" y || break
            DW_DEEPER_PASS=; ask_secret DW_DEEPER_PASS "Пароль администратора Deeper Connect"
            write_env "$DW_DIR/.env"
            dk rm -f "$NAME" >/dev/null 2>&1
            run_container "$DW_DIR/.env" "$DW_DIR/data" "$DW_PORT" || die "Контейнер не запустился"
            wait_up "$DW_PORT" || die "Watchdog не запустился"
        done
    fi
    firewall "$DW_PORT"
    finish "$DW_PORT"
}

do_update() {
    exists || die "Watchdog ещё не установлен здесь"
    pull
    step "Пересоздание контейнера с прежними настройками"
    data=$(mount_dir); port=$(host_port)
    [ -n "$data" ] || die "Не нашёл папку данных прежнего контейнера"
    port=${port:-8787}
    # The container's own settings: environment it was started with, minus what the image sets
    envf=/tmp/dw-env.$$; TMPS="$TMPS $envf"
    img=$(dk inspect -f '{{.Image}}' "$NAME")
    dk image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$img" > /tmp/dw-imgenv.$$ 2>/dev/null
    dk inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$NAME" | grep -v '^$' | grep -vxF -f /tmp/dw-imgenv.$$ > "$envf"
    rm -f /tmp/dw-imgenv.$$
    net=$(dk inspect -f '{{.HostConfig.NetworkMode}}' "$NAME")
    extra=; [ "$net" = host ] && extra="--network host"
    dk stop "$NAME" >/dev/null 2>&1
    dk rename "$NAME" "$NAME-old" >/dev/null 2>&1 || die "Не удалось переименовать прежний контейнер"
    # shellcheck disable=SC2086
    if run_container "$envf" "$data" "$port" $extra && wait_up "$port"; then
        dk rm -f "$NAME-old" >/dev/null 2>&1
        [ "$img" != "$(dk inspect -f '{{.Image}}' "$NAME")" ] && dk rmi "$img" >/dev/null 2>&1
        ok "Обновлено, настройки и журнал сохранены"
        finish "$port"
    else
        warn "Новая версия не запустилась: возвращаю прежнюю"
        dk rm -f "$NAME" >/dev/null 2>&1
        dk rename "$NAME-old" "$NAME" >/dev/null 2>&1 && dk start "$NAME" >/dev/null 2>&1
        die "Обновление не удалось, прежняя версия снова работает"
    fi
}

do_uninstall() {
    exists || { warn "Контейнер $NAME не найден"; return 0; }
    data=$(mount_dir)
    step "Удаление"
    if [ -z "$DW_YES" ] && [ -n "$TTY" ]; then yesno "Удалить контейнер $NAME?" n || { info "Отменено"; return 0; }; fi
    dk rm -f "$NAME" >/dev/null 2>&1 && ok "Контейнер удалён"
    dk rmi "$IMAGE" >/dev/null 2>&1 && ok "Образ удалён"
    if [ -n "$data" ]; then
        dir=$(dirname "$data")
        purge=$DW_PURGE
        [ -z "$purge" ] && [ -n "$TTY" ] && yesno "Удалить и настройки с журналом ($data)?" n && purge=1
        if [ -n "$purge" ]; then
            as_root rm -rf "$data"
            [ -f "$dir/.env" ] && as_root rm -f "$dir/.env"
            rmdir "$dir" 2>/dev/null
            ok "Данные удалены"
        else
            info "Данные оставлены в $data (при повторной установке в ту же папку они подхватятся)"
        fi
    fi
    say DONE "removed" "\n  Готово.\n"
}

do_status() {
    exists || { warn "Watchdog здесь не установлен"; say DONE "absent" ""; return 0; }
    step "Состояние"
    info "Контейнер: $(state_ru), образ $(dk inspect -f '{{.Config.Image}}' "$NAME"), создан $(dk inspect -f '{{.Created}}' "$NAME" | cut -c1-16)"
    info "Данные: $(mount_dir)"
    port=$(host_port); port=${port:-8787}
    http_ok "http://127.0.0.1:$port/" && ok "Веб-интерфейс отвечает" || warn "Веб-интерфейс не отвечает"
    step "Последние строки журнала"
    dk logs --tail 12 "$NAME" 2>&1 | while IFS= read -r l; do info "$l"; done
    show_urls "$port"
    say DONE "status" ""
}

finish() {
    port=$1
    step "Готово"
    show_urls "$port"
    [ -z "$DW_WEB_PASSWORD" ] && [ -z "$(env_get "$DW_DIR/.env" WEB_PASSWORD 2>/dev/null)" ] && \
        info "Первая открытая страница попросит придумать пароль входа."
    info "Приложение для Android: тот же адрес. Вне дома: обратный прокси с HTTPS (Synology: Портал входа → Обратный прокси) или VPN до дома; порт $port напрямую в интернет не открывайте."
    info "Обновить потом: этот же установщик → «Обновить». Журнал: $(basename "$DOCKER") logs $NAME"
    say DONE "http://127.0.0.1:$port/" ""
}

# ---------- main ----------
[ -z "$DW_MACHINE" ] && printf "\n$B Deeper Watchdog — установка в Docker$N\n $D%s$N\n" "$REPO"
detect_platform
step "Устройство"
ok "$PNAME, $ARCH, пользователь $(id -un)"
setup_docker

if [ -z "$MODE" ]; then
    if exists; then
        if [ -n "$TTY" ]; then
            echo
            info "Watchdog уже установлен ($(state_ru)). Что сделать?"
            info "1) Обновить до последней версии (настройки сохранятся)"
            info "2) Переустановить с новыми параметрами"
            info "3) Показать состояние"
            info "4) Удалить"
            info "5) Выход"
            c=; ask c "Выбор" 1
            case "$c" in 1) MODE=update ;; 2) MODE=install ;; 3) MODE=status ;; 4) MODE=uninstall ;; *) exit 0 ;; esac
        else
            MODE=update
        fi
    else
        MODE=install
    fi
fi
if [ "$MODE" = install ] && exists && [ -z "$DW_DIR" ]; then
    # Reinstall keeps the old folder (and its settings) unless told otherwise
    d=$(mount_dir); [ -n "$d" ] && DW_DIR=$(dirname "$d")
    [ -n "$DW_DIR" ] && [ -z "$DW_DEEPER_HOST" ] && DW_DEEPER_HOST=$(env_get "$DW_DIR/.env" DEEPER_HOST)
    [ -n "$DW_DIR" ] && [ -z "$DW_DEEPER_PASS" ] && DW_DEEPER_PASS=$(env_get "$DW_DIR/.env" DEEPER_PASS)
    [ -n "$DW_DIR" ] && [ -z "$DW_WEB_PASSWORD" ] && DW_WEB_PASSWORD=$(env_get "$DW_DIR/.env" WEB_PASSWORD)
    [ -z "$DW_PORT" ] && DW_PORT=$(host_port)
fi
case "$MODE" in
    install) do_install ;;
    update) do_update ;;
    uninstall|remove) do_uninstall ;;
    status) do_status ;;
    *) die "Неизвестная команда: $MODE (install, update, uninstall, status)" ;;
esac
exit 0
