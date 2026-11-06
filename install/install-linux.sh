#!/bin/sh
# Deeper Watchdog installer for Linux and macOS: puts the watchdog into Docker on this computer
# or on another device over SSH (server, NAS, router). Run: sh deeper-watchdog-install-linux.sh
# The installer that runs on the target is embedded below (install/dw-install.sh, gzip + base64).

PAYLOAD='@@PAYLOAD@@'
REPO=https://github.com/escvratar/deeper-watchdog

B= G= R= Y= D= N=
if [ -t 1 ]; then E=$(printf '\033'); B="$E[1m" G="$E[32m" R="$E[31m" Y="$E[33m" D="$E[2m" N="$E[0m"; fi
ask() {  # ask VAR "Question" default
    printf "  %s %s[%s]%s: " "$2" "$D" "$3" "$N"
    IFS= read -r a </dev/tty || a=
    eval "$1=\${a:-\$3}"
}
b64d() { base64 -d 2>/dev/null || base64 -D 2>/dev/null || openssl base64 -d -A; }

printf "\n%s Deeper Watchdog — установщик%s\n %s%s%s\n\n" "$B" "$N" "$D" "$REPO" "$N"
printf "  Куда установить?\n"
printf "  %s1%s) На этот компьютер (Docker)\n" "$B" "$N"
printf "  %s2%s) На другое устройство по SSH: сервер, NAS (Synology, QNAP), роутер с Docker\n" "$B" "$N"
printf "  %s3%s) Без Docker: portable-версия (нужен только Python 3)\n" "$B" "$N"
printf "  Тот же пункт обновляет, показывает состояние или удаляет уже установленный Watchdog.\n\n"
ask where "Выбор" 1

case "$where" in
1)
    T=$(mktemp 2>/dev/null || echo "/tmp/dw-install.$$.sh")
    echo "$PAYLOAD" | b64d | gzip -dc > "$T" || { echo "Не удалось распаковать установщик"; exit 1; }
    DW_SELF=$T sh "$T"
    exit $?
    ;;
2)
    command -v ssh >/dev/null 2>&1 || {
        printf "\n  %s✗ Нет программы ssh.%s Установите: sudo apt install openssh-client (или аналог)\n" "$R" "$N"; exit 1; }
    echo
    printf "  %sНа устройстве должен быть включён SSH:%s\n" "$B" "$N"
    printf "    Synology: Панель управления → Терминал и SNMP → Включить службу SSH (вход под администратором)\n"
    printf "    QNAP: Панель управления → Telnet/SSH → Разрешить SSH\n"
    printf "    Роутеры: SSH включается в настройках роутера или прошивке (у Xiaomi — отдельная разблокировка)\n\n"
    while :; do
        ask host "IP-адрес или имя устройства" "192.168.1.10"
        ask port "Порт SSH" 22
        ask user "Пользователь" root
        printf "\n  Подключаюсь к %s@%s... Пароль SSH спросит сама программа ssh.\n" "$user" "$host"
        printf "  %sПри первом подключении ssh спросит «Are you sure you want to continue connecting» — ответьте yes.%s\n\n" "$D" "$N"
        # The target unpacks the installer to /tmp, runs it in this terminal (-t: its questions) and deletes it
        ssh -t -o ConnectTimeout=15 -p "$port" "$user@$host" \
            "sh -c 'umask 077; T=/tmp/dw-install.\$\$.sh; echo $PAYLOAD | { base64 -d 2>/dev/null || openssl base64 -d -A; } | gzip -dc > \$T && DW_SELF=\$T sh \$T; r=\$?; rm -f \$T; exit \$r'"
        rc=$?
        [ $rc = 0 ] && exit 0
        if [ $rc = 255 ]; then
            printf "\n  %s✗ Не удалось подключиться по SSH.%s Частые причины:\n" "$R" "$N"
            printf "    • Connection refused — SSH на устройстве выключен или другой порт\n"
            printf "    • Connection timed out / No route to host — неверный адрес или устройство в другой сети\n"
            printf "    • Permission denied — неверный пользователь или пароль\n"
            printf "    • REMOTE HOST IDENTIFICATION HAS CHANGED — устройство переустановлено: ssh-keygen -R %s\n" "$host"
        fi
        printf "\n"
        ask again "Попробовать снова? (д/н)" н
        case "$again" in д*|Д*|y*|Y*) ;; *) exit $rc ;; esac
    done
    ;;
3)
    printf "\n  Скачайте deeper-watchdog-portable-linux.tar.gz со страницы релизов:\n  %s/releases/latest\n" "$REPO"
    printf "  Распакуйте и запустите ./run.sh — он спросит адрес и пароль Deeper и запустит Watchdog.\n"
    printf "  ./run.sh install-service включит автозапуск (systemd).\n\n"
    ;;
*) echo "  Нет такого пункта"; exit 1 ;;
esac
