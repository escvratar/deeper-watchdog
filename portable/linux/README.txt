Deeper Watchdog без Docker (Linux, macOS, роутеры с Python 3)
=============================================================

Нужен только Python 3.8+ (есть почти везде; Ubuntu/Debian: sudo apt install python3).

  ./run.sh                   запуск; первый запуск спросит адрес и пароль Deeper Connect,
                             порт и пароль веб-интерфейса и сразу проверит вход в Deeper
  ./run.sh install-service   работать в фоне и запускаться вместе с системой (systemd или cron)
  ./run.sh remove-service    выключить автозапуск
  ./run.sh setup             сменить адрес и пароли
  ./run.sh status            состояние

Веб-интерфейс: http://<IP этого устройства>:8787/
Настройки и журнал: папка data и файл .env рядом с run.sh.
Обновление: замените deeper_watchdog.py новым (data и .env не трогайте) и перезапустите.

https://github.com/escvratar/deeper-watchdog
