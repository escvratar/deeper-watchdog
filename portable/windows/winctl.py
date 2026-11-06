"""Helpers for the Windows portable version (called by the .bat files, which stay ASCII: cmd's code pages
mangle Russian text in .bat files). python winctl.py start-note | settings-note | autostart | stop [quiet]"""
import os
import sys
import signal
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
PID_FILE = os.path.join(HERE, "data", "watchdog.pid")
STARTUP = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup",
                       "Deeper Watchdog.bat")


def port():
    try:
        with open(os.path.join(HERE, ".env"), encoding="utf-8") as f:
            for line in f:
                if line.startswith("WEB_PORT="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return "8787"


def running_pid():
    """The background watchdog's process number, if that process is still our Python."""
    try:
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
    except (OSError, ValueError):
        return None
    try:
        # Bytes: tasklist writes in the OEM code page (memory sizes carry a non-UTF-8 space)
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                             capture_output=True, timeout=15).stdout.decode("ascii", "replace").lower()
    except Exception:
        return None
    # After a reboot the number may belong to another program
    return pid if "python" in out else None


def stop(quiet=False):
    pid = running_pid()
    if pid is None:
        if not quiet:
            print("Deeper Watchdog не запущен.")
        return
    try:
        os.kill(pid, signal.SIGTERM)  # TerminateProcess on Windows
    except OSError as e:
        print(f"Не удалось остановить процесс {pid}: {e}")
        return
    try:
        os.remove(PID_FILE)
    except OSError:
        pass
    if not quiet:
        print("Deeper Watchdog остановлен.")


def start_background():
    pyw = os.path.join(HERE, "python", "pythonw.exe")
    log = os.path.join(HERE, "data", "watchdog.log")
    os.makedirs(os.path.dirname(log), exist_ok=True)
    subprocess.Popen([pyw, os.path.join(HERE, "deeper_watchdog.py"), "--daemon", "--log-file", log], cwd=HERE,
                     creationflags=getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))


def autostart():
    if os.path.exists(STARTUP):
        os.remove(STARTUP)
        stop(quiet=True)
        print("Автозапуск выключен, фоновый Watchdog остановлен.")
        return
    pyw = os.path.join(HERE, "python", "pythonw.exe")
    log = os.path.join(HERE, "data", "watchdog.log")
    line = f'@start "" "{pyw}" "{os.path.join(HERE, "deeper_watchdog.py")}" --daemon --log-file "{log}"\r\n'
    # cmd reads .bat files in the console (OEM) code page: a Russian user name in the path must be written in it
    try:
        import ctypes
        enc = f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    except Exception:
        enc = "cp866"
    try:
        data = line.encode(enc)
    except UnicodeEncodeError:
        # Letters the code page lacks: the short 8.3 names of the folders are plain ASCII
        import ctypes
        buf = ctypes.create_unicode_buffer(1024)
        ctypes.windll.kernel32.GetShortPathNameW(HERE, buf, 1024)
        line = line.replace(HERE, buf.value)
        data = line.encode(enc, errors="replace")
    os.makedirs(os.path.dirname(STARTUP), exist_ok=True)
    with open(STARTUP, "wb") as f:
        f.write(data)
    stop(quiet=True)
    start_background()
    print("Автозапуск включён: Watchdog запущен в фоне и будет запускаться при входе в Windows.")
    print(f"Веб-интерфейс: http://127.0.0.1:{port()}/   Журнал: data\\watchdog.log")
    print("Выключить: запустите Autostart.bat ещё раз.")


def start_note():
    if running_pid():
        print(f"Watchdog уже работает в фоне: http://127.0.0.1:{port()}/ (остановить: Stop.bat)")
        sys.exit(1)
    print()
    print("Deeper Watchdog работает, пока открыто это окно (закрыть окно = остановить).")
    print("Чтобы он работал в фоне и запускался вместе с Windows: Autostart.bat")
    print()


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "stop":
        stop(quiet="quiet" in sys.argv)
    elif cmd == "autostart":
        autostart()
    elif cmd == "start-note":
        start_note()
    elif cmd == "settings-note":
        print("Новые настройки действуют после перезапуска Watchdog (Stop.bat, затем Start.bat или Autostart.bat).")
    else:
        print(__doc__)
