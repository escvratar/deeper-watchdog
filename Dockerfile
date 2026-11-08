FROM python:3.11-alpine

# tzdata: local time in logs and the web UI (the Deeper password is encrypted in pure Python)
RUN apk add --no-cache tzdata

WORKDIR /app
COPY deeper_watchdog.py /app/deeper_watchdog.py

# Settings, rules backups, event log and history live here: mount it to keep them across updates
VOLUME ["/data"]
EXPOSE 8787

ENV PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    TZ=Europe/Moscow

ENTRYPOINT ["python", "-u", "/app/deeper_watchdog.py", "--daemon"]
