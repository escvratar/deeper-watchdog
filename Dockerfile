FROM python:3.11-alpine

# openssl: RSA encryption of the Deeper Connect password; tzdata: local time in logs and the web UI
RUN apk add --no-cache openssl tzdata

WORKDIR /app
COPY deeper_watchdog.py /app/deeper_watchdog.py

# Settings, rules backups, event log and history live here: mount it to keep them across updates
VOLUME ["/data"]
EXPOSE 8787

ENV PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    TZ=Europe/Moscow

ENTRYPOINT ["python", "-u", "/app/deeper_watchdog.py", "--daemon"]
