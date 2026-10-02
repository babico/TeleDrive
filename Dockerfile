FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TELEDRIVE_CONFIG=/config/config.yaml \
    TELEDRIVE_AUTH_DIR=/data/auth

RUN groupadd --gid 10001 teledrive && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin teledrive

WORKDIR /app
COPY requirements-web.txt /app/requirements-web.txt
ARG TELEDRIVE_DB_EXTRA_PACKAGES=""
RUN pip install --no-cache-dir -r /app/requirements-web.txt \
 && if [ -n "$TELEDRIVE_DB_EXTRA_PACKAGES" ]; then pip install --no-cache-dir $TELEDRIVE_DB_EXTRA_PACKAGES; fi

COPY db.py uploader.py webapp.py /app/
COPY static /app/static
COPY config.docker.example.yaml /app/config.docker.example.yaml
RUN mkdir -p /config /data/sessions /data/auth /data/tmp /uploads \
 && chown -R 10001:10001 /config /data /uploads /app

USER 10001:10001

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3)" || exit 1

CMD ["uvicorn","webapp:app","--host","0.0.0.0","--port","8080","--workers","1"]
