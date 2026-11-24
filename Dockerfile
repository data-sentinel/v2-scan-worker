# Data Sentinel Vantage V2 scan worker 2026.48.2 - worker core standard 2026-48-11 §2
# Builds for linux/amd64 and linux/arm64, wheels only. No Java, no Oracle client, no ODBC.
#   docker buildx build --platform linux/amd64,linux/arm64 --build-arg DS_UID=<uid> --build-arg DS_GID=<gid> -t ds_scan:2026.48.2 .
FROM python:3.13-slim-trixie

ARG DS_UID=10001
ARG DS_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --only-binary=:all: --no-deps -r requirements.txt \
    && pip check

COPY ds_scan.py ds_connect_lib.py main.py ./

RUN groupadd --gid ${DS_GID} ds \
    && useradd --uid ${DS_UID} --gid ${DS_GID} --no-create-home --shell /usr/sbin/nologin ds \
    && mkdir -p /mnt/logs /mnt/datasets /mnt/scan_tmp \
    && chown ${DS_UID}:${DS_GID} /mnt/logs /mnt/datasets /mnt/scan_tmp

USER ${DS_UID}:${DS_GID}

# the port is Kevin's to give (architect note 2026-48-10, ruling 18): set DS_SERVICE_PORT in the stack
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import os,sys,urllib.request; p=os.environ.get('DS_SERVICE_PORT','5540'); sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+p+'/health', timeout=4).status==200 else 1)"]

STOPSIGNAL SIGTERM

CMD ["python", "main.py"]
