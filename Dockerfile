# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
COPY requirements.txt ./
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then PIP_CERT=/run/secrets/proxy_ca python -m pip install --no-cache-dir -r requirements.txt; else python -m pip install --no-cache-dir -r requirements.txt; fi
COPY ids_lab ids_lab
COPY lab lab
COPY config config
COPY models models
COPY templates templates
COPY static static
COPY reports/model_metrics.json reports/model_metrics.json
CMD ["python", "-m", "ids_lab", "--database", "/data/ids.sqlite3", "status"]
