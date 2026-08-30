# syntax=docker/dockerfile:1.7

ARG PYTHON_VERSION=3.12.13

FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src/retrywise

RUN python -m venv /opt/retrywise-venv

COPY pyproject.toml README.md __init__.py ./
COPY packages ./packages
COPY services ./services

RUN /opt/retrywise-venv/bin/python -m pip install --no-compile ".[api]" \
    && /opt/retrywise-venv/bin/python -c \
       "import fastapi, psycopg, uvicorn; import retrywise.services.control_plane.api"


FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="RetryWise control plane" \
      org.opencontainers.image.description="Policy-governed Razorpay payment recovery API"

ENV PATH="/opt/retrywise-venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0 \
    RETRYWISE_API_BIND_HOST=0.0.0.0 \
    RETRYWISE_API_PORT=8000

RUN groupadd --gid 10001 retrywise \
    && useradd --uid 10001 --gid retrywise --no-create-home \
       --shell /usr/sbin/nologin retrywise

COPY --from=builder --chown=10001:10001 /opt/retrywise-venv /opt/retrywise-venv

WORKDIR /app
USER 10001:10001

EXPOSE 8000
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2).read()"]

# API and worker are separate process roles built from the same immutable image.
# Access logs are disabled because the webhook endpoint token is part of the URL.
CMD ["uvicorn", "retrywise.services.control_plane.api:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "1", \
     "--no-access-log", "--no-server-header", "--limit-concurrency", "100", \
     "--timeout-keep-alive", "5"]
