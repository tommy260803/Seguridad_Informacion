FROM python:3.13.15-slim-bookworm@sha256:ed86c82274b3c69b52fb5820f358f0bd7df0b603332063cb5c6e32bd220c3e6e

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY sandbox/requirements-infra.lock /tmp/requirements-infra.lock
RUN python -m pip install --no-cache-dir -r /tmp/requirements-infra.lock \
    && rm /tmp/requirements-infra.lock

COPY src /app/src

USER 65532:65532

ENTRYPOINT ["python", "-m", "phishguard_infra"]
