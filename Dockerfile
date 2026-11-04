# syntax=docker/dockerfile:1
FROM python:3.13-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
RUN python -m venv /opt/venv
# Dependencies first, from the hashed lock file: fixed versions, verified hashes.
COPY requirements.lock ./
RUN /opt/venv/bin/pip install --require-hashes --no-deps -r requirements.lock
COPY pyproject.toml README.md ./
COPY src ./src
RUN /opt/venv/bin/pip install --no-deps .

FROM python:3.13-slim
# git: the admin UI installs plugins from git repositories (src/mcpopus/sources.py)
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin mcpopus \
 && mkdir -p /config /data /plugins \
 && chown 10001:10001 /config /data
COPY --from=build /opt/venv /opt/venv
COPY plugins/hello /opt/mcpopus/examples/hello
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCPOPUS_DATA_DIR=/data \
    MCPOPUS_CONFIG_DIR=/config \
    MCPOPUS_PLUGINS_DIR=/plugins \
    MCPOPUS_PUBLIC_BIND=0.0.0.0 \
    MCPOPUS_PUBLIC_PORT=8080 \
    MCPOPUS_ADMIN_BIND=0.0.0.0 \
    MCPOPUS_ADMIN_PORT=8081
USER 10001
EXPOSE 8080 8081
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["mcpopus", "healthcheck"]
ENTRYPOINT ["mcpopus"]
CMD ["run"]
