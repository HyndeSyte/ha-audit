# Same pinned base as the Harness App (Alpine 3.24 + Python 3.13, release
# 2026.08.0). git comes from that Alpine release; PyYAML is pinned on PyPI.
# Nothing else is fetched. The App version is baked in so it can report itself without
# any Supervisor access.
ARG BUILD_FROM=ghcr.io/home-assistant/base-python:3.13-alpine3.24-2026.08.0
FROM ${BUILD_FROM}
ARG BUILD_VERSION=0.1.0
RUN apk add --no-cache git \
    && pip install --no-cache-dir pyyaml==6.0.2
ENV AUDIT_VERSION=${BUILD_VERSION}
COPY app /opt/ha_audit
COPY rootfs /
RUN chmod a+x /etc/services.d/ha_audit/run \
    && python3 -c "import sys, yaml; sys.path.insert(0, '/opt/ha_audit'); import audit"
LABEL io.hass.type="addon" io.hass.version="0.1.0"
