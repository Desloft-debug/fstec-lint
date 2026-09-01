FROM node:20.11-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY --chown=appuser:appuser . /app
RUN npm ci --omit=dev

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD node healthcheck.js || exit 1

CMD ["node", "server.js"]
