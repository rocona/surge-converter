FROM node:22-bookworm-slim

ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="Surge Node Converter" \
      org.opencontainers.image.description="Convert proxy subscriptions to Surge configurations" \
      org.opencontainers.image.source="https://github.com/rocona/surge-converter" \
      org.opencontainers.image.revision="$VCS_REF"

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY server.js ./
COPY src ./src

USER node
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 8080) + '/healthz').then(r => { if (!r.ok) process.exit(1) }).catch(() => process.exit(1))"

CMD ["node", "server.js"]
