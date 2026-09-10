FROM node:24.20.0-bookworm-slim AS base

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

FROM base AS dependencies

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && npm cache clean --force

FROM base AS runtime

ENV NODE_ENV=production
WORKDIR /app

RUN rm -rf /usr/local/lib/node_modules/npm \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx \
    && mkdir -p /app/logs \
    && chown node:node /app /app/logs

COPY --from=dependencies --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json index.js web.js ai.js downloader.js ./

USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "index.js"]
