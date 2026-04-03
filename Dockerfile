# ═══════════════════════════════════════════════════
# ShieldNet MCP — Dockerfile (Multi‑stage)
# ═══════════════════════════════════════════════════

# ── Stage 1: Install dependencies ─────────────────
FROM node:22-alpine AS deps

WORKDIR /build

COPY package.json package-lock.json ./

RUN npm ci --omit=dev && \
    npm cache clean --force

# ── Stage 2: Production image ─────────────────────
FROM node:22-alpine AS production

LABEL org.opencontainers.image.title="ShieldNet MCP" \
      org.opencontainers.image.description="MCP Security Scanner — AI Agent Security Governance" \
      org.opencontainers.image.license="MIT"

WORKDIR /app

# Create non‑root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy production deps from builder
COPY --from=deps /build/node_modules ./node_modules

# Copy application source
COPY package.json ./
COPY src/ ./src/

# Ownership & permissions
RUN chown -R appuser:appgroup /app

USER appuser

# MCP servers communicate over stdio — no network port exposed.
# If ever used with SSE transport, uncomment below:
# EXPOSE 3100

ENTRYPOINT ["node"]
CMD ["src/index.js"]
