# Build stage
FROM node:18-alpine AS build-stage

EXPOSE 3001
WORKDIR /app

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"

# Install corepack, copy the app, install dependencies and build the app
RUN corepack enable

# Copy package files
COPY package.json pnpm-lock.yaml ./
COPY tsconfig.json ./

# Copy source files
COPY src ./src

ENV COREPACK_INTEGRITY_KEYS=0
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile


# Set environment variables
ENV NODE_ENV=production \
    PORT=3001 \
    HOST=0.0.0.0

# Build TypeScript
RUN pnpm run build


# Install tshark and required dependencies
RUN apk add --no-cache \
    tshark \
    libcap \
    bash \
    && setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap


# Create a non-root user with network capture capabilities
RUN addgroup -S wiremcp && \
    adduser -D -S -G wiremcp wiremcp && \
    addgroup wiremcp wireshark

# Set proper permissions
RUN chown -R wiremcp:wiremcp /app

# Switch to non-root user
USER wiremcp

# Expose the port for remote mode
EXPOSE 3001

# Production stage
FROM build-stage AS production-stage

# Copy built files from builder stage
COPY --from=build-stage /app/dist ./dist
COPY README.md ./

# Default command runs the built JavaScript
CMD ["pnpm", "run", "start"]
