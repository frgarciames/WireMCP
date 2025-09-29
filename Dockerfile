# WireMCP Dockerfile - TypeScript Build
FROM node:18-alpine AS builder

# Install build dependencies
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install all dependencies (including dev dependencies for build)
RUN npm ci

# Copy source files
COPY src ./src

# Build TypeScript
RUN npm run build

# Production stage
FROM node:18-alpine

# Install tshark and required dependencies
RUN apk add --no-cache \
    tshark \
    libcap \
    bash \
    && setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production

# Copy built files from builder stage
COPY --from=builder /app/dist ./dist
COPY README.md ./

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

# Set environment variables
ENV NODE_ENV=production \
    PORT=3001 \
    HOST=0.0.0.0

# Default command runs the built JavaScript
CMD ["npm", "run", "start"]
