FROM node:20-alpine

# Install build tools for node-pty (native addon) + Docker CLI
RUN apk add --no-cache \
    alpine-sdk \
    python3 \
    docker-cli

WORKDIR /app

# Install Node dependencies
COPY package*.json ./
RUN npm install

# Copy application source
COPY server.js index.html ./

# Copy default data files (overridden at runtime by volume mounts)
COPY credentials.json category-defs.json ./

EXPOSE 3232

# Run as root — required to read /proc and use the Docker socket
CMD ["node", "server.js"]