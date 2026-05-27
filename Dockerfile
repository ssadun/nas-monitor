FROM node:20-alpine

# Install Docker CLI for container monitoring and management
RUN apk add --no-cache \
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
