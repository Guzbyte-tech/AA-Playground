FROM node:20

WORKDIR /app

# Copy dependencies
COPY package*.json ./

# Install cleanly
RUN npm ci

# Copy the full source
COPY . .

# Build TypeScript
RUN npm run build

# Expose API port
EXPOSE 4000

# Start server
CMD ["node", "dist/index.js"]
