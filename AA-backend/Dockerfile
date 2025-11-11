# Use node image
FROM node:20

# Set working directory
WORKDIR /app

# Copy package.json and install deps
COPY package*.json ./
RUN npm install

# Copy rest of the source code
COPY . .

# Build TypeScript
RUN npm run build

# Expose port
EXPOSE 4000

# Start the app
CMD ["node", "dist/index.js"]
