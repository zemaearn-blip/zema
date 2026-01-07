#!/bin/bash

echo "🚀 Starting ZEMA Platform..."

# Create necessary directories
mkdir -p public
mkdir -p uploads/payments

# Set permissions
chmod -R 755 uploads
chmod -R 755 public

# Install dependencies if not installed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install --production
    echo "✅ Dependencies installed"
fi

# Start the server
echo "🌐 Starting server on port ${PORT:-10000}..."
node server.js
