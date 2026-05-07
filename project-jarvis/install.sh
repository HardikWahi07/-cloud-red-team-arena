#!/bin/bash
# Project JARVIS Install Script

echo "🚀 Initializing Project JARVIS..."

# Check dependencies
if ! [ -x "$(command -v docker)" ]; then
  echo 'Error: docker is not installed.' >&2
  exit 1
fi

if ! [ -x "$(command -v docker-compose)" ]; then
  echo 'Error: docker-compose is not installed.' >&2
  exit 1
fi

# Create .env if it doesn't exist
if [ ! -f .env ]; then
  echo "Creating .env template..."
  echo "OPENAI_API_KEY=your_key_here" > .env
fi

echo "📦 Building containers..."
docker-compose build

echo "✅ Project JARVIS is ready."
echo "Run 'docker-compose up' to start the system."
