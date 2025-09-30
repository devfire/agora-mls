#!/bin/bash
# Simple test script to send /join command to the running application

echo "Starting test script..."

# Start the application in background with debug logging
cd /home/ig/Documents/agora-mls
cargo run -- -l debug &
APP_PID=$!

echo "Application started with PID: $APP_PID"

# Wait for application to start
sleep 3

echo "Sending /join foo bar command..."
# Send the command to the application
echo "/join foo bar" > /proc/$APP_PID/fd/0

# Wait a bit to see the output
sleep 2

# Clean up
kill $APP_PID 2>/dev/null
echo "Test completed."