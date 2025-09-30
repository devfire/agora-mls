#!/bin/bash
# Simple test script to test the join command without SSH key issues

echo "Building application..."
cd /home/ig/Documents/agora-mls
cargo build

echo "Starting application in background..."
# Start the application and redirect stdin from a file
echo "/join foo bar" | timeout 10s ./target/debug/agora-mls -l debug

echo "Test completed."