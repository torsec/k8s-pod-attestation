#!/bin/bash

# Loop through all directories in the current directory
for dir in */; do
    # Enter the directory
    cd "$dir" || continue
    
    # Check if go.mod exists to confirm it's a Go module
    if [ -f "go.mod" ]; then
        echo "Updating dependencies in $dir"
        go get -u
    else
        echo "Skipping $dir (no go.mod found)"
    fi
    
    # Return to the parent directory
    cd ..
done
