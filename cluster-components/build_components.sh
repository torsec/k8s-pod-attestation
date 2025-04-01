#!/bin/bash

# Loop through all directories in the current directory
for dir in */; do
    # Enter the directory
    cd "$dir" || continue
    
    # Find any .sh file in the directory
    sh_file=$(ls *.sh 2>/dev/null | head -n 1)
    
    if [ -n "$sh_file" ]; then
        echo "Running $sh_file in $dir"
        chmod +x "$sh_file"  # Ensure it's executable
        ./$sh_file
    else
        echo "Skipping $dir (no .sh file found)"
    fi
    
    # Return to the parent directory
    cd ..
done
