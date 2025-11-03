#!/bin/bash
set -euo pipefail

# Get tag from first argument, default to "latest"
TAG=${1:-latest}

# Loop through all subdirectories in cmd
for dir in */; do
    echo "------------------------------------------------------------------------------------"
    echo "Processing directory: $dir"

    # Enter the directory
    cd "$dir"

    # Find the first .sh file
    sh_file=$(find . -maxdepth 1 -type f -name "*.sh" | head -n 1)

    if [ -n "$sh_file" ]; then
        echo "Running $sh_file in $dir with tag: $TAG"
        chmod +x "$sh_file"
        ./"$sh_file" "$TAG"
    else
        echo "Skipping $dir (no .sh file found)"
    fi

    # Return to parent directory
    cd ..
done
