#!/bin/bash
set -e

# Setup dependencies
#./vendor.sh

# Compile
# Added ustar.c to the source list
gcc -std=c99 -Wall -Wextra -Wpedantic \
    -I./include \
    core.c archive.c driver.c ustar.c monocypher.c \
    -o kyu

echo "Build complete: ./kyu"
