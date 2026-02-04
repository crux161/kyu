#!/bin/bash
# Kyu Archiver Build Script
echo "Building Kyu Archiver (QQX5)..."
clang -g -Wall -Wextra -std=c99 \
    core.c \
    monocypher.c \
    driver.c \
    -I./include \
    -o kyu

if [ $? -eq 0 ]; then
    echo "Build Successful: ./kyu"
else
    echo "Build Failed."
    exit 1
fi
