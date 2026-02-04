#!/bin/bash
echo "Building Kyu (Audit Mode)..."
clang -g -fsanitize=address,undefined -O1 -fno-omit-frame-pointer \
    core.c \
    monocypher.c \
    driver.c \
    -I./include \
    -o kyu_audit
