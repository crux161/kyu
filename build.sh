#!/bin/zsh

set -xe

clang -g -Wall -O3 -D_DEFAULT_SOURCE qq.c -o qq 
