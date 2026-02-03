#!/bin/bash
set -xe

cc -g -Wall -O3 -fPIC -D_DEFAULT_SOURCE -c qq.c -o qq.o

ar rcs libqq.a qq.o

cc -g -Wall -O3 qq_driver.c -L. -lqq -o qq
