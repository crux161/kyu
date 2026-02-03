#!/bin/zsh 

time ./qq -c ./big.txt ./big.qq
time ./qq -d ./big.qq ./big_q.txt
ls -lah *.qq *.txt && \
diff big.txt big_q.txt && \
sha256sum ./big.txt && \
sha256sum ./big_q.txt
