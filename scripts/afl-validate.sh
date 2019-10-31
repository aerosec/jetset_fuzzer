#!/usr/bin/env bash

# Recompiles qemu and then runs the given script with the given input file
make clean
cd criu
make -j30
cd ..
touch accel/tcg/cpu-exec.c
make LD_LIBRARY_PATH=./criu/lib/c/ CFLAGS="$CFLAGS $PWD/criu/lib/c/built-in.o \
    -L/usr/lib/x86_64-linux-gnu/ -lprotobuf-c -DVALIDATING_AFL=1" -j30

i=0
out_dir=$4
mkdir $out_dir


while read -r f; do
    fn=$(basename -- $f)
    env TERM=dumb timeout --signal=9 $3 $1 < $f >> "${out_dir}/${i}_${fn}_res.txt" 2>&1
    i=$((i+1))

done < "$2"

wait
