#!/usr/bin/env bash

# Script for running AFL fuzzer with full system qemu.

# Disable block chaining
export QEMU_LOG="nochain"

FUZZ_NAME='f0'
FUZZ_TYPE='M'
ADDIT_CFLAGS=''
QEMU_TRACE_SCR=''
CPU_PIN=''
REBUILD_QEMU=0
REBUILD_AFL=0

POSITIONAL=()
while [[ $# -gt 0 ]]
do
    key="$1"

    case $key in
        # Name of fuzzer instance, also designates where to store all
        # files for the purposes of recording output, etc..
        -n|--fuzzer-name)
            FUZZ_NAME="$2"
            shift # past argument
            shift # past value
            ;;
        # Whether this is a master or secondary fuzzer, for parallelizing
        # when running under docker
        -t|--fuzzer-type)
            FUZZ_TYPE="$2"
            shift # past argument
            shift # past value
            ;;
        # Additional cflags to pass during compilation of qemu, if
        # that option is also specified
        -c|--additional-cflags)
            ADDIT_CFLAGS="$2"
            shift # past argument
            shift # past value
            ;;
        # The script to use for running qemu; should be set up to the
        # device you want to emulate
        -s|--qemu-trace-script)
            QEMU_TRACE_SCR="$2"
            shift # past argument
            shift # past value
            ;;
        # The cpu to pin AFL to; used by docer since the /proc of
        # each container is unaware of the others
        -p|--pin-cpu)
            CPU_PIN="$2"
            shift # past argument
            shift # past value
            ;;
        # Whether to recompile qemu and the qemu binary path to copy into the
        # current directory
        -q|--rebuild-qemu)
            REBUILD_QEMU=1
            QEMU_BIN_PATH="$2"
            shift # past argument
            shift # past value
            ;;
        # Whether to recompile AFL in the current directory
        -a|--rebuild-afl)
            REBUILD_AFL=1
            shift # past argument
            ;;
        --default)
            DEFAULT=YES
            shift # past argument
            ;;
        *)    # unknown option
            POSITIONAL+=("$1") # save it in an array for later
            shift # past argument
            ;;
    esac
done

if [ $REBUILD_QEMU -ne 0 ]; then
    echo "RECOMPILING QEMU"
    cd ..
    touch accel/tcg/cpu-exec.c
    make clean
    cd criu
    make -j30 || exit 1
    cd ..
    if [ "$ADDIT_CFLAGS" != "" ]; then
        make LD_LIBRARY_PATH=./criu/lib/c/ CFLAGS="$CFLAGS $PWD/criu/lib/c/built-in.o -L/usr/lib/x86_64-linux-gnu/ -lprotobuf-c $ADDIT_CFLAGS" -j30 || exit 1
    else
        make LD_LIBRARY_PATH=./criu/lib/c/ CFLAGS="$CFLAGS $PWD/criu/lib/c/built-in.o -L/usr/lib/x86_64-linux-gnu/ -lprotobuf-c" -j30 || exit 1
    fi
    sleep 1
    cd afl
    cp ../$QEMU_BIN_PATH afl-qemu
fi

if [ $REBUILD_AFL -ne 0 ]; then
    echo "RECOMPILING AFL"
    make || exit 1
fi

if [ "$QEMU_TRACE_SCR" != '' ]; then
    echo "COPYING TRACE"
    cp $QEMU_TRACE_SCR afl-qemu-trace
fi

rm -rf syncdir/$FUZZ_NAME
echo "MAKING DIRECTORIES FOR $FUZZ_NAME"
mkdir syncdir/ > /dev/null 2>&1
mkdir syncdir/$FUZZ_NAME
./run-afl.sh -$FUZZ_TYPE $FUZZ_NAME $CPU_PIN
sleep 0.2
./run-afl.sh -$FUZZ_TYPE $FUZZ_NAME $CPU_PIN
