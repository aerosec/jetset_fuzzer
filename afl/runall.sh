#!/usr/bin/env bash

# Script for running AFL fuzzer with full system qemu.
export QEMU_LOG="nochain"

FUZZ_NAME='f0'
FUZZ_TYPE='M'
ADDIT_CFLAGS=''
QEMU_TRACE_SCR=''
CPU_PIN=''
REBUILD_QEMU=0
REBUILD_AFL=0
TMPFS_PATH=''

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
        # Whether to run AFL inside of a tmpfs
        -f|--fast)
            TMPFS_PATH="$2"
            shift # past argument
            shift # past value
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
        make LD_LIBRARY_PATH=./criu/lib/c/ CFLAGS="$CFLAGS -O3 $PWD/criu/lib/c/built-in.o -L/usr/lib/x86_64-linux-gnu/ -lprotobuf-c $ADDIT_CFLAGS" -j30 || exit 1
    else
        make LD_LIBRARY_PATH=./criu/lib/c/ CFLAGS="$CFLAGS -O3 $PWD/criu/lib/c/built-in.o -L/usr/lib/x86_64-linux-gnu/ -lprotobuf-c" -j30 || exit 1
    fi
    sleep 1
    cd afl
    cp ../$QEMU_BIN_PATH afl-qemu
fi

if [ $REBUILD_AFL -ne 0 ]; then
    echo "RECOMPILING AFL"
    make -j30 || exit 1
fi

if [ "$QEMU_TRACE_SCR" != '' ]; then
    echo "COPYING TRACE"
    cp $QEMU_TRACE_SCR afl-qemu-trace
fi

makedata () {
  if [ "$TMPFS_PATH" != '' ]; then
      echo "SETTING UP TMPFS"
      if [ ! -f $TMPFS_PATH/afl-fuzz ]; then
        cp afl-fuzz run-afl.sh afl-qemu afl-qemu-trace $TMPFS_PATH/
        cp -r ./testcases $TMPFS_PATH/
        cp -r ./data $TMPFS_PATH/
      fi
      cd $TMPFS_PATH
  fi

  echo "MAKING DIRECTORIES FOR $FUZZ_NAME"
  mkdir -p syncdir/$FUZZ_NAME > /dev/null 2>&1
  cp -r ./data ./syncdir/$FUZZ_NAME/
}

# We do this weird bash mumbojumbo below so that we can write
# the afl fuzzer's own pid to a file for use by subprocesses
# inside of the syncdir, which can be in tmpfs, by using the
# nicely accessible BASHPID env var (otherwise, the current shell
# would be the one executing the command). However, this requires
# us to use the coproc keyword so we can wait on the shell.

# Run twice; once to set up state, once to start fuzzing
makedata
bash -c "./run-afl.sh -$FUZZ_TYPE $FUZZ_NAME $CPU_PIN"
sleep 0.2
makedata
bash -c "./run-afl.sh -$FUZZ_TYPE $FUZZ_NAME $CPU_PIN"
