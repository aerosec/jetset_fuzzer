#!/usr/bin/env bash
mkdir outputs
for i in {0..24}; do 
    if [ $i = 0 ] && [ "$1" = "f" ]; then
	      sudo docker run --cap-add ALL --privileged --tmpfs /run --mount type=bind,source=/home/mbland/Projects/aerosec/cmu.fuzz/afl/syncdir,target=/usr/src/app/afl/syncdir bland_fuzz ./runall.sh -n "$1${i}" -p $i > ./outputs/$i 2>&1 &
    else
        # all other fuzzers are secondary
	      sudo docker run --cap-add ALL --privileged --tmpfs /run --mount type=bind,source=/home/mbland/Projects/aerosec/cmu.fuzz/afl/syncdir,target=/usr/src/app/afl/syncdir bland_fuzz ./runall.sh -t S -n "$1${i}" -p $i > ./outputs/$i 2>&1 &
    fi
done
