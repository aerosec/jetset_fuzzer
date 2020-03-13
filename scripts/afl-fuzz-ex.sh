#!/usr/bin/env bash
mkdir outputs
for i in {0..27}; do 
    if [ $i = 0 ]; then
	      sudo docker run --cap-add ALL --privileged --tmpfs /run -v /home/mbland/Projects/aerosec/cmu.fuzz/afl/syncdir:/usr/src/app/afl/syncdir -v /mnt/tmpfs:/mnt/tmpfs bland_fuzz ./runall.sh -n "$1${i}" -p $i > ./outputs/$i 2>&1 &
    else
        # all other fuzzers are secondary
	      sudo docker run --cap-add ALL --privileged --tmpfs /run -v /home/mbland/Projects/aerosec/cmu.fuzz/afl/syncdir:/usr/src/app/afl/syncdir -v /mnt/tmpfs:/mnt/tmpfs bland_fuzz ./runall.sh -t S -n "$1${i}" -p $i > ./outputs/$i 2>&1 &
    fi
done
