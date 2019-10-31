#!/usr/bin/env bash
mkdir outputs
for i in {0..24}; do 
    if [ -z $i ]; then
	      sudo docker run --cap-add ALL --privileged --tmpfs /run -v ~/projects/aerosec/qemu.local/afl/syncdir:/usr/src/app/afl/syncdir bland_fuzz ./runall.sh -n "f${i}" -p $i > ./outputs/$i 2>&1 &
    else
        # all other fuzzers are secondary
	      sudo docker run --cap-add ALL --privileged --tmpfs /run -v ~/projects/aerosec/qemu.local/afl/syncdir:/usr/src/app/afl/syncdir bland_fuzz ./runall.sh -t S -n "f${i}" -p $i > ./outputs/$i 2>&1 &
    fi
done
