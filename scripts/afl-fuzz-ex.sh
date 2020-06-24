#!/usr/bin/env bash
for i in {0..27}; do 
    if [ $i = 0 ]; then
	      sudo docker run --cap-add ALL --privileged --tmpfs /run -v $(PWD)/afl/syncdir:/usr/src/app/afl/syncdir -v /mnt/tmpfs:/mnt/tmpfs bland_fuzz ./runall.sh -n "$1${i}" -p $i -f /mnt/tmpfs/ > /dev/null 2>&1 &
    else
        # all other fuzzers are secondary
	      sudo docker run --cap-add ALL --privileged --tmpfs /run -v $(PWD)/afl/syncdir:/usr/src/app/afl/syncdir -v /mnt/tmpfs:/mnt/tmpfs bland_fuzz ./runall.sh -t S -n "$1${i}" -p $i -f /mnt/tmpfs/ > /dev/null 2>&1 &
    fi
done
