#!/usr/bin/env bash
echo $BASHPID > ./syncdir/$2/afl_parent_pid
exec ./afl-fuzz -i testcases/others/syscall/ -o syncdir/ -t 30 -m 5G -Q $1 $2 -c $3 -- ignored
