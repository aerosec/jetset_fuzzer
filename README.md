# aerosec-afl

Repository for setting up an architecture independent fuzzer based on AFL in an instance of the QEmu codebase.

## Setup

Copy this repo into the base of your QEmu instance, then

```
for f in ./patches/*; do
    patch -p1 < $f
done
```

Then, find the PC you want to checkpoint (so that each fuzz case begins at that PC and that program state), 
and specify it to the command line to your qemu script, as in `/afl/afl-qemu-scripts`, e.g. `-afl-entry 0x1033734`, 

`-afl-start` and `-afl-end` should generally be kept at 0 and -1.  
`-afl-criu-dir ./syncdir/$1/criu/ -afl-fuzzer-name $1` should also stay the same, and must be included. 

`-afl-state-files` is an optional command line option, which is a comma-delimited list of any files 
that need to be reset after each run of the fuzzer.

Next, include /hw/misc/fuzz_read.h in any QEmu file with some functionality of the device you want to 
fuzz (e.g. syscall handling), and make a call to fuzz_read with some default value as the argument 
(this will be returned if there is no more fuzzed input to read, so 0 is a good bet). fuzz_read will return 
the next byte of fuzzer input, and this can be written to the device's registers, memory, returned from 
I/O, or whatever you want to fuzz.

Once this is set up, read the readme under `/afl` to start the fuzzing. 
