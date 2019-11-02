# aerosec-afl

Repository for setting up an architecture independent fuzzer based on AFL in an instance of the QEmu codebase.

## Setup

Copy this repo into the base of your QEmu instance, then

```
for f in ./patches/*; do
    patch -p1 < $f
done
```

Then, find the PC you want to checkpoint (so that each fuzz case begins at that PC and that program state).
This can be done by changing `AFL_QEMU_CPU_SNIPPET` of `accel/tcg/afl-qemu-cpu-inl.h` to print `itb->pc`.
It can also be done by modifying the code elsewhere in qemu to execute the setup code under the first
if conditional of `AFL_QEMU_CPU_SNIPPET`, e.g., have the fuzzing checkpoint once a certain sequence of 
I/O operations occurs.
If you choose the former option, specify the PC to the command line to your qemu script, as in 
`/afl/afl-qemu-scripts`, e.g. `-afl-entry 0x1033734`, otherwise choose -1 and modify `AFL_QEMU_CPU_SNIPPET`.

`-afl-start` and `-afl-end` should generally be kept at 0 and -1.  
`-afl-criu-dir ./syncdir/$1/criu/ -afl-fuzzer-name $1` should also stay the same, and must be included. 

`-afl-state-files` is an optional command line option, which is a comma-delimited list of any files 
that need to be reset after each run of the fuzzer.

Next, include /hw/misc/fuzz_read.h in any QEmu file with some functionality of the device you want to 
fuzz (e.g. syscall handling), and make a call to fuzz_read with some default value as the argument 
(this will be returned if there is no more fuzzed input to read, so 0 is a good bet). fuzz_read will return 
the next byte of fuzzer input, and this can be written to the device's registers, memory, returned from 
I/O, or whatever you want to fuzz.

## Compiling for validation

By default, all of the above will make qemu non-runnable without also having an instance of afl.
To regulate this, recompile with the VALIDATING_AFL flag; this will disable all the afl-specific
instrumentation, though it will still include the now nop-homomorphic `AFL_QEMU_CPU_SNIPPET` in 
the code (for purposes of making it to print out `itb->pc`).

The command to compile is now 

```
make LD_LIBRARY_PATH=./criu/lib/c/ CFLAGS="$CFLAGS $PWD/criu/lib/c/built-in.o \
    -L/usr/lib/x86_64-linux-gnu/ -lprotobuf-c -Wno-error -DVALIDATING_AFL=1" -j30
```

## Compiling for fuzzing

Once this is set up, read the readme under `/afl` to start the fuzzing. 

## Optional Patches 

There is also an optional patch to the `-serial` flag for QEmu that makes output append-only. This can 
be applied via the `./opt_patches` directory; if it isn't added, serial device output cannot be logged
to `./afl/syncdir/{fuzzer name}/stdout`, which is useful for determining how fuzzing is changing the 
serial output of the device. Similar changes may be neccessary if you are reliant on other file-base
output, since each CRIU restore of a fuzz instance will reset file pointer state to what it was 
at the time of a checkpoint.

## Possible Points of Failure

The possible issues are mainly in CRIU checkpointing, i.e. you do not properly reset file state, or are 
reliant on some transient shared memory file mapping. The first point of debugging may therefore be
`/afl/syncdir/{fuzzer name}/criu/restore.log` to see if there were any issues in checkpointing the
process.
