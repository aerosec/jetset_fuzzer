# aerosec-afl

Repository for setting up an architecture independent fuzzer based on AFL in an instance of the QEmu codebase.

## Setup

Copy this repo into the base of your QEmu instance, then

```
for f in ./patches/*; do
    patch -p1 < $f
done
```

### Choosing an entry point for fuzzing

`accel/tcg/afl-qemu-cpu-inl.h` defines a function called `afl_setup_snippet(CPUState * cpu)` that initializes
a checkpoint, which AFL will restore to as it feeds in different fuzz inputs to the program. You should 
put this function call somewhere in your code where you want to restore to, e.g. modifying 
`./target/arm/helper.c` to call this function whenever a specific interrupt, like a syscall, occurs. 

However, make sure this occurs after at least one basic block has been executed, or bad things will happen.
Additionally, make sure you aren't doing fuzzing inside of a timer-triggered hardware interaction; 
non-deterministic fuzz firings will mess with AFL's control server timing (maybe? Haven't tested extensively)

Another good option is to add instrumentation above the `afl_maybe_log()` function call in 
`cpu-exec.c` under `./accel/tcg/`. 
By doing this, you can not only set the `afl_setup_snippet` call to trigger on a particular instruction in
the program, but also add arbitrary instrumentation, like printing register state, to that block of the code.
Generally I start by adding a few print statements to figure out what the PC I want to checkpoint at is.
For arbitrary instrumentation make sure to set the environment variable `QEMU_LOG` to `"nochain" so that 
every itb is retranslated (you may also need to comment out the lines that are commented out in `example/cpu-exec.c`)

An example of instrumentation for syscall fuzzing in a sensitive piece of hardware is in `example/cpu-exec.c`.

If you choose this option, it is possible to specify the PC to the command line to your qemu script, as in 
`/afl/afl-qemu-scripts`, e.g. `-afl-entry 0x1033734`; this will be saved in an extern variable named
`afl_entry_point` that you may then use in your own code to check for the proper place to call 
`afl_setup_snippet`.

`-afl-start` and `-afl-end` should generally be kept at 0 and -1 unless you know what you are doing.
`-afl-criu-dir ./syncdir/$1/criu/ -afl-fuzzer-name $1` should probably stay the same (see below), and 
must be included. 

`-afl-state-files` is an optional command line option, which is a comma-delimited list of any files 
that need to be reset after each run of the fuzzer (i.e. files whose state can be modified by QEMU's runtime,
such as databases.); this works by copying the files from `./syncdir/[fuzzer-name]/criu/[files]` into 
a folder labeled "data" under the fuzzer's specific directory, i.e. `-afl-state-files ./syncdir/$1/data/data.bin`, 
and these files should be added to the `/afl/data` directory, so they may be set up properly during fuzzing. 

#### Setting afl-criu-dir to tmpfs

Since restoring can be slow, it is useful to keep CRIU state in RAM, which dramatically speeds up 
restores; you will need to create a large in-ram file system, however, and specify it on the command 
line, something like:

```
sudo mount -t tmpfs -o size=100G tmpfs /mnt/tmpfs
```

then specify `-afl-criu-dir /mnt/tmpfs/syncdir/$1/criu` to the qemu run process.

But make sure to remove the syncdir under tmpfs after each run!

Also, see additional instructions in the readme under the /afl directory.

### Feeding fuzzer input to the program

Under `./hw/misc/fuzz_read.h` there is a function called `fuzzed_read(default value, size in bytes)`,
which reads from AFLs fuzzer input (or stdin), up to 8 bytes at a time, and returns them in a 
`uint_64`. You can make a call to this function at any point in the qemu emulator, e.g., when some 
device I/O occurs, to feed fuzzer input into register state, memory, etc..

## Setting Up Crash Conditions

Oddly enough, we treat non-zero exits as crashes, since signals inside the child QEMU process 
are handled inside the guest machine, and the emulator should not send signals under expected
execution contions.

We could actually say a signal in the child is a fatal error but that is left as a TODO.

This noted, you will want to add exit condtions to the QEMU child process that the fork server 
will see as crashes.

The fork server communicates to afl the exit code of the child process, thus, to signal SIGSEGV, you 
should add 

```
exit(11); 
```

and to signal a normal exit,

```
exit(0);
```

This is defined under `accel/tcg/afl_*.c` if you would like to change this functionality somehow.

# Compiling for validation

By default, all of the above will make qemu non-runnable without also having an instance of afl.
To regulate this, recompile with the VALIDATING_AFL flag; this will disable all the afl-specific
instrumentation, though it will still include the call to `afl_maybe_log` in 
`cpu-exec.c` (though now it doesn't do anything, you can modify this function so it does extra work 
even when the rest of the fuzzing is disabled). 

Fuzzed input will be read from a file called `./stdin`, stdout, stderr will be written to files 
`./stdout`, `./stderr`, respectively. This was done for input processing, but you can change
it back by modifying `hw/misc/fuzz_read.h`.

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
