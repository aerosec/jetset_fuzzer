# BlandFuzz: Everything is the same.

Reinstrumented version of afl that allows arbitrary fuzzing of anything, anywhere

Works by running each instance of the fuzzer in a docker container.

Check the `runall.sh` script for a listing of command line args and explanations.

## Working it

First, we compile the code and make sure everything runs okay ...

### Decide on an input

Most likely, you will need to modify `run-afl.sh` to change the `-i` flag
to change the seed input that AFL will use for fuzzing. By default, this
is a set of files under the `./testcases` directory.

### Start fuzzing!

These files will rebuild the project, thought the scripts may fail 
during the copying some of the files, so check that the relative paths
in the tree of scripts starting from ./runall.sh are correct.

After this runs successfully, ^C to kill it; the environment for the docker 
container is set up and the neccessary files are compiled.

Please compile with warnings treated as errors. Ideally in the future this
gets fixed by someone.

```
sudo ./runall.sh -q i386-softmmu/qemu-system-i386 -a -c "-Wno-error -DSYNTH_ENABLED=1" -s "afl-qemu-scripts/afl-qemu-trace-synth-cmu"
```

or

```
sudo ./runall.sh -q i386-softmmu/qemu-system-i386 -c "-Wno-error" -a -s "afl-qemu-scripts/afl-qemu-trace-oracle-cmu"
```

If this works, everything is in proper order!

Now, cd into the directory above this one, and use the Dockerfile to set up the container:

```
sudo docker build -t bland_fuzz .
```

The docker container is now set up for running the program, with the working directory as /afl.

```
sudo docker run --cap-add ALL --privileged --interactive --tty --tmpfs /run \
	-v ~/projects/aerosec/qemu.local/afl/syncdir:/usr/src/app/afl/syncdir \
	bland_fuzz {command to run}
```

"command to run" should be the `runall.sh` script. e.g.

```
./runall.sh -n my_fuzzer -p 2
```

Inside the docker container, a private `/proc` is used, so automatic inference of 
the cpu to pin to will fail; thus, a core must be specified explicitly or each container
will pin to CPU 0. This script pins to CPU 2.

See `../scripts/afl-fuzz-ex.sh` for an example of spinning up multiple containers.

### Cleaning up

Be sure to kill stuff after you are done! 

```
sudo docker stop $(sudo docker ps -a -q); sudo docker kill $(sudo docker ps -a -q); sudo docker rm $(sudo docker ps -a -q)
# Clean up dangling images
sudo docker rmi $(sudo docker images -qf dangling=true);
```

### A note about syncdir output

The `syncdir/{fuzzer name}/stdout` output produced labels each fuzz case with a number. There is a small
oboe here; the file that gets produced under the `syncdir/{fuzzer name}/hangs` directory is the 
fuzz case number plus 1.

### How things work

For a reference of how the thing works, check the commit logs.

Of course, the smart thing for the person who originally made this to have done (and for me to have figured out) 
would have been to implement the forkserver independently of Qemu and not worry about single-run fuzzing speed,
and to have used docker containers to isolate each run. Then we could just focus on lightweight snapshots like
FirmAFL and other new-age fuzzers. This works for now, the rest is left to future work.

### Speeding up using tmpfs

If you have the RAM for it, you should go ahead and run the whole process inside of a tmpfs; this 
is controlled by passing the `-f` flag to `runall.sh` with an argument of the location of the 
tmpfs root to run the script at.

Important: the first run, if the data is not copied, will copy the setup data to the tmpfs directory. 
You should make sure this step completes before starting docker containers, because otherwise there
will be race conditions in overwriting the files in this directory.

You may need to add some additional directory `cp` commands to the runall script, for the testcase input 
directory for AFL.

