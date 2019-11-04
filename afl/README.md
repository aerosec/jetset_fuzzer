# BlandFuzz: Everything is the same.

Reinstrumented version of afl that allows arbitrary fuzzing of anything, anywhere

Works by running each instance of the fuzzer in a docker container.

Check the `runall.sh` script for a listing of command line args and explanations.

## Working it

First, we compile the code and make sure everything runs okay ...

### Running Without Docker, setting up the environment

#### Decide on an input

Most likely, you will need to modify `run-afl.sh` to change the `-i` flag
to change the seed input that AFL will use for fuzzing. By default, this
is a set of files under the `./testcases` directory.

#### Start fuzzing!

These files will rebuild the project, thought the scripts may fail 
during the copying some of the files, so check that the relative paths
in the tree of scripts starting from ./runall.sh are correct.

After this runs successfully, ^C to kill it; the environment for the docker 
container is set up and the neccessary files are compiled.

```
sudo ./runall.sh -q i386-softmmu/qemu-system-i386 -a -c "-DSYNTH_ENABLED=1" -s "afl-qemu-scripts/afl-qemu-trace-synth-cmu"
```

or

```
sudo ./runall.sh -q i386-softmmu/qemu-system-i386 -a -s "afl-qemu-scripts/afl-qemu-trace-oracle-cmu"
```

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
sudo docker kill $(sudo docker ps -a -q); sudo docker rm $(sudo docker ps -a -q)
```

### A note on implementation

For a reference of how the thing works, check the commit logs.

Of course, the smart thing for the person who originally made this to have done (and for me to have figured out) 
would have been to implement the forkserver independently of Qemu and not worry about single-run fuzzing speed,
and to have used docker containers to isolate each run. Then we could just focus on lightweight snapshots like
FirmAFL and other new-age fuzzers. This works for now, the rest is left to future work.

