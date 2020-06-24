sudo docker run -it --cap-add ALL --privileged --tmpfs /run -v $(PWD)/afl/syncdir:/usr/src/app/afl/syncdir -v /mnt/tmpfs:/mnt/tmpfs bland_fuzz ./runall.sh -n "f0" -p 0 -f /mnt/tmpfs/
