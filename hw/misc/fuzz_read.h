
/*
  Contains a simple definition that handles getting fuzz input from AFL
*/

#ifndef FUZZ_READ_H
#define FUZZ_READ_H

#include "qemu/osdep.h"
#include <stdio.h>

extern int afl_setup_done;
extern char *afl_fuzzer_name;
static int output_redirected = 0;
static int wrote_to_parent = 0;

static uint64_t fuzzed_read(uint64_t dflt, size_t sz) {
  if (afl_setup_done) {
    if (!wrote_to_parent) {
      char tmp[1024] = {0};
      sprintf(tmp, "./syncdir/%s/parent_pid", afl_fuzzer_name);
      FILE *pid_file = fopen(tmp, "r");
      pid_t fs_pid;
      fread(&fs_pid, sizeof(pid_t), 1, pid_file);
      fclose(pid_file);
      char properfd[1024];
      sprintf(properfd, "/proc/%d/fd/%d", fs_pid, 200); // FORKSRV_PID + 2
      int comm_channel = open(properfd, O_WRONLY);
      fprintf(stderr, "WRITING TO PARENTS CHANNEL %s\n", properfd);
      int my_pid = getpid();
      if (write(comm_channel, &my_pid, 4) != 4) {
        fprintf(stderr, "FAILED TO WRITE TO PIPE! %s\n", strerror(errno));
        exit(5);
      }
      close(comm_channel);
      fprintf(stderr, "WROTE TO PARENT\n");
      wrote_to_parent = 1;
    }

#ifndef VALIDATING_AFL
    if (!output_redirected) {
      char tmp[1024];
      fclose(stdin);
      sprintf(tmp, "./syncdir/%s/.cur_input", afl_fuzzer_name);
      stdin = fopen(tmp, "r");
      fclose(stderr);
      sprintf(tmp, "./syncdir/%s/stderr", afl_fuzzer_name);
      stderr = fopen(tmp, "a+");
      output_redirected = 1;
    }
#else
    if (!output_redirected) {
      fclose(stdin);
      stdin = fopen("/dev/stdin", "r");
      fclose(stderr);
      stderr = fopen("/dev/stderr", "a+");
      output_redirected = 1;
    }
#endif
    uint64_t res = dflt;
    int cnt = fread(&res, 1, sz, stdin);
    if (cnt == sizeof(uint64_t)) {
      return res;
    }
  }
  return dflt;
}

#endif
