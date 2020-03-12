
/*
  Contains a simple definition that handles getting fuzz input from AFL
*/

#ifndef FUZZ_READ_H
#define FUZZ_READ_H

#include "qemu/osdep.h"
#include <stdio.h>

extern int afl_setup_done;
extern char *afl_fuzzer_name;
int output_redirected = 0;
static int wrote_to_parent = 0;

/**
 * Checks for a ptrace process attached to the child; used to tell when the
 * fuzzer is ready to begin execution.
 */
bool debugger_is_attached() {
  char buf[4096];

  const int status_fd = open("/proc/self/status", O_RDONLY);
  if (status_fd == -1)
    return false;

  int num_read = read(status_fd, buf, sizeof(buf) - 1);
  if (num_read <= 0) {
    return false;
  }

  char tracerPidString[] = "TracerPid:";
  char *tracer_pid_ptr = strstr(buf, tracerPidString);
  if (!tracer_pid_ptr) {
    return false;
  }

  for (char *characterPtr = tracer_pid_ptr + sizeof(tracerPidString) - 1;
       characterPtr <= buf + num_read; ++characterPtr) {
    if (isspace(*characterPtr)) {

      continue;
    } else {

      return isdigit(*characterPtr) != 0 && *characterPtr != '0';
    }
  }

  return false;
}

static uint64_t fuzzed_read(uint64_t dflt, size_t sz) {
#ifndef VALIDATING_AFL
  if (afl_setup_done) {

    /* Do the initial setup to let the parent know who we are */
    /* NOTE: why is this here? Because we want to start fuzzing
       only once we've hit the point of fuzzing, and not just
       when afl_setup_snippet is called; this allows for
       more flexible fuzzing positions. */
    if (!wrote_to_parent) {
      /* Get the parent's pid */
      char tmp[1024] = {0};
      sprintf(tmp, "./syncdir/%s/parent_pid", afl_fuzzer_name);
      FILE *pid_file = fopen(tmp, "r");
      pid_t fs_pid;
      fread(&fs_pid, sizeof(pid_t), 1, pid_file);
      fclose(pid_file);

      /* Tell the parent our PID */
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

      /* Wait for parent to PTRACE_ATTACH */
      while (!debugger_is_attached()) {
      }

      /* Wait for PTRACE_CONT */
      sigset_t sigset;
      sigemptyset(&sigset);
      sigaddset(&sigset, SIGUSR2);
      int sig;
      sigwait(&sigset, &sig);
    }

    if (!output_redirected) {
      char tmp[1024];
      fclose(stdin);
      sprintf(tmp, "./syncdir/%s/.cur_input", afl_fuzzer_name);
      stdin = fopen(tmp, "r");
      fclose(stderr);
      sprintf(tmp, "./syncdir/%s/stderr", afl_fuzzer_name);
      stderr = fopen(tmp, "a+");
      fclose(stdout);
      sprintf(tmp, "./syncdir/%s/stdout", afl_fuzzer_name);
      stdout = fopen(tmp, "a+");
      output_redirected = 1;
    }
#else
  if (!output_redirected) {
    fclose(stdin);
    stdin = fopen("./stdin", "r");
    /*
    fclose(stderr);
    stderr = fopen("./stderr", "a+");
    fclose(stdout);
    stdout = fopen("./stdout", "a+");
    */
    output_redirected = 1;
  }
#endif
    uint64_t res = 0;
    int cnt = fread(&res, 1, sz, stdin);
    if (cnt == sz) {
      return res;
    }
#ifndef VALIDATING_AFL
  }
#endif
  return dflt;
}

#endif
