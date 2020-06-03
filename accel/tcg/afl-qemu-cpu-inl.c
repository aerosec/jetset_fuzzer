#include "afl-qemu-cpu-inl.h"

#define TSL_FD (FORKSRV_FD - 1)

static unsigned char afl_fork_child;
ulong afl_entry_point, /* ELF entry point (_start) */
    afl_start_code,    /* .text start pointer      */
    afl_end_code;      /* .text end pointer        */
const char *afl_fuzzer_name;
const char *afl_criu_dir;
const char *afl_criu_state_fns = 0;

static int afl_setup_done = 0;
int i_am_forkserver = 0;

/* initial forkserver pid during dump in child */
unsigned int afl_forksrv_pid;

int criu_dump_done = 0;
int afl_criu_notified = 0;
long fuzzed_cnt = 0;

/* Instrumentation ratio: */

static unsigned int afl_inst_rms = MAP_SIZE;

/* This is equivalent to afl-as.h: */
static unsigned char *afl_area_ptr;

/* Sets up afl */
inline void afl_setup_snippet(CPUState *cpu) {
#ifndef VALIDATING_AFL
  if (!afl_setup_done) {
    /* Account for time dialation */
    set_criu_dump_time();

    /* Pause the VM */
    vm_stop(4);

    afl_setup();
    afl_forkserver(cpu);

    /* In child, start the VM up again */
    vm_start();

    /* Notify afl-fuzz (not the forkserver!) that we are started */
    sigusr2_afl();

    /* We do this as close to the point where execution resumes as possible, in
       order to give the illusion that nothing at all happened */
    set_criu_restore_time();
  }
#endif
}

void kill_children(void) {
  char *buff = NULL;
  size_t len = 255;
  char command[256] = {0};

  sprintf(command, "ps -ef|awk '$3==%u {print $2}'", getpid());
  FILE *fp = (FILE *)popen(command, "r");
  while (getline(&buff, &len, fp) >= 0) {
    kill(atoi(buff), SIGKILL);
  }
  free(buff);
  fclose(fp);
}

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Set up SHM region and initialize other stuff. */

void afl_setup(void) {
#ifndef VALIDATING_AFL

  char *id_str = getenv(SHM_ENV_VAR), *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100)
      r = 100;
    if (!r)
      r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;
  }

  if (id_str) {

    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void *)-1)
      exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r)
      afl_area_ptr[0] = 1;
  }

  if (getenv("AFL_INST_LIBS")) {

    afl_start_code = 0;
    afl_end_code = (ulong)-1;
  }

  /* pthread_atfork() seems somewhat broken in util/rcu.c, and I'm
     not entirely sure what is the cause. This disables that
     behaviour, and seems to work alright? */
  rcu_disable_atfork();
#endif

  afl_setup_done = 1;
}

/**
 * Files to save for restore are specified on the command line
 */
void criu_copy_file_state(void) {
  if (afl_criu_state_fns) {
    // Of course this is vulnerable but I'm not the security-conscious type...
    char copy_str[4098];
    char filename[4098] = {0};

    char *pt = filename;
    strcpy(pt, afl_criu_state_fns);
    while (pt != NULL && *pt) {
      int i = 0;
      while (pt[i] && pt[i] != ',') {
        i++;
      }

      if (!pt[i]) {
        i--; // So that the loop halts
      } else {
        pt[i] = 0;
      }

      sprintf(copy_str, "cp %s %s", pt, afl_criu_dir);
      fprintf(stderr, "%s\n", copy_str);
      system(copy_str);

      pt += i + 1;
    }
  }
}

void criu_restore_file_state(void) {
  if (afl_criu_state_fns) {
    // Ugh, mucho repeated code with copy_file_state, but whatever
    char copy_str[4098];
    char filename[4098] = {0};
    char tmp[4098] = {0};

    char *pt = filename;
    char *basename;
    char *tmp_bn;
    strcpy(pt, afl_criu_state_fns);
    while (pt != NULL && *pt) {
      // Cut at the next comma
      int i = 0;
      while (pt[i] && pt[i] != ',') {
        i++;
      }

      if (!pt[i]) {
        i--; // So that the loop halts
      } else {
        pt[i] = 0;
      }

      // Get the base name
      strcpy(tmp, pt);
      basename = strtok(tmp, "/");
      while (1) {
        tmp_bn = strtok(NULL, "/");
        if (tmp_bn) {
          basename = tmp_bn;
        } else {
          break;
        }
      }

      // Copy the file
      sprintf(copy_str, "cp %s%s %s", afl_criu_dir, basename, pt);
      fprintf(stderr, "%s\n", copy_str);
      system(copy_str);

      // Next file in the list
      pt += i + 1;
    }
  }
}

/* Function for performing a fork, but instead of forking, restore a criu
 * process */
int criu_fork(void) {
  int shm_id;
  struct stat sb;
  char afl_criu_dir_fs_exists[128];
  strcpy(afl_criu_dir_fs_exists, afl_criu_dir);
  strcat(afl_criu_dir_fs_exists, "fs_exists");

  criu_init_opts();
  criu_set_log_level(4);
  criu_set_shell_job(1);
  /* criu_set_leave_running(1); // dangerous, but it must be done */

  /* Check if the CRIU folder exists */
  if (stat(afl_criu_dir, &sb) == 0) { /* If it exists, then do not checkpoint */

    int fd = open(afl_criu_dir, O_DIRECTORY);
    criu_set_images_dir_fd(fd);

    if (stat(afl_criu_dir_fs_exists, &sb) != 0) {

      mkdir(afl_criu_dir_fs_exists, S_IRWXU | S_IRWXG | S_IRWXO);

      // Write shared memory id for child
      char afl_criu_dir_shm_id[1024];
      strcpy(afl_criu_dir_shm_id, afl_criu_dir);
      strcat(afl_criu_dir_shm_id, "shm_id");
      FILE *shm_f = fopen(afl_criu_dir_shm_id, "w+");
      fputs(getenv(SHM_ENV_VAR), shm_f);
      fclose(shm_f);

      char tmp[1024];
      sprintf(tmp, "./syncdir/%s/parent_pid", afl_fuzzer_name);
      FILE *pid_file = fopen(tmp, "w+");
      pid_t my_pid = getpid();
      fwrite(&my_pid, sizeof(my_pid), 1, pid_file);
      fclose(pid_file);

      i_am_forkserver = 1;

      int pipefd[2];
      pipe(pipefd);
      dup2(pipefd[1], FORKSRV_FD + 2);
      dup2(pipefd[0], FORKSRV_FD + 3);
      close(pipefd[0]);
      close(pipefd[1]);
    }

    if (i_am_forkserver) {
      FILE *f;
      char tmp[1024];

      sprintf(tmp, "%s/restore.log", afl_criu_dir);
      f = fopen(tmp, "w");
      fclose(f);
      criu_set_log_file("restore.log");

      sprintf(tmp, "./syncdir/%s/stderr", afl_fuzzer_name);
      f = fopen(tmp, "a+");
      fprintf(f, "%ld\n", fuzzed_cnt);
      fclose(f);

      sprintf(tmp, "./syncdir/%s/stdout", afl_fuzzer_name);
      f = fopen(tmp, "a+");
      fprintf(f, "\n=== FUZZ CASE %ld ===\n", fuzzed_cnt++);
      fclose(f);

      fflush(stderr);
      fflush(stdout);

      criu_restore_file_state();

      /* Create a pipe for getting the proper child ID */
      int npid = fork();
      if (!npid) {

        int success = -1;
        while (success < 0) {
          // Sometimes we have stolen the pid of the restored
          // process, so we try and remove our claim on it.
          npid = fork();
          if (npid) {
            signal(SIGCHLD, SIG_IGN); // Ignore child death
            exit(0);
          }

          success = criu_restore();
        }
        setsid();
        exit(0); // Kill the cleric
      }

      signal(SIGCHLD, SIG_IGN); // Ignore child death

      npid = 0;
      fprintf(stderr, "PARENT READING CHILD PID\n");
      if (read(FORKSRV_FD + 3, &npid, 4) != 4) {
        fprintf(stderr, "PARENT READ FAILED!\n");
        exit(5);
      }
      fprintf(stderr, "PARENT READ CHILD PID %d\n", npid);

      close(fd);
      return npid;
    } else {
      fprintf(stderr, "CHILD SAW CRIU FLDR EXISTS\n");
      /* Otherwise, we are the child, and we return 0 */
      close(fd);
      return 0;
    }

  } else {
    char criu_dir_mkdir_cmd[4096];
    sprintf(criu_dir_mkdir_cmd, "mkdir -m 777 -p %s", afl_criu_dir);
    fprintf(stderr, "%s\n", criu_dir_mkdir_cmd);
    system(criu_dir_mkdir_cmd);
    int fd = open(afl_criu_dir, O_DIRECTORY);

    shmdt(afl_area_ptr); // for dump
    criu_copy_file_state();

    /* Kills original process */
    criu_set_images_dir_fd(fd);
    criu_set_log_file("dump.log");
    close(0);
    close(1);
    close(2);

    criu_dump();

    /* Now, the child will start here*/
    char tmp[1024];
    sprintf(tmp, "./syncdir/%s/.cur_input", afl_fuzzer_name);
    stdin = fopen(tmp, "r");
    sprintf(tmp, "./syncdir/%s/stderr", afl_fuzzer_name);
    stderr = fopen(tmp, "a+");
    sprintf(tmp, "./syncdir/%s/stdout", afl_fuzzer_name);
    stdout = fopen(tmp, "a+");

    /* Reinstate shared memory for fuzzing */
    char afl_criu_dir_shm_id[128];
    strcpy(afl_criu_dir_shm_id, afl_criu_dir);
    strcat(afl_criu_dir_shm_id, "shm_id");
    char id_str[128];
    FILE *shm_f = fopen(afl_criu_dir_shm_id, "r");
    char c;
    int i = 0;
    while (EOF != (c = fgetc(shm_f))) {
      id_str[i++] = c;
    }
    id_str[i] = 0;
    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    close(fd);
    setsid();

    /* Tell the parent our PID. We re-read because the
     dump recorded the pid of the original "checkpoint"
      process. */
    pid_t ppid;
    sprintf(tmp, "./syncdir/%s/parent_pid", afl_fuzzer_name);
    FILE *pid_file = fopen(tmp, "r");
    fread(&ppid, sizeof(pid_t), 1, pid_file);
    fclose(pid_file);

    sprintf(tmp, "/proc/%d/fd/%d", ppid, FORKSRV_FD + 2);
    int comm_channel = open(tmp, O_WRONLY);
    int my_pid = getpid();
    if (write(comm_channel, &my_pid, 4) != 4) {
      fprintf(stderr, "CHILD FAILED TO WRITE PID! %s\n", strerror(errno));
      exit(5);
    }
    close(comm_channel);

    fprintf(stderr, "CHILD DONE INITIALIZING\n");

    return 0;
  }
}

void kill_children(void);

/* Sends a SIGUSR2 to the AFL process, used for telling the
   parent we are alive and to start the execution timer */
void sigusr2_afl(void) {
  /* Get file */
  char tmp[1024] = {0};
  sprintf(tmp, "./syncdir/%s/afl_parent_pid", afl_fuzzer_name);
  FILE *pid_file = fopen(tmp, "r");
  pid_t afl_parent_pid;

  /* Read in PID value */
  int i = 0;
  while (fread(tmp + i, sizeof(char), 1, pid_file) == 1) {
    i++;
  }
  tmp[i] = 0;
  fclose(pid_file);

  kill(atoi(tmp), SIGUSR2);
}

/* Fork server logic, invoked once we hit _start. */
void afl_forkserver(CPUState *cpu) {
#ifndef VALIDATING_AFL
  static unsigned char tmp[4];

  if (!afl_area_ptr)
    return;

  /* Tell AFL that we are alive */
  sigusr2_afl();

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4)
    return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {

    pid_t child_pid;
    int status, t_fd[2];

    /* Whoops, parent dead? */
    if (read(FORKSRV_FD, tmp, 4) != 4)
      exit(2);

    /* Establish a channel with child to grab translation commands. We'll
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0)
      exit(3);
    close(t_fd[1]);

    child_pid = criu_fork(); // we vfork cause qemu is weird

    fprintf(stderr, "FORK DONE, RET: %d\n", child_pid);

    if (child_pid < 0)
      exit(4);

    if (!child_pid) {
      // we are in the restored child, mkae no assumptions about any vars
      /* Communicate pid to AFL for timeouts */
      child_pid = getpid();

      /* Close descriptors and run free. */
      afl_fork_child = 1;
      close(t_fd[0]);
      fprintf(stderr, "STARTING CHILD %d\n", child_pid);

      return;
    }

    /* Parent. */
    close(TSL_FD);

    /* NOTE: Sends SIGSTOP to child, handled in fuzz_read.h */
    if (ptrace(PTRACE_SEIZE, child_pid, NULL, NULL) < 0) {
      fprintf(stderr, "PTRACE SEIZE ERROR. %s", strerror(errno));
      exit(5);
    }

    fprintf(stderr, "WRITING CHILDID TO AFL %d\n", child_pid);
    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
      fprintf(stderr, "FAILED TO WRITE TO AFL! %s\n", strerror(errno));
      exit(5);
    }

    fprintf(stderr, "WROTE TO AFL!\n");

    while (1) {
      int w = waitpid(child_pid, &status, __WALL);

      if (w == -1) {
        perror("waitpid error :");
        exit(EXIT_FAILURE);
      }

      if (WIFEXITED(status)) {
        printf("exited, status=%d\n", WEXITSTATUS(status));
      } else if (WIFSIGNALED(status)) {
        printf("killed by signal %d\n", WTERMSIG(status));
      } else if (WIFSTOPPED(status)) {
        printf("stopped by signal %d\n", WSTOPSIG(status));
      } else if (WIFCONTINUED(status)) {
        printf("continued\n");
      }

      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        /* Oddly, we treat non-zero exits as crashes */
        if (WEXITSTATUS(status) != 0) {
          status = WEXITSTATUS(status);
        }

        printf("exited, sending to AFL status %d\n", status);
        if (write(FORKSRV_FD + 1, &status, 4) != 4)
          exit(7);
        printf("SENT STATUS TO AFL\n");

        // Forcefully kill all children...
        kill_children();

        break;
      }
    }
  }
#endif
}

/*
  The equivalent of the tuple logging routine from afl-as.h.
*/

/* Whether stdin, stdout have been set properly, final flag that
 fuzzing has started. */
int output_redirected = 0;
void afl_fuzz_read(uint8_t *dest, int num_bytes) {
#ifndef VALIDATING_AFL
  if (afl_setup_done) {

    /* NOTE: Maybe should wait for PTRACE_SEIZE here, technically,
      but I guess it is fine to hope and not worry if we die before
    the parent gets to us. */

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
    output_redirected = 1;
  }
#endif
    uint8_t res[num_bytes];
    int cnt = fread(res, 1, num_bytes, stdin);
    for (int i = 0; i < num_bytes; i++) {
      if (cnt != 0) {
        *dest = res[i];
        dest++;
        cnt--;
      }
    }
#ifndef VALIDATING_AFL
  }
#endif
}

inline void afl_maybe_log(ulong cur_loc) {
#ifndef VALIDATING_AFL
  static __thread ulong prev_loc;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
      Linux systems. */
  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
    return;

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
      concern. Phew. But instruction addresses may be aligned. Let's mangle
      the value to get something quasi-uniform. */

  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
      address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= afl_inst_rms)
    return;

  afl_area_ptr[cur_loc ^ prev_loc]++;
  prev_loc = cur_loc >> 1;
#endif
}

int afl_setup_isdone(void) { return afl_setup_done; }
