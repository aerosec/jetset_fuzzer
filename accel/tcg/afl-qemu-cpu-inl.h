/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com> and
              Maxwell Bland <mb28@illinois.edu>

   Idea & design very much by Andrew Griffiths.

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.10.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.
*/

#ifndef AFL_QEMU_CPU_INL_H_
#define AFL_QEMU_CPU_INL_H_
#include "../../afl/config.h"
#include "qemu/typedefs.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* Function declarations. */
void kill_children(void);
void afl_setup(void);
void afl_forkserver(CPUState *cpu);
void afl_maybe_log(ulong cur_loc);
void afl_setup_snippet(CPUState *cpu);

/* Data structure passed around by the translate handlers: */
struct afl_tsl {
  ulong pc;
  ulong cs_base;
  ulong cf_mask;
  uint64_t flags;
};

#endif
