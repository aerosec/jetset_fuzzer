/*
 * Additional bookeeping for time dialation during criu fuzzing.
 * Wraps the functions originally in timer.h for getting time.
 * Author: Bland
 * Date: 2020-03-13
 */

#ifndef CRIU_TIME_DIALATION_H
#define CRIU_TIME_DIALATION_H
#include "qemu/typedefs.h"

static int64_t criu_dump_time = 0;
static int64_t criu_restore_time = 0;

static inline int64_t criu_dialation(int64_t time) {
    int64_t criu_offset = 0;

    if (criu_dump_time && criu_restore_time) {
        criu_offset = criu_restore_time - criu_dump_time;
    }

    return time - criu_offset;
}

/*
 * Low level clock functions
 * Dialate time if fuzzing
 */

/* get host real time in nanosecond */
static inline int64_t get_clock_realtime(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return criu_dialation(tv.tv_sec * 1000000000LL + (tv.tv_usec * 1000));
}


/* Warning: don't insert tracepoints into these functions, they are
   also used by simpletrace backend and tracepoints would cause
   an infinite recursion! */
#ifdef _WIN32
extern int64_t clock_freq;

static inline int64_t get_clock(void)
{
    LARGE_INTEGER ti;
    QueryPerformanceCounter(&ti);
    return criu_dialation(muldiv64(ti.QuadPart, NANOSECONDS_PER_SECOND, clock_freq));
}

#else
extern int use_rt_clock;
static inline int64_t get_clock(void)
{
#ifdef CLOCK_MONOTONIC
    if (use_rt_clock) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return criu_dialation(ts.tv_sec * 1000000000LL + ts.tv_nsec);
    } else
#endif
    {
        /* XXX: using gettimeofday leads to problems if the date
           changes, so it should be avoided. */
        return get_clock_realtime();
    }
}
#endif

static inline void set_criu_dump_time(void) {
    criu_dump_time = get_clock();
}

static inline void set_criu_restore_time(void) {
    criu_restore_time = get_clock();
}

#endif
