--- a/include/qemu/timer.h
+++ b/include/qemu/timer.h
@@ -5,6 +5,7 @@
 #include "qemu/bitops.h"
 #include "qemu/notify.h"
 #include "qemu/host-utils.h"
+#include "criu/time-dialation.h"
 
 #define NANOSECONDS_PER_SECOND 1000000000LL
 
@@ -838,52 +839,6 @@ static inline int64_t get_max_clock_jump(void)
     return 60 * NANOSECONDS_PER_SECOND;
 }
 
-/*
- * Low level clock functions
- */
-
-/* get host real time in nanosecond */
-static inline int64_t get_clock_realtime(void)
-{
-    struct timeval tv;
-
-    gettimeofday(&tv, NULL);
-    return tv.tv_sec * 1000000000LL + (tv.tv_usec * 1000);
-}
-
-/* Warning: don't insert tracepoints into these functions, they are
-   also used by simpletrace backend and tracepoints would cause
-   an infinite recursion! */
-#ifdef _WIN32
-extern int64_t clock_freq;
-
-static inline int64_t get_clock(void)
-{
-    LARGE_INTEGER ti;
-    QueryPerformanceCounter(&ti);
-    return muldiv64(ti.QuadPart, NANOSECONDS_PER_SECOND, clock_freq);
-}
-
-#else
-
-extern int use_rt_clock;
-
-static inline int64_t get_clock(void)
-{
-#ifdef CLOCK_MONOTONIC
-    if (use_rt_clock) {
-        struct timespec ts;
-        clock_gettime(CLOCK_MONOTONIC, &ts);
-        return ts.tv_sec * 1000000000LL + ts.tv_nsec;
-    } else
-#endif
-    {
-        /* XXX: using gettimeofday leads to problems if the date
-           changes, so it should be avoided. */
-        return get_clock_realtime();
-    }
-}
-#endif
 
 /* icount */
 int64_t cpu_get_icount_raw(void);
