/* sanitizers controls: one planted bug per sanitizer, built with the same flags as the module build.
 * Each control must be reported by its tool; the clean variant (no -DBUG) must stay quiet. */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
int main(int argc, char **argv) {
    volatile int zero = argc - 1; /* 0, but not a compile-time constant */
#if defined(CTL_ASAN)
    char *p = (char *)malloc(16);
    p[16 * !zero + (zero ? 0 : 0)] = 1; /* index 16 of 16 (one past the end) */
    printf("%d\n", p[0]); free(p);
#elif defined(CTL_UBSAN)
    volatile int x = INT_MAX; x += 1 + zero;
    printf("%d\n", x);
#elif defined(CTL_MSAN)
    int *p = (int *)malloc(sizeof(int));
    if (*p == 12345) printf("hit\n"); /* branch on uninitialised heap */
    free(p);
#endif
    return 0;
}
