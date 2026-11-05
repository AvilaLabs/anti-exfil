/*
 * Planted bug: an attacker-influenced index lands inside a different, valid
 * heap allocation. ASan checks that the target byte is addressable, not that
 * it belongs to the object the pointer came from. Fil-C checks the pointer's
 * own bounds. FIXED checks the index against the length of `a`.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *a = malloc(64);
    char *b = malloc(64);
    char *volatile va;
    char *volatile vb;
    long idx;
    if (!a || !b)
        return 1;
    memset(a, 'a', 64);
    strcpy(b, "TOPSECRET");
    va = a;
    vb = b;
    idx = (long)(vb - va); /* distance to the other allocation */
#ifdef FIXED
    if (idx < 0 || idx >= 64) {
        puts("index refused");
        free(a);
        free(b);
        return 0;
    }
#endif
    printf("leaked: %c\n", va[idx]);
    free(a);
    free(b);
    return 0;
}
