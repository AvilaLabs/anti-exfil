/* Planted bug: the first byte is read after the block is freed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *p = malloc(16);
    if (!p)
        return 1;
    memcpy(p, "abc", 4);
#ifndef FIXED
    free(p);
#endif
    printf("%c\n", p[0]);
#ifdef FIXED
    free(p);
#endif
    return 0;
}
