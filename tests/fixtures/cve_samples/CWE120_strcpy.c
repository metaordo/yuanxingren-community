/*
 * CWE-120 Buffer Overflow — Juliet-style test case.
 * Source: user-controlled stdin -> sink: strcpy into fixed-size buffer.
 *
 * Expected detection: SVF taint analysis traces the buffer through strcpy
 * with no length check.
 */
#include <stdio.h>
#include <string.h>

void bad(char *user_input) {
    char dst[16];
    strcpy(dst, user_input);   /* sink: unbounded copy */
    printf("Copied: %s\n", dst);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        bad(argv[1]);          /* source: argv */
    }
    return 0;
}
