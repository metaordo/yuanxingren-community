/*
 * CWE-78 OS Command Injection — Juliet-style test case.
 * Source: argv -> sink: system().
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char cmd[256];
    if (argc < 2) return 1;
    snprintf(cmd, sizeof(cmd), "echo %s", argv[1]);  /* taint enters cmd */
    system(cmd);                                       /* sink */
    return 0;
}
