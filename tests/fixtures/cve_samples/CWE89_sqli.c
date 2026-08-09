/*
 * CWE-89 SQL Injection — Juliet-style test case.
 * Source: argv -> sink: sqlite3_exec with unparameterized string concat.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Stand-in for the real sqlite3_exec to keep the fixture compile-free. */
int sqlite3_exec(void *db, const char *sql, void *cb, void *arg, char **err);

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char query[512];
    snprintf(query, sizeof(query),
             "SELECT * FROM users WHERE name='%s'", argv[1]);
    sqlite3_exec(NULL, query, NULL, NULL, NULL);
    return 0;
}
