#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "trace.h"

static char trace[32];
static size_t events;

void mark(char event) {
    if (events + 1 >= sizeof(trace)) abort();
    trace[events++] = event;
    trace[events] = '\0';
}

static int check(void (*sample)(int), int raise_exception, const char *expected) {
    trace[0] = '\0';
    events = 0;
    __try { sample(raise_exception); }
    __except (GetExceptionCode() == (DWORD)0xE0420001 ?
              EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { mark('C'); }
    if (strcmp(trace, expected) == 0) {
        printf("raise=%d trace=%s\n", raise_exception, trace);
        return 0;
    }
    fprintf(stderr, "raise=%d: expected %s, got %s\n", raise_exception, expected, trace);
    return 1;
}

int main(void) {
    int failures = 0;
    failures += check(sample_except, 0, "BR");
    failures += check(sample_except, 1, "BQH");
    failures += check(sample_finally, 0, "BRF");
    failures += check(sample_finally, 1, "BFC");
    failures += check(sample_nested, 0, "BRI");
    failures += check(sample_nested, 1, "BQIO");
    return failures;
}
