/* Source reference for the three C exception scopes in fork issue #3. */
#include <windows.h>
#include "trace.h"

#define SAMPLE_EXCEPTION ((DWORD)0xE0420001)

static __declspec(noinline) void body(int raise_exception) {
    mark('B');
    if (raise_exception) RaiseException(SAMPLE_EXCEPTION, 0, 0, NULL);
    mark('R');
}

static __declspec(noinline) int filter(DWORD code) {
    mark('Q');
    return code == SAMPLE_EXCEPTION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

__declspec(noinline) void sample_except(int raise_exception) {
    __try { body(raise_exception); }
    __except (filter(GetExceptionCode())) { mark('H'); }
}

__declspec(noinline) void sample_finally(int raise_exception) {
    __try { body(raise_exception); }
    __finally { mark('F'); }
}

__declspec(noinline) void sample_nested(int raise_exception) {
    __try {
        __try { body(raise_exception); }
        __finally { mark('I'); }
    } __except (filter(GetExceptionCode())) {
        mark('O');
    }
}
