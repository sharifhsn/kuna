/* Source reference for the three C exception scopes in fork issue #3. */
#include <windows.h>
#include "trace.h"

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
