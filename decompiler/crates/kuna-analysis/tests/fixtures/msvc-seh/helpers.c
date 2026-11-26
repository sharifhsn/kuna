#include <windows.h>
#include "helpers.h"

#define SAMPLE_EXCEPTION ((DWORD)0xE0420001)

__declspec(noinline) void body(int raise_exception) {
    mark('B');
    if (raise_exception) RaiseException(SAMPLE_EXCEPTION, 0, 0, NULL);
    mark('R');
}

__declspec(noinline) int filter(DWORD code) {
    mark('Q');
    return code == SAMPLE_EXCEPTION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}
