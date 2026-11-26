# Source reference for C structured exception handling

From an x64 MSVC Developer Command Prompt in this directory:

```bat
python check_roundtrip.py
```

`scopes.c` holds the three functions under test. The separate consumer in
`check.c` calls each function on its normal and exceptional paths, compares
the exact event sequence, and returns the number of mismatches. The helper functions live in a separate translation unit so the consumer
can link against either implementation.

To test a real export with a native Windows Kuna executable:

```bat
python check_roundtrip.py --kuna C:\tools\kuna.exe --specs C:\src\kuna\specs
```

This runs the native reference, exports the three named functions and builds
and runs the generated C with the same helpers and consumer. A compiler error
or any mismatched trace fails the check. To check an export made on another
host, use `--exported-c path\to\scopes.exe.c` with its generated header beside
it. The checked-in source workflow exercises only the reference path.


| Function | Normal | Exception raised inside the body |
| --- | --- | --- |
| sample_except | BR | BQH |
| sample_finally | BRF | BFC |
| sample_nested | BRI | BQIO |

B enters the body and R reaches its normal return. Q evaluates the filter.
H and O enter the local and outer handlers. F and I are the standalone and
nested cleanup blocks. C marks the consumer catching an exception propagated
by `sample_finally`. In the nested exceptional case, the filter runs before
the inner cleanup, then control reaches the outer handler.

These are source behavior checks for C SEH. Verification of Kuna's emitted C,
C++ exception personalities and fallback output are separate requirements.
