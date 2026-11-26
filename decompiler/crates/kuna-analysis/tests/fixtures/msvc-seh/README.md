# Source reference for C structured exception handling

From an x64 MSVC Developer Command Prompt in this directory:

```bat
cl /nologo /W4 /WX /O2 /EHa /TC scopes.c check.c /Fe:scopes.exe
scopes.exe
```

`scopes.c` holds the three functions under test. The separate consumer in
`check.c` calls each function on its normal and exceptional paths, compares
the exact event sequence, and returns the number of mismatches. For a later
C export round trip, compile the exported implementations with the same consumer.

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
