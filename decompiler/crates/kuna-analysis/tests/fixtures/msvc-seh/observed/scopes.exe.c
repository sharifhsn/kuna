#include "scopes.exe.h"

// Function: sample_except @ 0x140001000
void sample_except(int raise_exception)
{
  body(raise_exception);
}

// Function: sample_finally @ 0x140001020
void sample_finally(int raise_exception)
{
  body(raise_exception);
  mark('F'); // tail-call
}

// Function: sample_nested @ 0x140001040
void sample_nested(int raise_exception)
{
  body(raise_exception);
  mark('I');
}

