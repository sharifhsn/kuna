#ifndef SCOPES_EXE_H
#define SCOPES_EXE_H

/* kuna recompile prelude (generated): core scalar typedefs */
#include <stdbool.h>
#if defined(__STDC_VERSION__) && __STDC_VERSION__ > 201710L && (__STDC_VERSION__ >= 202311L || (defined(__clang__) && __clang_major__ >= 16) || (defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 13))
#define KUNA_ANY_ARGS ...
#else
#define KUNA_ANY_ARGS
#endif
/* target pointers are 8 bytes: compile for that data model, or a
   `T *` member of a different width moves every field after it */

typedef double float8;
typedef float float4;
typedef int int4;
typedef int wchar4;
typedef long double float10; /* sizeof may differ */
typedef long double float16; /* sizeof may differ */
typedef long long int8;
typedef short int2;
typedef short wchar2;
typedef signed char int1;
typedef unsigned char code; /* pseudo (function body) type */
typedef unsigned char uint1;
typedef unsigned char xunknown1;
typedef unsigned int uint4;
typedef unsigned int xunknown4;
typedef unsigned long long uint8;
typedef unsigned long long xunknown8;
typedef unsigned short uint2;
typedef unsigned short xunknown2;

/* the Ghidra/kuna `undefined` family */
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined3; /* 3 bytes in the decompiler; sizeof differs */
typedef unsigned int undefined4;
typedef unsigned long long undefined5; /* 5 bytes in the decompiler; sizeof differs */
typedef unsigned long long undefined6; /* 6 bytes in the decompiler; sizeof differs */
typedef unsigned long long undefined7; /* 7 bytes in the decompiler; sizeof differs */
typedef unsigned long long undefined8;
#if defined(__SIZEOF_INT128__) && !(defined(__clang__) && defined(_WIN32))
__extension__ typedef unsigned __int128 undefined16 __attribute__((aligned(1)));
#else
typedef struct { unsigned char b[16]; } undefined16;
#endif
typedef struct { unsigned char b[32]; } undefined32;

/* user-defined types */
typedef struct DNameNode_vftable DNameNode_vftable;
typedef struct DNameNode DNameNode;
typedef struct pairNode pairNode;
typedef struct pDNameNode_vftable pDNameNode_vftable;
typedef struct DNameStatusNode_vftable DNameStatusNode_vftable;
typedef struct pairNode_vftable pairNode_vftable;
typedef struct pcharNode_vftable pcharNode_vftable;
typedef struct charNode_vftable charNode_vftable;
typedef struct pcharNode pcharNode;
typedef struct std__exception_vftable std__exception_vftable; /* renamed from "std::exception_vftable" */
typedef struct std__exception std__exception; /* renamed from "std::exception" */
typedef struct std__bad_exception std__bad_exception; /* renamed from "std::bad_exception" */
typedef struct type_info_vftable type_info_vftable;
typedef struct type_info type_info;
typedef struct DNameStatusNode DNameStatusNode;
typedef struct pDNameNode pDNameNode;
typedef struct charNode charNode;
typedef struct std__bad_exception_vftable std__bad_exception_vftable; /* renamed from "std::bad_exception_vftable" */

struct DNameNode_vftable {
    void *vfunc_0;
    void *vfunc_1;
    void *vfunc_2;
    void *vfunc_3;
};

struct DNameNode {
    DNameNode_vftable *vftable;
};

struct pairNode {
    DNameNode base_DNameNode;
    void *field_0x8;
    void *field_0x10;
    unsigned int field_0x18;
    undefined1 _pad1c[4];
};

struct pDNameNode_vftable {
    void *vfunc_0;
    void *vfunc_1;
    void *vfunc_2;
    void *vfunc_3;
};

struct DNameStatusNode_vftable {
    void *vfunc_0;
    void *vfunc_1;
    void *vfunc_2;
    void *vfunc_3;
};

struct pairNode_vftable {
    void *vfunc_0;
    void *vfunc_1;
    void *vfunc_2;
    void *vfunc_3;
};

struct pcharNode_vftable {
    void *vfunc_0;
    void *vfunc_1;
    void *vfunc_2;
    void *vfunc_3;
};

struct charNode_vftable {
    void *vfunc_0;
    void *vfunc_1;
    void *vfunc_2;
    void *vfunc_3;
};

struct pcharNode {
    DNameNode base_DNameNode;
    unsigned long long field_0x8;
    int field_0x10;
    undefined1 _pad14[4];
};

/* renamed from "std::exception_vftable" */
struct std__exception_vftable {
    void *(*scalar_deleting_destructor)(std__exception *,unsigned int);
    void *vfunc_1;
};

/* renamed from "std::exception" */
struct std__exception {
    std__exception_vftable *vftable;
    unsigned long long field_0x8;
    unsigned long long field_0x10;
};

/* renamed from "std::bad_exception" */
struct std__bad_exception {
    std__exception base_exception;
};

struct type_info_vftable {
    void *(*scalar_deleting_destructor)(type_info *,unsigned int);
};

struct type_info {
    type_info_vftable *vftable;
    undefined1 _pad8[16];
};

struct DNameStatusNode {
    DNameNode base_DNameNode;
    unsigned int field_0x8;
    unsigned int field_0xc;
};

struct pDNameNode {
    DNameNode base_DNameNode;
    void *field_0x8;
};

struct charNode {
    DNameNode base_DNameNode;
    unsigned char field_0x8;
    undefined1 _pad9[7];
};

/* renamed from "std::bad_exception_vftable" */
struct std__bad_exception_vftable {
    void *(*scalar_deleting_destructor)(std__bad_exception *,unsigned int);
    void *vfunc_1;
};


/* declared call targets */
extern void body(int);
extern void mark(char);

/* function prototypes */
void sample_except(int raise_exception);
void sample_finally(int raise_exception);
void sample_nested(int raise_exception);

#endif /* SCOPES_EXE_H */
