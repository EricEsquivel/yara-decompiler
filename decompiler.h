#ifndef YARA_DECOMPILER_H
#define YARA_DECOMPILER_H

#include <stdint.h>
#include "../libyara/include/yara/types.h"
#include "../libyara/include/yara/arena.h"

typedef struct _DECOMPILED_META
{
    char* identifier;
    char* string;
    int64_t integer;
    int32_t type;

} DECOMPILED_META;

typedef struct _DECOMPILED_STRING
{
    uint32_t flags;
    char* identifier;
    char* string;
    int32_t length;

} DECOMPILED_STRING;

typedef struct _DECOMPILED_RULE
{
    char* identifier;
    char* tags;
    DECOMPILED_META* metas;
    DECOMPILED_STRING* strings;
    int num_metas;
    int num_strings;

} DECOMPILED_RULE;

typedef struct _DECOMPILED_YARA_FILE
{
    DECOMPILED_RULE* rules;
    int num_rules;

} DECOMPILED_YARA_FILE;

typedef struct _SYMBOL {
    uintptr_t addr;
    char* name;
} SYMBOL;

typedef struct YR_ARENA_FILE_HEADER YR_ARENA_FILE_HEADER;
typedef struct YR_ARENA_FILE_BUFFER YR_ARENA_FILE_BUFFER;

#pragma pack(push)
#pragma pack(1)

struct YR_ARENA_FILE_HEADER
{
  uint8_t magic[4];
  uint8_t version;
  uint8_t num_buffers;
};

struct YR_ARENA_FILE_BUFFER
{
  uint64_t offset;
  uint32_t size;
};

#pragma pack(pop)

extern SYMBOL* symbol_table;
extern int num_symbols;
extern uintptr_t mapped_base;
extern size_t mapped_size;

char* find_symbol(uintptr_t addr);

void decompile_rule_condition(const uint8_t* code_start, int rule_idx);

void* resolve_ref(uint8_t* file_mem, YR_ARENA_FILE_BUFFER* buffers, YR_ARENA_REF* ref);

void print_meta(YR_META* meta, uint8_t* file_mem, YR_ARENA_FILE_BUFFER* buffers);
void print_string(YR_STRING* string, uint8_t* file_mem, YR_ARENA_FILE_BUFFER* buffers);

#endif