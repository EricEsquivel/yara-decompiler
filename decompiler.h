
#ifndef YARA_DECOMPILER_H
#define YARA_DECOMPILER_H

#include <stdint.h>

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
    uint32_t buffer_id;
    uint32_t offset;
    char* name;
} SYMBOL;

extern SYMBOL* symbol_table;
extern int num_symbols;

char* find_symbol(uint32_t buffer_id, uint32_t offset);

void decompile_rule_condition(const uint8_t* code_start, int rule_idx);

#endif
