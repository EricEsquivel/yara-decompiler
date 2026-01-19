

#include <stdio.h>
#include <string.h>
#include "disassembler.h"
#include "decompiler.h"
#include "yara/libyara/include/yara/exec.h"
#include "yara/libyara/include/yara/compiler.h"

const char* opcode_names[256] = {
    [OP_ERROR] = "ERROR",
    [OP_HALT] = "HALT",
    [OP_NOP] = "NOP",
    [OP_AND] = "AND",
    [OP_OR] = "OR",
    [OP_NOT] = "NOT",
    [OP_BITWISE_NOT] = "BITWISE_NOT",
    [OP_BITWISE_AND] = "BITWISE_AND",
    [OP_BITWISE_OR] = "BITWISE_OR",
    [OP_BITWISE_XOR] = "BITWISE_XOR",
    [OP_SHL] = "SHL",
    [OP_SHR] = "SHR",
    [OP_MOD] = "MOD",
    [OP_INT_TO_DBL] = "INT_TO_DBL",
    [OP_STR_TO_BOOL] = "STR_TO_BOOL",
    [OP_PUSH] = "PUSH",
    [OP_POP] = "POP",
    [OP_CALL] = "CALL",
    [OP_OBJ_LOAD] = "OBJ_LOAD",
    [OP_OBJ_VALUE] = "OBJ_VALUE",
    [OP_OBJ_FIELD] = "OBJ_FIELD",
    [OP_INDEX_ARRAY] = "INDEX_ARRAY",
    [OP_COUNT] = "COUNT",
    [OP_LENGTH] = "LENGTH",
    [OP_FOUND] = "FOUND",
    [OP_FOUND_AT] = "FOUND_AT",
    [OP_FOUND_IN] = "FOUND_IN",
    [OP_OFFSET] = "OFFSET",
    [OP_OF] = "OF",
    [OP_PUSH_RULE] = "PUSH_RULE",
    [OP_INIT_RULE] = "INIT_RULE",
    [OP_MATCH_RULE] = "MATCH_RULE",
    [OP_INCR_M] = "INCR_M",
    [OP_CLEAR_M] = "CLEAR_M",
    [OP_ADD_M] = "ADD_M",
    [OP_POP_M] = "POP_M",
    [OP_PUSH_M] = "PUSH_M",
    [OP_SET_M] = "SET_M",
    [OP_SWAPUNDEF] = "SWAPUNDEF",
    [OP_FILESIZE] = "FILESIZE",
    [OP_ENTRYPOINT] = "ENTRYPOINT",
    [OP_UNUSED] = "UNUSED",
    [OP_MATCHES] = "MATCHES",
    [OP_IMPORT] = "IMPORT",
    [OP_LOOKUP_DICT] = "LOOKUP_DICT",
    [OP_JUNDEF] = "JUNDEF",
    [OP_JUNDEF_P] = "JUNDEF_P",
    [OP_JNUNDEF] = "JNUNDEF",
    [OP_JNUNDEF_P] = "JNUNDEF_P",
    [OP_JFALSE] = "JFALSE",
    [OP_JFALSE_P] = "JFALSE_P",
    [OP_JTRUE] = "JTRUE",
    [OP_JTRUE_P] = "JTRUE_P",
    [OP_JL_P] = "JL_P",
    [OP_JLE_P] = "JLE_P",
    [OP_ITER_NEXT] = "ITER_NEXT",
    [OP_ITER_START_ARRAY] = "ITER_START_ARRAY",
    [OP_ITER_START_DICT] = "ITER_START_DICT",
    [OP_ITER_START_INT_RANGE] = "ITER_START_INT_RANGE",
    [OP_ITER_START_INT_ENUM] = "ITER_START_INT_ENUM",
    [OP_ITER_START_STRING_SET] = "ITER_START_STRING_SET",
    [OP_ITER_CONDITION] = "ITER_CONDITION",
    [OP_ITER_END] = "ITER_END",
    [OP_JZ] = "JZ",
    [OP_JZ_P] = "JZ_P",
    [OP_PUSH_8] = "PUSH_8",
    [OP_PUSH_16] = "PUSH_16",
    [OP_PUSH_32] = "PUSH_32",
    [OP_PUSH_U] = "PUSH_U",
    [OP_CONTAINS] = "CONTAINS",
    [OP_STARTSWITH] = "STARTSWITH",
    [OP_ENDSWITH] = "ENDSWITH",
    [OP_ICONTAINS] = "ICONTAINS",
    [OP_ISTARTSWITH] = "ISTARTSWITH",
    [OP_IENDSWITH] = "IENDSWITH",
    [OP_IEQUALS] = "IEQUALS",
    [OP_OF_PERCENT] = "OF_PERCENT",
    [OP_OF_FOUND_IN] = "OF_FOUND_IN",
    [OP_COUNT_IN] = "COUNT_IN",
    [OP_DEFINED] = "DEFINED",
    [OP_ITER_START_TEXT_STRING_SET] = "ITER_START_TEXT_STRING_SET",
    [OP_OF_FOUND_AT] = "OF_FOUND_AT",

    [OP_INT_EQ] = "INT_EQ",
    [OP_INT_NEQ] = "INT_NEQ",
    [OP_INT_LT] = "INT_LT",
    [OP_INT_GT] = "INT_GT",
    [OP_INT_LE] = "INT_LE",
    [OP_INT_GE] = "INT_GE",
    [OP_INT_ADD] = "INT_ADD",
    [OP_INT_SUB] = "INT_SUB",
    [OP_INT_MUL] = "INT_MUL",
    [OP_INT_DIV] = "INT_DIV",
    [OP_INT_MINUS] = "INT_MINUS",
    
    [OP_DBL_EQ] = "DBL_EQ",
    [OP_DBL_NEQ] = "DBL_NEQ",
    [OP_DBL_LT] = "DBL_LT",
    [OP_DBL_GT] = "DBL_GT",
    [OP_DBL_LE] = "DBL_LE",
    [OP_DBL_GE] = "DBL_GE",
    [OP_DBL_ADD] = "DBL_ADD",
    [OP_DBL_SUB] = "DBL_SUB",
    [OP_DBL_MUL] = "DBL_MUL",
    [OP_DBL_DIV] = "DBL_DIV",
    [OP_DBL_MINUS] = "DBL_MINUS",

    [OP_STR_EQ] = "STR_EQ",
    [OP_STR_NEQ] = "STR_NEQ",
    [OP_STR_LT] = "STR_LT",
    [OP_STR_GT] = "STR_GT",
    [OP_STR_LE] = "STR_LE",
    [OP_STR_GE] = "STR_GE",

    [OP_INT8] = "INT8",
    [OP_INT16] = "INT16",
    [OP_INT32] = "INT32",
    [OP_UINT8] = "UINT8",
    [OP_UINT16] = "UINT16",
    [OP_UINT32] = "UINT32",
    [OP_INT8BE] = "INT8BE",
    [OP_INT16BE] = "INT16BE",
    [OP_INT32BE] = "INT32BE",
    [OP_UINT8BE] = "UINT8BE",
    [OP_UINT16BE] = "UINT16BE",
    [OP_UINT32BE] = "UINT32BE",
};

int get_instr_len(const uint8_t* ip)
{
    switch(*ip)
    {
        case OP_PUSH:
        case OP_PUSH_M:
        case OP_ADD_M:
        case OP_POP_M:
        case OP_SET_M:
        case OP_INCR_M:
        case OP_CLEAR_M:
        case OP_PUSH_RULE:
        case OP_MATCH_RULE:
        case OP_IMPORT:
        case OP_CALL:
        case OP_OBJ_LOAD:
        case OP_OBJ_FIELD:
        case OP_OF:
        case OP_OF_PERCENT:
        case OP_SWAPUNDEF:
            return 1 + 8;
        
        case OP_PUSH_8:
            return 1 + 1;
        
        case OP_PUSH_16:
            return 1 + 2;

        case OP_PUSH_32:
            return 1 + 4;

        case OP_JUNDEF_P:
        case OP_JNUNDEF:
        case OP_JFALSE:
        case OP_JFALSE_P:
        case OP_JTRUE:
        case OP_JTRUE_P:
        case OP_JL_P:
        case OP_JLE_P:
        case OP_JZ:
        case OP_JZ_P:
            return 1 + 4;

        case OP_INIT_RULE:
            return 1 + 4 + 4; 

        default:
            return 1;
    }
}


void print_instruction(const uint8_t* ip)
{
    if (opcode_names[*ip] == NULL)
    {
        printf("UNKNOWN_%d", *ip);
        return;
    }

    printf("%s", opcode_names[*ip]);

    switch(*ip)
    {
        case OP_PUSH:
        case OP_PUSH_M:
        case OP_ADD_M:
        case OP_POP_M:
        case OP_SET_M:
        case OP_INCR_M:
        case OP_CLEAR_M:
        case OP_PUSH_RULE:
        case OP_MATCH_RULE:
        case OP_IMPORT:
        case OP_CALL:
        case OP_OBJ_LOAD:
        case OP_OBJ_FIELD:
        case OP_SWAPUNDEF:
        {
            uintptr_t addr = *(uintptr_t*)(ip + 1);
            char* symbol = find_symbol(addr);
            if (symbol)
            {
                printf(" %s", symbol);
            }
            else
            {
                if (addr == 0xFFFABADAFABADAFFLL)
                    printf(" UNDEFINED");
                else
                    printf(" %lld (0x%llx)", (long long)addr, (unsigned long long)addr);
            }
            break;
        }

        case OP_PUSH_8:
            printf(" %d", *(uint8_t*)(ip + 1));
            break;
        
        case OP_PUSH_16:
            printf(" %d", *(uint16_t*)(ip + 1));
            break;

        case OP_PUSH_32:
            printf(" %d", *(uint32_t*)(ip + 1));
            break;

        case OP_JUNDEF_P:
        case OP_JNUNDEF:
        case OP_JFALSE:
        case OP_JFALSE_P:
        case OP_JTRUE:
        case OP_JTRUE_P:
        case OP_JL_P:
        case OP_JLE_P:
        case OP_JZ:
        case OP_JZ_P:
            printf(" %d", *(int*)(ip + 1));
            break;

        case OP_INIT_RULE:
            printf(" jmp:%d idx:%d", *(int*)(ip + 1), *(uint32_t*)(ip + 5));
            break;

        case OP_OF:
        case OP_OF_PERCENT:
            printf(" %s", *(uintptr_t*)(ip + 1) == 0 ? "STRING_SET" : "RULE_SET");
            break;
    }
}

void disassemble(const uint8_t* code_start, int rule_idx)
{
    const uint8_t* ip = code_start;
    
    while(1)
    {
        if (*ip == OP_INIT_RULE)
        {
            uint32_t current_rule_idx = *(uint32_t*)(ip + 5);
            if (current_rule_idx == rule_idx) break;
        }
        ip += get_instr_len(ip);
        if (ip > code_start + 1024*1024) return;
    }

    const uint8_t* rule_start = ip;
    int32_t jmp_offset = *(int32_t*)(ip + 1);
    const uint8_t* rule_end = rule_start + jmp_offset;

    while(ip < rule_end && *ip != OP_HALT)
    {
        printf("%04lx: ", (unsigned long)(ip - rule_start));
        print_instruction(ip);
        printf("\n");
        ip += get_instr_len(ip);
    }

    if (*ip == OP_HALT)
    {
        printf("%04lx: HALT\n", (unsigned long)(ip - rule_start));
    }
}
