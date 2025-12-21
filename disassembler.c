#include <stdio.h>
#include "disassembler.h"
#include "decompiler.h"
#include "../libyara/include/yara/exec.h"

const char* opcode_names[256] = {
    [OP_ERROR] = "OP_ERROR",
    [OP_HALT] = "OP_HALT",
    [OP_NOP] = "OP_NOP",
    [OP_AND] = "OP_AND",
    [OP_OR] = "OP_OR",
    [OP_NOT] = "OP_NOT",
    [OP_BITWISE_NOT] = "OP_BITWISE_NOT",
    [OP_BITWISE_AND] = "OP_BITWISE_AND",
    [OP_BITWISE_OR] = "OP_BITWISE_OR",
    [OP_BITWISE_XOR] = "OP_BITWISE_XOR",
    [OP_SHL] = "OP_SHL",
    [OP_SHR] = "OP_SHR",
    [OP_MOD] = "OP_MOD",
    [OP_INT_TO_DBL] = "OP_INT_TO_DBL",
    [OP_STR_TO_BOOL] = "OP_STR_TO_BOOL",
    [OP_PUSH] = "OP_PUSH",
    [OP_POP] = "OP_POP",
    [OP_CALL] = "OP_CALL",
    [OP_OBJ_LOAD] = "OP_OBJ_LOAD",
    [OP_OBJ_VALUE] = "OP_OBJ_VALUE",
    [OP_OBJ_FIELD] = "OP_OBJ_FIELD",
    [OP_INDEX_ARRAY] = "OP_INDEX_ARRAY",
    [OP_COUNT] = "OP_COUNT",
    [OP_LENGTH] = "OP_LENGTH",
    [OP_FOUND] = "OP_FOUND",
    [OP_FOUND_AT] = "OP_FOUND_AT",
    [OP_FOUND_IN] = "OP_FOUND_IN",
    [OP_OFFSET] = "OP_OFFSET",
    [OP_OF] = "OP_OF",
    [OP_PUSH_RULE] = "OP_PUSH_RULE",
    [OP_INIT_RULE] = "OP_INIT_RULE",
    [OP_MATCH_RULE] = "OP_MATCH_RULE",
    [OP_INCR_M] = "OP_INCR_M",
    [OP_CLEAR_M] = "OP_CLEAR_M",
    [OP_ADD_M] = "OP_ADD_M",
    [OP_POP_M] = "OP_POP_M",
    [OP_PUSH_M] = "OP_PUSH_M",
    [OP_SET_M] = "OP_SET_M",
    [OP_SWAPUNDEF] = "OP_SWAPUNDEF",
    [OP_FILESIZE] = "OP_FILESIZE",
    [OP_ENTRYPOINT] = "OP_ENTRYPOINT",
    [OP_UNUSED] = "OP_UNUSED",
    [OP_MATCHES] = "OP_MATCHES",
    [OP_IMPORT] = "OP_IMPORT",
    [OP_LOOKUP_DICT] = "OP_LOOKUP_DICT",
    [OP_JUNDEF] = "OP_JUNDEF",
    [OP_JUNDEF_P] = "OP_JUNDEF_P",
    [OP_JNUNDEF] = "OP_JNUNDEF",
    [OP_JNUNDEF_P] = "OP_JNUNDEF_P",
    [OP_JFALSE] = "OP_JFALSE",
    [OP_JFALSE_P] = "OP_JFALSE_P",
    [OP_JTRUE] = "OP_JTRUE",
    [OP_JTRUE_P] = "OP_JTRUE_P",
    [OP_JL_P] = "OP_JL_P",
    [OP_JLE_P] = "OP_JLE_P",
    [OP_ITER_NEXT] = "OP_ITER_NEXT",
    [OP_ITER_START_ARRAY] = "OP_ITER_START_ARRAY",
    [OP_ITER_START_DICT] = "OP_ITER_START_DICT",
    [OP_ITER_START_INT_RANGE] = "OP_ITER_START_INT_RANGE",
    [OP_ITER_START_INT_ENUM] = "OP_ITER_START_INT_ENUM",
    [OP_ITER_START_STRING_SET] = "OP_ITER_START_STRING_SET",
    [OP_ITER_CONDITION] = "OP_ITER_CONDITION",
    [OP_ITER_END] = "OP_ITER_END",
    [OP_JZ] = "OP_JZ",
    [OP_JZ_P] = "OP_JZ_P",
    [OP_PUSH_8] = "OP_PUSH_8",
    [OP_PUSH_16] = "OP_PUSH_16",
    [OP_PUSH_32] = "OP_PUSH_32",
    [OP_PUSH_U] = "OP_PUSH_U",
    [OP_CONTAINS] = "OP_CONTAINS",
    [OP_STARTSWITH] = "OP_STARTSWITH",
    [OP_ENDSWITH] = "OP_ENDSWITH",
    [OP_ICONTAINS] = "OP_ICONTAINS",
    [OP_ISTARTSWITH] = "OP_ISTARTSWITH",
    [OP_IENDSWITH] = "OP_IENDSWITH",
    [OP_IEQUALS] = "OP_IEQUALS",
    [OP_OF_PERCENT] = "OP_OF_PERCENT",
    [OP_OF_FOUND_IN] = "OP_OF_FOUND_IN",
    [OP_COUNT_IN] = "OP_COUNT_IN",
    [OP_DEFINED] = "OP_DEFINED",
    [OP_ITER_START_TEXT_STRING_SET] = "OP_ITER_START_TEXT_STRING_SET",
    [OP_OF_FOUND_AT] = "OP_OF_FOUND_AT",

    [OP_INT_EQ] = "OP_INT_EQ",
    [OP_INT_NEQ] = "OP_INT_NEQ",
    [OP_INT_LT] = "OP_INT_LT",
    [OP_INT_GT] = "OP_INT_GT",
    [OP_INT_LE] = "OP_INT_LE",
    [OP_INT_GE] = "OP_INT_GE",
    [OP_INT_ADD] = "OP_INT_ADD",
    [OP_INT_SUB] = "OP_INT_SUB",
    [OP_INT_MUL] = "OP_INT_MUL",
    [OP_INT_DIV] = "OP_INT_DIV",
    [OP_INT_MINUS] = "OP_INT_MINUS",
    
    [OP_DBL_EQ] = "OP_DBL_EQ",
    [OP_DBL_NEQ] = "OP_DBL_NEQ",
    [OP_DBL_LT] = "OP_DBL_LT",
    [OP_DBL_GT] = "OP_DBL_GT",
    [OP_DBL_LE] = "OP_DBL_LE",
    [OP_DBL_GE] = "OP_DBL_GE",
    [OP_DBL_ADD] = "OP_DBL_ADD",
    [OP_DBL_SUB] = "OP_DBL_SUB",
    [OP_DBL_MUL] = "OP_DBL_MUL",
    [OP_DBL_DIV] = "OP_DBL_DIV",
    [OP_DBL_MINUS] = "OP_DBL_MINUS",

    [OP_STR_EQ] = "OP_STR_EQ",
    [OP_STR_NEQ] = "OP_STR_NEQ",
    [OP_STR_LT] = "OP_STR_LT",
    [OP_STR_GT] = "OP_STR_GT",
    [OP_STR_LE] = "OP_STR_LE",
    [OP_STR_GE] = "OP_STR_GE",

    [OP_INT8] = "OP_INT8",
    [OP_INT16] = "OP_INT16",
    [OP_INT32] = "OP_INT32",
    [OP_UINT8] = "OP_UINT8",
    [OP_UINT16] = "OP_UINT16",
    [OP_UINT32] = "OP_UINT32",
    [OP_INT8BE] = "OP_INT8BE",
    [OP_INT16BE] = "OP_INT16BE",
    [OP_INT32BE] = "OP_INT32BE",
    [OP_UINT8BE] = "OP_UINT8BE",
    [OP_UINT16BE] = "OP_UINT16BE",
    [OP_UINT32BE] = "OP_UINT32BE",
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
        case OP_PUSH_RULE:
        case OP_MATCH_RULE:
        case OP_CALL:
        case OP_OBJ_LOAD:
        case OP_OBJ_FIELD:
        case OP_OF:
        case OP_OF_PERCENT:
            return 1 + 8;
        
        case OP_PUSH_8:
            return 1 + 1;
        
        case OP_PUSH_16:
            return 1 + 2;

        case OP_PUSH_32:
            return 1 + 4;

        case OP_JFALSE:
        case OP_JTRUE:
        case OP_JUNDEF:
        case OP_JNUNDEF:
        case OP_JZ:
        case OP_JFALSE_P:
        case OP_JTRUE_P:
        case OP_JUNDEF_P:
        case OP_JNUNDEF_P:
        case OP_JZ_P:
        case OP_JL_P:
        case OP_JLE_P:
            return 1 + 4;

        case OP_INIT_RULE:
            return 1 + 4 + 4; // jump offset + rule index

        default:
            return 1;
    }
}


void print_instruction(const uint8_t* ip)
{
    if (opcode_names[*ip] == NULL)
    {
        printf("Unknown opcode: %d", *ip);
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
        case OP_PUSH_RULE:
        case OP_MATCH_RULE:
        case OP_CALL:
        case OP_OBJ_LOAD:
        case OP_OBJ_FIELD:
        {
            uint32_t buffer_id = *(uint32_t*)(ip + 1);
            uint32_t offset = *(uint32_t*)(ip + 5);
            char* symbol = find_symbol(buffer_id, offset);
            if (symbol)
            {
                printf(" %s", symbol);
            }
            else
            {
                printf(" %lld (0x%llx)", *(long long*)(ip + 1), *(long long*)(ip + 1));
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

        case OP_JFALSE:
        case OP_JTRUE:
        case OP_JUNDEF:
        case OP_JNUNDEF:
        case OP_JZ:
        case OP_JFALSE_P:
        case OP_JTRUE_P:
        case OP_JUNDEF_P:
        case OP_JNUNDEF_P:
        case OP_JZ_P:
        case OP_JL_P:
        case OP_JLE_P:
            printf(" %d", *(int*)(ip + 1));
            break;

        case OP_INIT_RULE:
            printf(" jmp:%d idx:%d", *(int*)(ip + 1), *(uint32_t*)(ip + 5));
            break;

        case OP_OF:
        case OP_OF_PERCENT:
            printf(" type:%d", *(uint8_t*)(ip + 1));
            break;
    }
}

void disassemble(const uint8_t* code_start, int rule_idx)
{
    const uint8_t* ip = code_start;
    
    // Find the start of the code for this rule
    while(1)
    {
        if (*ip == OP_INIT_RULE)
        {
            uint32_t current_rule_idx = *(uint32_t*)(ip + 5);
            if (current_rule_idx == rule_idx)
            {
                break;
            }
        }
        
        ip += get_instr_len(ip);

        if (ip > code_start + 65536)
        {
             printf("    // Could not find code for rule\n");
             return;
        }
    }

    const uint8_t* rule_start = ip;
    int32_t jmp_offset = *(int32_t*)(ip + 1);
    const uint8_t* rule_end = rule_start + jmp_offset;

    while(ip < rule_end && *ip != OP_HALT)
    {
        printf("    ");
        print_instruction(ip);
        printf("\n");
        ip += get_instr_len(ip);
    }

    if (*ip == OP_HALT)
    {
        printf("    OP_HALT\n");
    }
}