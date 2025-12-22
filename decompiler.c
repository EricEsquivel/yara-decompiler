#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "decompiler.h"
#include "../libyara/include/yara/exec.h"
#include "../libyara/include/yara/compiler.h"

typedef struct {
    char* items[1024];
    int top;
} STACK;

void stack_push(STACK* s, const char* val)
{
    if (s->top >= 1024) return;
    s->items[s->top++] = strdup(val);
}

char* stack_pop(STACK* s)
{
    if (s->top <= 0) return strdup("UNDEFINED");
    return s->items[--s->top];
}

extern int get_instr_len(const uint8_t* ip);

int is_pool_literal(const char* symbol)
{
    if (symbol == NULL) return 0;
    if (symbol[0] == '$') return 0;
    if (strcmp(symbol, "all") == 0 || strcmp(symbol, "any") == 0) return 0;
    const char* modules[] = {"pe", "elf", "math", "dotnet", "hash", "magic", "cuckoo", "console", "time", "dex", "macho"};
    for (int i = 0; i < (int)(sizeof(modules)/sizeof(modules[0])); i++)
    {
        if (strcmp(symbol, modules[i]) == 0) return 0;
    }
    return 1;
}

void decompile_rule_condition(const uint8_t* code_start, int rule_idx)
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

    ip += get_instr_len(ip); 

    STACK s;
    s.top = 0;

    char* mem_slots[1024];
    for(int i=0; i<1024; i++) mem_slots[i] = NULL;

    char* current_range = NULL;
    char* current_loop_cond = NULL;
    char buf[4096];

    while(ip < rule_end && *ip != OP_HALT && *ip != OP_MATCH_RULE)
    {
        uint8_t opcode = *ip;
        int len = get_instr_len(ip);

        switch(opcode)
        {
            case OP_PUSH:
            {
                uintptr_t addr = *(uintptr_t*)(ip + 1);
                if (addr == 0xFFFABADAFABADAFFLL) stack_push(&s, "all");
                else
                {
                    char* symbol = find_symbol(addr);
                    if (symbol)
                    {
                        if (is_pool_literal(symbol))
                        {
                             sprintf(buf, "\"%s\"", symbol);
                             stack_push(&s, buf);
                        }
                        else stack_push(&s, symbol);
                    }
                    else
                    {
                        double dval = *(double*)(ip + 1);
                        if (isnan(dval) == 0 && isinf(dval) == 0 && dval != 0.0 && (dval > 1e-10 || dval < -1e-10))
                             sprintf(buf, "%g", dval);
                        else
                        {
                            long long val = *(long long*)(ip + 1);
                            if (val > 0xFFFF) sprintf(buf, "0x%llx", (unsigned long long)val);
                            else sprintf(buf, "%lld", val);
                        }
                        stack_push(&s, buf);
                    }
                }
                break;
            }
            case OP_PUSH_U:
                stack_push(&s, "all");
                break;
            case OP_PUSH_8:
                sprintf(buf, "%d", *(uint8_t*)(ip + 1));
                stack_push(&s, buf);
                break;
            case OP_PUSH_16:
                sprintf(buf, "%d", *(uint16_t*)(ip + 1));
                stack_push(&s, buf);
                break;
            case OP_PUSH_32:
            {
                unsigned int val = *(unsigned int*)(ip + 1);
                if (val > 0xFFFF) sprintf(buf, "0x%x", val);
                else sprintf(buf, "%u", val);
                stack_push(&s, buf);
                break;
            }
            case OP_POP:
                free(stack_pop(&s));
                break;
            case OP_FOUND:
                break;
            case OP_AND:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s and %s)", v1, v2);
                stack_push(&s, buf);
                free(v1); free(v2);
                break;
            }
            case OP_OR:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s or %s)", v1, v2);
                stack_push(&s, buf);
                free(v1); free(v2);
                break;
            }
            case OP_NOT:
            {
                char* v1 = stack_pop(&s);
                sprintf(buf, "not %s", v1);
                stack_push(&s, buf);
                free(v1);
                break;
            }
            case OP_BITWISE_NOT:
            {
                char* v1 = stack_pop(&s);
                sprintf(buf, "~%s", v1);
                stack_push(&s, buf);
                free(v1);
                break;
            }
            case OP_BITWISE_AND:
            case OP_BITWISE_OR:
            case OP_BITWISE_XOR:
            case OP_SHL:
            case OP_SHR:
            case OP_MOD:
            case OP_INT_ADD:
            case OP_DBL_ADD:
            case OP_INT_SUB:
            case OP_DBL_SUB:
            case OP_INT_MUL:
            case OP_DBL_MUL:
            case OP_INT_DIV:
            case OP_DBL_DIV:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                const char* op = opcode == OP_BITWISE_AND ? "&" :
                                 opcode == OP_BITWISE_OR ? "|" :
                                 opcode == OP_BITWISE_XOR ? "^" :
                                 opcode == OP_SHL ? "<<" :
                                 opcode == OP_SHR ? ">>" :
                                 opcode == OP_MOD ? "%" :
                                 opcode == OP_INT_ADD || opcode == OP_DBL_ADD ? "+" :
                                 opcode == OP_INT_SUB || opcode == OP_DBL_SUB ? "-" :
                                 opcode == OP_INT_MUL || opcode == OP_DBL_MUL ? "*" : "/";
                sprintf(buf, "(%s %s %s)", v1, op, v2);
                stack_push(&s, buf);
                free(v1); free(v2);
                break;
            }
            case OP_INT_EQ:
            case OP_DBL_EQ:
            case OP_STR_EQ:
            case OP_IEQUALS:
            case OP_INT_NEQ:
            case OP_DBL_NEQ:
            case OP_STR_NEQ:
            case OP_INT_LT:
            case OP_DBL_LT:
            case OP_STR_LT:
            case OP_INT_GT:
            case OP_DBL_GT:
            case OP_STR_GT:
            case OP_INT_LE:
            case OP_DBL_LE:
            case OP_STR_LE:
            case OP_INT_GE:
            case OP_DBL_GE:
            case OP_STR_GE:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                const char* op = (opcode == OP_INT_EQ || opcode == OP_DBL_EQ || opcode == OP_STR_EQ || opcode == OP_IEQUALS) ? "==" :
                                 (opcode == OP_INT_NEQ || opcode == OP_DBL_NEQ || opcode == OP_STR_NEQ) ? "!=" :
                                 (opcode == OP_INT_LT || opcode == OP_DBL_LT || opcode == OP_STR_LT) ? "<" :
                                 (opcode == OP_INT_GT || opcode == OP_DBL_GT || opcode == OP_STR_GT) ? ">" :
                                 (opcode == OP_INT_LE || opcode == OP_DBL_LE || opcode == OP_STR_LE) ? "<=" : ">=";
                sprintf(buf, "(%s %s %s)", v1, op, v2);
                stack_push(&s, buf);
                free(v1); free(v2);
                break;
            }
            case OP_OBJ_LOAD:
            {
                uintptr_t addr = *(uintptr_t*)(ip + 1);
                char* symbol = find_symbol(addr);
                if (symbol) stack_push(&s, symbol);
                else stack_push(&s, "UNKNOWN_OBJ");
                break;
            }
            case OP_OBJ_FIELD:
            {
                uintptr_t addr = *(uintptr_t*)(ip + 1);
                char* field_name = find_symbol(addr);
                char* obj = stack_pop(&s);
                sprintf(buf, "%s.%s", obj, field_name ? field_name : "UNKNOWN_FIELD");
                stack_push(&s, buf);
                free(obj);
                break;
            }
            case OP_CALL:
            {
                uintptr_t addr = *(uintptr_t*)(ip + 1);
                char* args_fmt = find_symbol(addr);
                int num_args = args_fmt ? (int)strlen(args_fmt) : 0;
                char* args[10];
                for(int i=0; i<num_args; i++) args[i] = stack_pop(&s);
                char* func = stack_pop(&s);
                sprintf(buf, "%s(", func);
                for(int i=num_args-1; i>=0; i--) {
                    strcat(buf, args[i]);
                    if (i > 0) strcat(buf, ", ");
                    free(args[i]);
                }
                strcat(buf, ")");
                stack_push(&s, buf);
                free(func);
                break;
            }
            case OP_CONTAINS:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s contains %s)", v1, v2);
                stack_push(&s, buf);
                free(v1); free(v2);
                break;
            }
            case OP_COUNT:
            {
                char* val = stack_pop(&s);
                if (val[0] == '$') sprintf(buf, "#%s", val+1);
                else sprintf(buf, "#%s", val);
                stack_push(&s, buf);
                free(val);
                break;
            }
            case OP_LENGTH:
            {
                char* val = stack_pop(&s);
                if (val[0] == '$') sprintf(buf, "!%s", val+1);
                else sprintf(buf, "!%s", val);
                stack_push(&s, buf);
                free(val);
                break;
            }
            case OP_OFFSET:
            {
                char* str = stack_pop(&s); 
                char* idx = stack_pop(&s); 
                if (str[0] == '$') sprintf(buf, "@%s[%s]", str+1, idx);
                else sprintf(buf, "@%s[%s]", str, idx);
                stack_push(&s, buf);
                free(str); free(idx);
                break;
            }
            case OP_FILESIZE:
                stack_push(&s, "filesize");
                break;
            case OP_FOUND_AT:
            {
                char* str = stack_pop(&s); 
                char* off = stack_pop(&s); 
                sprintf(buf, "%s at %s", str, off);
                stack_push(&s, buf);
                free(str); free(off);
                break;
            }
            case OP_FOUND_IN:
            {
                char* str = stack_pop(&s);   
                char* end = stack_pop(&s);   
                char* start = stack_pop(&s); 
                sprintf(buf, "%s in (%s..%s)", str, start, end);
                stack_push(&s, buf);
                free(str); free(end); free(start);
                break;
            }
            case OP_UINT32:
            {
                char* off = stack_pop(&s);
                sprintf(buf, "uint32(%s)", off);
                stack_push(&s, buf);
                free(off);
                break;
            }
            case OP_OF:
            {
                char* set_items[128];
                int set_count = 0;
                char* item = stack_pop(&s);
                while(strcmp(item, "all") != 0 && strcmp(item, "any") != 0 && strcmp(item, "UNDEFINED") != 0 && set_count < 128)
                {
                    set_items[set_count++] = item;
                    item = stack_pop(&s);
                }
                char* quantifier = item;
                sprintf(buf, "%s of (", quantifier);
                for(int i=set_count-1; i>=0; i--)
                {
                    strcat(buf, set_items[i]);
                    if (i > 0) strcat(buf, ", ");
                    free(set_items[i]);
                }
                strcat(buf, ")");
                stack_push(&s, buf);
                free(quantifier);
                break;
            }
            case OP_CLEAR_M:
                break;
            case OP_POP_M:
            {
                uintptr_t addr = *(uintptr_t*)(ip + 1);
                char* val = stack_pop(&s);
                if (addr < 1024) {
                    if (mem_slots[addr]) free(mem_slots[addr]);
                    mem_slots[addr] = strdup(val);
                }
                free(val);
                break;
            }
            case OP_PUSH_M:
            {
                uintptr_t addr = *(uintptr_t*)(ip + 1);
                if (addr < 1024 && mem_slots[addr]) stack_push(&s, mem_slots[addr]);
                else stack_push(&s, "0");
                break;
            }
            case OP_ITER_START_INT_RANGE:
            {
                char* end = stack_pop(&s);
                char* start = stack_pop(&s);
                sprintf(buf, "(%s..%s)", start, end);
                if (current_range) free(current_range);
                current_range = strdup(buf);
                stack_push(&s, buf);
                free(start); free(end);
                break;
            }
            case OP_ITER_NEXT:
                stack_push(&s, "i"); 
                break;
            case OP_ITER_CONDITION:
            {
                char* _quant = stack_pop(&s);
                char* _num_true = stack_pop(&s);
                char* _cond = stack_pop(&s);
                if (current_loop_cond) free(current_loop_cond);
                current_loop_cond = strdup(_cond);
                stack_push(&s, _quant);
                stack_push(&s, _num_true);
                stack_push(&s, _cond);
                free(_quant); free(_num_true); free(_cond);
                break;
            }
            case OP_ITER_END:
            {
                char* quantifier = stack_pop(&s); 
                free(stack_pop(&s)); // num_true
                free(stack_pop(&s)); // total_iters
                sprintf(buf, "for %s i in %s : ( %s )", quantifier, current_range ? current_range : "RANGE", current_loop_cond ? current_loop_cond : "CONDITION");
                stack_push(&s, buf);
                free(quantifier);
                break;
            }
            case OP_MATCH_RULE:
                break;
        }
        ip += len;
    }

    if (s.top > 0)
    {
        char* res = stack_pop(&s);
        printf("    %s\n", res);
        free(res);
    }
    
    while(s.top > 0) free(stack_pop(&s));
    for(int i=0; i<1024; i++) if (mem_slots[i]) free(mem_slots[i]);
    if (current_range) free(current_range);
    if (current_loop_cond) free(current_loop_cond);
}