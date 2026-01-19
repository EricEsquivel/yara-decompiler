#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "decompiler.h"
#include "../libyara/include/yara/exec.h"
#include "../libyara/include/yara/compiler.h"

typedef struct {
    char** items;
    int top;
    int capacity;
} STACK;

static void stack_init(STACK* s)
{
    s->capacity = 1024;
    s->items = malloc(s->capacity * sizeof(char*));
    s->top = 0;
}

static void stack_push(STACK* s, const char* val)
{
    if (val == NULL) return;
    if (s->top >= s->capacity) {
        s->capacity *= 2;
        s->items = realloc(s->items, s->capacity * sizeof(char*));
    }
    s->items[s->top++] = strdup(val);
}

static char* stack_pop(STACK* s)
{
    if (s->top <= 0) return strdup("");
    char* val = s->items[--s->top];
    return val;
}

static char* stack_peek(STACK* s)
{
    if (s->top <= 0) return strdup("");
    return strdup(s->items[s->top-1]);
}

extern int get_instr_len(const uint8_t* ip);

static int is_pool_literal(const char* symbol)
{
    if (symbol == NULL || symbol[0] == '\0') return 0;
    if (symbol[0] == '$') return 0;
    
    const char* modules[] = {"pe", "elf", "math", "dotnet", "hash", "magic", "cuckoo", "console", "time", "dex", "macho", "all", "any", "them"};
    for (int i = 0; i < (int)(sizeof(modules)/sizeof(modules[0])); i++)
    {
        if (strcmp(symbol, modules[i]) == 0) return 0;
    }
    
    // Loop variables i, j, k etc.
    if (strlen(symbol) == 1 && symbol[0] >= 'a' && symbol[0] <= 'z') return 0;

    char* endptr;
    strtol(symbol, &endptr, 10);
    if (*endptr == '\0') return 0;

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

    STACK s;
    stack_init(&s);

    char* mem_slots[1024];
    for(int i=0; i<1024; i++) mem_slots[i] = NULL;

    char buf[16384];
    char* current_range[16];
    char* current_loop_cond[16];
    int loop_is_string_set[16];  // 0 = int range, 1 = string set
    for(int i=0; i<16; i++) { current_range[i] = NULL; current_loop_cond[i] = NULL; loop_is_string_set[i] = 0; }

    int loop_depth = 0;

    const uint8_t* curr_ip = rule_start + get_instr_len(rule_start);
    while(curr_ip < rule_end && *curr_ip != OP_HALT && *curr_ip != OP_MATCH_RULE)
    {
        uint8_t opcode = *curr_ip;
        int len = get_instr_len(curr_ip);

        switch(opcode)
        {
            case OP_PUSH:
            {
                uintptr_t addr = *(uintptr_t*)(curr_ip + 1);
                if (addr == 0xFFFABADAFABADAFFLL) stack_push(&s, "SENTINEL_U");
                else
                {
                    char* symbol = find_symbol(addr);
                    if (symbol && strlen(symbol) > 0)
                    {
                        if (is_pool_literal(symbol))
                        {
                             snprintf(buf, sizeof(buf), "\"%s\"", symbol);
                             stack_push(&s, buf);
                        }
                        else stack_push(&s, symbol);
                    }
                    else
                    {
                        double dval = *(double*)(curr_ip + 1);
                        if (isnan(dval) == 0 && isinf(dval) == 0 && dval != 0.0 && (dval > 1e-10 || dval < -1e-10))
                             snprintf(buf, sizeof(buf), "%g", dval);
                        else
                        {
                            long long val = *(long long*)(curr_ip + 1);
                            if (val > 0xFFFF || val < -0xFFFF) snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)val);
                            else snprintf(buf, sizeof(buf), "%lld", val);
                        }
                        stack_push(&s, buf);
                    }
                }
                break;
            }
            case OP_PUSH_U:
                stack_push(&s, "SENTINEL_U");
                break;
            case OP_PUSH_RULE:
            {
                // PUSH_RULE pushes the result of another rule (1 if matched, 0 if not)
                // For decompilation, we output the rule name as a reference
                uint64_t rule_idx = *(uint64_t*)(curr_ip + 1);
                char* rule_name = get_rule_name((int)rule_idx);
                if (rule_name) {
                    stack_push(&s, rule_name);
                } else {
                    snprintf(buf, sizeof(buf), "rule_%llu", (unsigned long long)rule_idx);
                    stack_push(&s, buf);
                }
                break;
            }
            case OP_PUSH_8:
                snprintf(buf, sizeof(buf), "%d", *(uint8_t*)(curr_ip + 1));
                stack_push(&s, buf);
                break;
            case OP_PUSH_16:
                snprintf(buf, sizeof(buf), "%d", *(uint16_t*)(curr_ip + 1));
                stack_push(&s, buf);
                break;
            case OP_PUSH_32:
            {
                unsigned int val = *(unsigned int*)(curr_ip + 1);
                if (val > 0xFFFF) snprintf(buf, sizeof(buf), "0x%x", val);
                else snprintf(buf, sizeof(buf), "%u", val);
                stack_push(&s, buf);
                break;
            }
            case OP_POP:
                free(stack_pop(&s));
                break;
            case OP_AND:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                // Suppress internal placeholders
                int v1_internal = (strcmp(v1, "SENTINEL_U") == 0 || strcmp(v1, "1") == 0 ||
                                   strcmp(v1, "num_true") == 0 || strcmp(v1, "ITER_INT_RANGE") == 0 ||
                                   strcmp(v1, "ITER_STRING_SET") == 0 || strcmp(v1, "ITER_HAS_MORE") == 0);
                int v2_internal = (strcmp(v2, "SENTINEL_U") == 0 || strcmp(v2, "1") == 0 ||
                                   strcmp(v2, "num_true") == 0 || strcmp(v2, "ITER_INT_RANGE") == 0 ||
                                   strcmp(v2, "ITER_STRING_SET") == 0 || strcmp(v2, "ITER_HAS_MORE") == 0);
                if (v1_internal) stack_push(&s, v2);
                else if (v2_internal) stack_push(&s, v1);
                else {
                    snprintf(buf, sizeof(buf), "(%s and %s)", v1, v2);
                    stack_push(&s, buf);
                }
                free(v1); free(v2);
                break;
            }
            case OP_OR:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                // Suppress internal placeholders
                int v1_internal = (strcmp(v1, "SENTINEL_U") == 0 || strcmp(v1, "0") == 0 ||
                                   strcmp(v1, "ITER_INT_RANGE") == 0 || strcmp(v1, "ITER_STRING_SET") == 0 ||
                                   strcmp(v1, "ITER_HAS_MORE") == 0);
                int v2_internal = (strcmp(v2, "SENTINEL_U") == 0 || strcmp(v2, "0") == 0 ||
                                   strcmp(v2, "ITER_INT_RANGE") == 0 || strcmp(v2, "ITER_STRING_SET") == 0 ||
                                   strcmp(v2, "ITER_HAS_MORE") == 0);
                if (v1_internal) stack_push(&s, v2);
                else if (v2_internal) stack_push(&s, v1);
                else {
                    snprintf(buf, sizeof(buf), "(%s or %s)", v1, v2);
                    stack_push(&s, buf);
                }
                free(v1); free(v2);
                break;
            }
            case OP_NOT:
            {
                char* v1 = stack_pop(&s);
                if (strcmp(v1, "SENTINEL_U") != 0 && strcmp(v1, "num_true") != 0 && strlen(v1) > 0) {
                    snprintf(buf, sizeof(buf), "not %s", v1);
                    stack_push(&s, buf);
                }
                free(v1);
                break;
            }
            case OP_DEFINED:
            {
                char* v1 = stack_pop(&s);
                if (strcmp(v1, "SENTINEL_U") != 0 && strlen(v1) > 0) {
                    snprintf(buf, sizeof(buf), "defined %s", v1);
                    stack_push(&s, buf);
                }
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
                snprintf(buf, sizeof(buf), "(%s %s %s)", v1, op, v2);
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
                snprintf(buf, sizeof(buf), "(%s %s %s)", v1, op, v2);
                stack_push(&s, buf);
                free(v1); free(v2);
                break;
            }
            case OP_OBJ_LOAD:
            {
                uintptr_t addr = *(uintptr_t*)(curr_ip + 1);
                char* symbol = find_symbol(addr);
                if (symbol) stack_push(&s, symbol);
                else stack_push(&s, "UNKNOWN_OBJ");
                break;
            }
            case OP_OBJ_VALUE:
                break;
            case OP_OBJ_FIELD:
            {
                uintptr_t addr = *(uintptr_t*)(curr_ip + 1);
                char* field_name = find_symbol(addr);
                char* obj = stack_pop(&s);
                if (strcmp(obj, "SENTINEL_U") == 0) stack_push(&s, field_name ? field_name : "UNKNOWN_FIELD");
                else {
                    snprintf(buf, sizeof(buf), "%s.%s", obj, field_name ? field_name : "UNKNOWN_FIELD");
                    stack_push(&s, buf);
                }
                free(obj);
                break;
            }
            case OP_INDEX_ARRAY:
            {
                char* index = stack_pop(&s);
                char* obj = stack_pop(&s);
                snprintf(buf, sizeof(buf), "%s[%s]", obj, index);
                stack_push(&s, buf);
                free(index); free(obj);
                break;
            }
            case OP_CALL:
            {
                uintptr_t addr = *(uintptr_t*)(curr_ip + 1);
                char* args_fmt = find_symbol(addr);
                int num_args = args_fmt ? (int)strlen(args_fmt) : 0;
                char* args[10];
                for(int i=0; i<num_args; i++) args[i] = stack_pop(&s);
                char* func = stack_pop(&s);
                snprintf(buf, sizeof(buf), "%s(", func);
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
                snprintf(buf, sizeof(buf), "(%s contains %s)", v1, v2);
                stack_push(&s, buf);
                free(v1); free(v2);
                break;
            }
            case OP_COUNT:
            {
                char* val = stack_pop(&s);
                if (val[0] == '$') snprintf(buf, sizeof(buf), "#%s", val+1);
                else snprintf(buf, sizeof(buf), "#%s", val);
                stack_push(&s, buf);
                free(val);
                break;
            }
            case OP_LENGTH:
            {
                char* val = stack_pop(&s);
                if (val[0] == '$') snprintf(buf, sizeof(buf), "!%s", val+1);
                else snprintf(buf, sizeof(buf), "!%s", val);
                stack_push(&s, buf);
                free(val);
                break;
            }
            case OP_OFFSET:
            {
                char* str = stack_pop(&s);
                char* idx = stack_pop(&s);
                // Check if this is a bare @ in a for..of loop (string is "#" placeholder)
                if (strcmp(str, "#") == 0) {
                    // In "for any of ($a,$b) : (@ > 100)", @ refers to current string
                    snprintf(buf, sizeof(buf), "@");
                }
                else if (str[0] == '$') snprintf(buf, sizeof(buf), "@%s[%s]", str+1, idx);
                else snprintf(buf, sizeof(buf), "@%s[%s]", str, idx);
                stack_push(&s, buf);
                free(str); free(idx);
                break;
            }
            case OP_FILESIZE:
                stack_push(&s, "filesize");
                break;
            case OP_ENTRYPOINT:
                stack_push(&s, "entrypoint");
                break;
            case OP_FOUND_AT:
            {
                char* str = stack_pop(&s); 
                char* off = stack_pop(&s); 
                snprintf(buf, sizeof(buf), "%s at %s", str, off);
                stack_push(&s, buf);
                free(str); free(off);
                break;
            }
            case OP_FOUND_IN:
            {
                char* str = stack_pop(&s);   
                char* end = stack_pop(&s);   
                char* start = stack_pop(&s); 
                snprintf(buf, sizeof(buf), "%s in (%s..%s)", str, start, end);
                stack_push(&s, buf);
                free(str); free(end); free(start);
                break;
            }
            case OP_UINT32:
            {
                char* off = stack_pop(&s);
                snprintf(buf, sizeof(buf), "uint32(%s)", off);
                stack_push(&s, buf);
                free(off);
                break;
            }
            case OP_OF:
            case OP_OF_FOUND_IN:
            case OP_OF_PERCENT:
            {
                char* range_end = NULL;
                char* range_start = NULL;
                if (opcode == OP_OF_FOUND_IN) {
                    range_end = stack_pop(&s);
                    range_start = stack_pop(&s);
                }

                char* set_items[128];
                int set_count = 0;
                char* item = stack_pop(&s);
                while(strcmp(item, "SENTINEL_U") != 0 && set_count < 128 && strlen(item) > 0)
                {
                    set_items[set_count++] = item;
                    item = stack_pop(&s);
                }
                free(item);
                char* quantifier = stack_pop(&s);
                if (strcmp(quantifier, "SENTINEL_U") == 0) { free(quantifier); quantifier = strdup("all"); }
                // Handle "none of" - quantifier of 0 means none
                else if (strcmp(quantifier, "0") == 0) { free(quantifier); quantifier = strdup("none"); }

                // Format quantifier with % for percentage-based matching
                char quant_buf[64];
                if (opcode == OP_OF_PERCENT) {
                    snprintf(quant_buf, sizeof(quant_buf), "%s%%", quantifier);
                } else {
                    snprintf(quant_buf, sizeof(quant_buf), "%s", quantifier);
                }

                if (set_count == 0) {
                    snprintf(buf, sizeof(buf), "%s of them", quant_buf);
                } else {
                    snprintf(buf, sizeof(buf), "%s of (", quant_buf);
                    for(int i=set_count-1; i>=0; i--)
                    {
                        strcat(buf, set_items[i]);
                        if (i > 0) strcat(buf, ", ");
                        free(set_items[i]);
                    }
                    strcat(buf, ")");
                }

                if (opcode == OP_OF_FOUND_IN) {
                    char temp[16384];
                    snprintf(temp, sizeof(temp), "%s in (%s..%s)", buf, range_start, range_end);
                    strcpy(buf, temp);
                    free(range_start); free(range_end);
                }

                stack_push(&s, buf);
                free(quantifier);
                break;
            }
            case OP_PUSH_M:
            {
                uintptr_t addr = *(uintptr_t*)(curr_ip + 1);
                if (addr % 4 == 0) stack_push(&s, "num_true");
                else if (addr % 4 == 3) {
                    // Check if we have a stored value first (for string set iterations)
                    if (addr < 1024 && mem_slots[addr] && strcmp(mem_slots[addr], "#") == 0) {
                        stack_push(&s, mem_slots[addr]);
                    } else {
                        // Integer range loop variable
                        snprintf(buf, sizeof(buf), "%c", 'i' + (int)(addr/4));
                        stack_push(&s, buf);
                    }
                }
                else if (addr < 1024 && mem_slots[addr]) stack_push(&s, mem_slots[addr]);
                else {
                    snprintf(buf, sizeof(buf), "M%lu", (unsigned long)addr);
                    stack_push(&s, buf);
                }
                break;
            }
            case OP_POP_M:
            {
                uintptr_t addr = *(uintptr_t*)(curr_ip + 1);
                char* val = stack_pop(&s);
                if (addr < 1024) {
                    if (mem_slots[addr]) free(mem_slots[addr]);
                    mem_slots[addr] = strdup(val);
                }
                free(val);
                break;
            }
            case OP_ITER_START_INT_RANGE:
            {
                char* end = stack_pop(&s);
                char* start = stack_pop(&s);
                snprintf(buf, sizeof(buf), "(%s..%s)", start, end);
                if (current_range[loop_depth]) free(current_range[loop_depth]);
                current_range[loop_depth] = strdup(buf);
                loop_is_string_set[loop_depth] = 0;  // Integer range loop
                // Push iterator placeholder - will be consumed by POP after loop completes
                stack_push(&s, "ITER_INT_RANGE");
                free(start); free(end);
                loop_depth++;
                break;
            }
            case OP_ITER_START_STRING_SET:
            case OP_ITER_START_TEXT_STRING_SET:
            {
                // Pop count from stack
                char* count_str = stack_pop(&s);
                int count = atoi(count_str);
                free(count_str);

                // Pop string references
                char* set_items[128];
                int set_count = 0;
                for (int i = 0; i < count && i < 128; i++) {
                    set_items[set_count++] = stack_pop(&s);
                }

                // Pop sentinel
                char* sentinel = stack_pop(&s);
                free(sentinel);

                // Build string set representation
                snprintf(buf, sizeof(buf), "(");
                for (int i = set_count - 1; i >= 0; i--) {
                    strcat(buf, set_items[i]);
                    if (i > 0) strcat(buf, ", ");
                    free(set_items[i]);
                }
                strcat(buf, ")");

                if (current_range[loop_depth]) free(current_range[loop_depth]);
                current_range[loop_depth] = strdup(buf);
                loop_is_string_set[loop_depth] = 1;  // String set loop

                // Push iterator placeholder
                stack_push(&s, "ITER_STRING_SET");
                loop_depth++;
                break;
            }
            case OP_ITER_NEXT:
            {
                // Pop iterator, push it back, then push has_more, then current item
                // Stack order: [iter, has_more, current_item]
                // After this: POP_M stores current_item, JTRUE_P checks has_more
                char* iter = stack_pop(&s);
                // Push iterator back (stack_push makes a copy)
                stack_push(&s, iter);
                free(iter);  // Free the original after pushing a copy
                // Push has_more flag (will be consumed by JTRUE_P after POP_M)
                stack_push(&s, "ITER_HAS_MORE");
                // For string set iterations, push "#" placeholder
                // For integer range iterations, push the loop variable name
                if (loop_depth > 0 && loop_is_string_set[loop_depth - 1]) {
                    stack_push(&s, "#");  // Current string in iteration
                } else {
                    // Integer range loop - push variable name
                    char var_name = 'i' + (loop_depth > 0 ? loop_depth - 1 : 0);
                    snprintf(buf, sizeof(buf), "%c", var_name);
                    stack_push(&s, buf);
                }
                break;
            }
            case OP_ITER_CONDITION:
            {
                char* _quant = stack_pop(&s);
                char* _num_true = stack_pop(&s);
                char* _cond = stack_pop(&s);
                if (current_loop_cond[loop_depth-1]) free(current_loop_cond[loop_depth-1]);
                current_loop_cond[loop_depth-1] = strdup(_cond);
                stack_push(&s, _quant);
                stack_push(&s, _num_true);
                stack_push(&s, _cond);
                free(_quant); free(_num_true); free(_cond);
                break;
            }
            case OP_ITER_END:
            {
                char* _cond = stack_pop(&s);
                char* _num_true = stack_pop(&s);
                char* _total_iters = stack_pop(&s);
                const char* q = (strcmp(_cond, "SENTINEL_U") == 0) ? "all" : _cond;
                if (strcmp(q, "1") == 0) q = "any";

                if (loop_is_string_set[loop_depth - 1]) {
                    // String set loop: "for any of ($a, $b) : ( condition )"
                    snprintf(buf, sizeof(buf), "for %s of %s : ( %s )",
                             q,
                             current_range[loop_depth-1] ? current_range[loop_depth-1] : "them",
                             current_loop_cond[loop_depth-1] ? current_loop_cond[loop_depth-1] : "true");
                } else {
                    // Integer range loop: "for any i in (0..10) : ( condition )"
                    char var_name = 'i' + loop_depth - 1;
                    snprintf(buf, sizeof(buf), "for %s %c in %s : ( %s )",
                             q, var_name,
                             current_range[loop_depth-1] ? current_range[loop_depth-1] : "RANGE",
                             current_loop_cond[loop_depth-1] ? current_loop_cond[loop_depth-1] : "CONDITION");
                }
                stack_push(&s, buf);
                free(_cond); free(_num_true); free(_total_iters);
                loop_depth--;
                break;
            }
            case OP_JFALSE:
            case OP_JTRUE:
                break;
            case OP_JFALSE_P:
            case OP_JTRUE_P:
                free(stack_pop(&s));
                break;
            default:
                break;
        }
        curr_ip += len;
    }

    // Final consolidation with sub-expression suppression
    // Helper to check if a value is an internal placeholder that should be suppressed
    #define IS_INTERNAL(v) (strlen(v) == 0 || strcmp(v, "SENTINEL_U") == 0 || strcmp(v, "num_true") == 0 || strcmp(v, "1") == 0 || strcmp(v, "0") == 0 || strcmp(v, "ITER_STRING_SET") == 0 || strcmp(v, "ITER_HAS_MORE") == 0 || strcmp(v, "ITER_INT_RANGE") == 0)

    while (s.top > 1)
    {
        char* v2 = stack_pop(&s);
        char* v1 = stack_pop(&s);

        if (IS_INTERNAL(v1)) {
            stack_push(&s, v2);
        } else if (IS_INTERNAL(v2)) {
            stack_push(&s, v1);
        } else if (strstr(v1, v2) != NULL) {
            stack_push(&s, v1);
        } else if (strstr(v2, v1) != NULL) {
            stack_push(&s, v2);
        } else {
            snprintf(buf, sizeof(buf), "(%s and %s)", v1, v2);
            stack_push(&s, buf);
        }
        free(v1); free(v2);
    }

    if (s.top > 0)
    {
        char* res = stack_pop(&s);
        if (strcmp(res, "1") == 0) {
            printf("    true\n");
        } else if (strcmp(res, "0") == 0) {
            printf("    false\n");
        } else if (strlen(res) > 0 && strcmp(res, "SENTINEL_U") != 0 && strcmp(res, "num_true") != 0) {
            printf("    %s\n", res);
        } else {
            // Empty condition - output true as fallback
            printf("    true\n");
        }
        free(res);
    }
    else
    {
        // No condition on stack - output true as fallback
        printf("    true\n");
    }
    
    while(s.top > 0) free(stack_pop(&s));
    free(s.items);
    for(int i=0; i<1024; i++) if (mem_slots[i]) free(mem_slots[i]);
    for(int i=0; i<16; i++) { if (current_range[i]) free(current_range[i]); if (current_loop_cond[i]) free(current_loop_cond[i]); }
}
