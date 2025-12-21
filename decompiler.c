#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decompiler.h"
#include "../libyara/include/yara/exec.h"

typedef struct {
    char* items[1024];
    int top;
} STACK;

void stack_push(STACK* s, const char* val)
{
    s->items[s->top++] = strdup(val);
}

char* stack_pop(STACK* s)
{
    if (s->top == 0) return strdup("ERROR_STACK_UNDERFLOW");
    return s->items[--s->top];
}

extern int get_instr_len(const uint8_t* ip);

void decompile_rule_condition(const uint8_t* code_start, int rule_idx)
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
        if (ip > code_start + 65536) return;
    }

    const uint8_t* rule_start = ip;
    int32_t jmp_offset = *(int32_t*)(ip + 1);
    const uint8_t* rule_end = rule_start + jmp_offset;

    ip += get_instr_len(ip); // skip OP_INIT_RULE

    STACK s;
    s.top = 0;

    char buf[2048];

    while(ip < rule_end && *ip != OP_HALT && *ip != OP_MATCH_RULE)
    {
        uint8_t opcode = *ip;
        int len = get_instr_len(ip);

        switch(opcode)
        {
            case OP_PUSH:
            {
                uint32_t buffer_id = *(uint32_t*)(ip + 1);
                uint32_t offset = *(uint32_t*)(ip + 5);
                char* symbol = find_symbol(buffer_id, offset);
                if (symbol)
                {
                    stack_push(&s, symbol);
                }
                else
                {
                    sprintf(buf, "%lld", *(long long*)(ip + 1));
                    stack_push(&s, buf);
                }
                break;
            }
            case OP_PUSH_8:
                sprintf(buf, "%d", *(uint8_t*)(ip + 1));
                stack_push(&s, buf);
                break;
            case OP_PUSH_16:
                sprintf(buf, "%d", *(uint16_t*)(ip + 1));
                stack_push(&s, buf);
                break;
            case OP_PUSH_32:
                sprintf(buf, "%d", *(uint32_t*)(ip + 1));
                stack_push(&s, buf);
                break;
            
            case OP_FOUND:
            {
                char* val = stack_pop(&s);
                stack_push(&s, val); 
                free(val);
                break;
            }

            case OP_AND:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s and %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_OR:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s or %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
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
            case OP_INT_ADD:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s + %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_INT_SUB:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s - %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_INT_MUL:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s * %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_INT_DIV:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s / %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_INT_EQ:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s == %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_INT_NEQ:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s != %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_INT_LT:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s < %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_INT_GT:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s > %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_INT_LE:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s <= %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_INT_GE:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s >= %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_OBJ_LOAD:
            {
                uint32_t buffer_id = *(uint32_t*)(ip + 1);
                uint32_t offset = *(uint32_t*)(ip + 5);
                char* symbol = find_symbol(buffer_id, offset);
                if (symbol)
                    stack_push(&s, symbol);
                else
                    stack_push(&s, "UNKNOWN_OBJ");
                break;
            }
            case OP_OBJ_FIELD:
            {
                uint32_t buffer_id = *(uint32_t*)(ip + 1);
                uint32_t offset = *(uint32_t*)(ip + 5);
                char* field_name = find_symbol(buffer_id, offset);
                char* obj = stack_pop(&s);
                sprintf(buf, "%s.%s", obj, field_name ? field_name : "UNKNOWN_FIELD");
                stack_push(&s, buf);
                free(obj);
                break;
            }
            case OP_OBJ_VALUE:
                // Assume it gets the value of object on stack.
                break;
            
            case OP_CALL:
            {
                uint32_t buffer_id = *(uint32_t*)(ip + 1);
                uint32_t offset = *(uint32_t*)(ip + 5);
                char* args_fmt = find_symbol(buffer_id, offset);
                int num_args = args_fmt ? strlen(args_fmt) : 0;
                
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
            case OP_STR_EQ:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s == %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_STR_NEQ:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s != %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_CONTAINS:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s contains %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_STARTSWITH:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s startswith %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_ENDSWITH:
            {
                char* v2 = stack_pop(&s);
                char* v1 = stack_pop(&s);
                sprintf(buf, "(%s endswith %s)", v1, v2);
                stack_push(&s, buf);
                free(v1);
                free(v2);
                break;
            }
            case OP_PUSH_RULE:
            {
                uint32_t buffer_id = *(uint32_t*)(ip + 1);
                uint32_t offset = *(uint32_t*)(ip + 5);
                char* symbol = find_symbol(buffer_id, offset);
                if (symbol)
                    stack_push(&s, symbol);
                else
                    stack_push(&s, "UNKNOWN_RULE");
                break;
            }
            case OP_MATCH_RULE:
            {
                char* val = stack_pop(&s);
                stack_push(&s, val);
                free(val);
                break;
            }
            case OP_COUNT:
            {
                char* val = stack_pop(&s);
                sprintf(buf, "#%s", val + (val[0] == '$' ? 1 : 0));
                stack_push(&s, buf);
                free(val);
                break;
            }
            case OP_LENGTH:
            {
                char* val = stack_pop(&s);
                sprintf(buf, "!%s", val + (val[0] == '$' ? 1 : 0));
                stack_push(&s, buf);
                free(val);
                break;
            }
            case OP_OFFSET:
            {
                char* str = stack_pop(&s);
                char* idx = stack_pop(&s);
                sprintf(buf, "@%s[%s]", str + (str[0] == '$' ? 1 : 0), idx);
                stack_push(&s, buf);
                free(str);
                free(idx);
                break;
            }
            case OP_FILESIZE:
                stack_push(&s, "filesize");
                break;
            case OP_ENTRYPOINT:
                stack_push(&s, "entrypoint");
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
    
    // Clean up stack
    while(s.top > 0) free(stack_pop(&s));
}