#include <stdio.h>
#include <string.h>
#include "decompiler.h"
#include "../libyara/include/yara/types.h"

void print_meta(YR_META* meta, uint8_t* file_mem, YR_ARENA_FILE_BUFFER* buffers)
{
    printf("    %s = ", meta->identifier);
    if (meta->type == META_TYPE_STRING)
    {
        printf("\"%s\"\n", meta->string);
    }
    else if (meta->type == META_TYPE_INTEGER)
    {
        printf("%lld\n", meta->integer);
    }
    else if (meta->type == META_TYPE_BOOLEAN)
    {
        printf("%s\n", meta->integer ? "true" : "false");
    }
}

void print_string(YR_STRING* string, uint8_t* file_mem, YR_ARENA_FILE_BUFFER* buffers)
{
    uint8_t* value = string->string;
    char* identifier = (char*)string->identifier;
    
    if (identifier[0] == '$')
        printf("    %s = ", identifier);
    else
        printf("    $%s = ", identifier);
    
    if (STRING_IS_HEX(string))
    {
        printf("{ ");
        for (int j = 0; j < string->length; j++)
        {
            printf("%02X ", value[j]);
        }
        printf("}");
    }
    else if (STRING_IS_REGEXP(string))
    {
        // YARA does not store regex source. 
        // We print a placeholder that is valid YARA syntax.
        if (string->length > 0)
            printf("/%.*s/", string->length, value);
        else
            printf("/[RE_SOURCE_N_A]/");
    }
    else
    {
        printf("\"%.*s\"", string->length, value);
    }

    if (!STRING_IS_HEX(string) && !STRING_IS_REGEXP(string))
    {
        if (STRING_IS_NO_CASE(string)) printf(" nocase");
        if (STRING_IS_ASCII(string)) printf(" ascii");
        if (STRING_IS_WIDE(string)) printf(" wide");
        if (STRING_IS_FULL_WORD(string)) printf(" fullword");
    }
    
    if (STRING_IS_PRIVATE(string)) printf(" private");

    printf("\n");
}