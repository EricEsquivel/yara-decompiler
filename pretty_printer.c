#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decompiler.h"
#include "../libyara/include/yara/types.h"

void print_meta(YR_META* meta, uint8_t* file_mem, YR_ARENA_FILE_BUFFER* buffers)
{
    printf("    %s = ", meta->identifier);
    if (meta->type == META_TYPE_INTEGER)
        printf("%lld\n", meta->integer);
    else if (meta->type == META_TYPE_BOOLEAN)
        printf("%s\n", meta->integer ? "true" : "false");
    else
        printf("\"%s\"\n", meta->string);
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
        // A compiled hex string might have its length reduced if it has atoms,
        // but we can try to extract the original bytes if they are available.
        // For this prototype, we print what we have.
        if (string->length > 0) {
            for (uint32_t i = 0; i < string->length; i++)
            {
                printf("%02x ", value[i]);
            }
        } else {
            // Fallback for complex hex strings that might just have atoms
            printf("00 "); 
        }
        printf("}");
    }
    else if (STRING_IS_REGEXP(string))
    {
        if (string->length > 0)
            printf("/%.*s/", string->length, value);
        else
            printf("/[RE_SOURCE_N_A]/");
    }
    else
    {
        printf("\"");
        for (uint32_t i = 0; i < string->length; i++)
        {
            if (value[i] >= 0x20 && value[i] <= 0x7E && value[i] != '"' && value[i] != '\\')
                putchar(value[i]);
            else
                printf("\\x%02x", value[i]);
        }
        printf("\"");
    }

    if (STRING_IS_NO_CASE(string)) printf(" nocase");
    if (!STRING_IS_HEX(string))
    {
        if (STRING_IS_ASCII(string)) printf(" ascii");
        if (STRING_IS_WIDE(string)) printf(" wide");
        if (STRING_IS_FULL_WORD(string)) printf(" fullword");
    }
    if (STRING_IS_PRIVATE(string)) printf(" private");
    if (STRING_IS_XOR(string)) printf(" xor");
    if (STRING_IS_BASE64(string)) printf(" base64");
    if (STRING_IS_BASE64_WIDE(string)) printf(" base64wide");

    printf("\n");
}
