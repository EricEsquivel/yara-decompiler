#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

#include "decompiler.h"
#include "disassembler.h"
#include "../libyara/include/yara/types.h"
#include "../libyara/include/yara/arena.h"
#include "../libyara/include/yara/compiler.h"
#include "../libyara/include/yara/exec.h"


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

SYMBOL* symbol_table = NULL;
int num_symbols = 0;

void add_symbol(uint32_t buffer_id, uint32_t offset, char* name)
{
    symbol_table = realloc(symbol_table, sizeof(SYMBOL) * (num_symbols + 1));
    symbol_table[num_symbols].buffer_id = buffer_id;
    symbol_table[num_symbols].offset = offset;
    symbol_table[num_symbols].name = strdup(name);
    num_symbols++;
}

char* find_symbol(uint32_t buffer_id, uint32_t offset)
{
    for (int i = 0; i < num_symbols; i++)
    {
        if (symbol_table[i].buffer_id == buffer_id && symbol_table[i].offset == offset)
        {
            return symbol_table[i].name;
        }
    }
    return NULL;
}


uint8_t* map_file(const char* file_path, size_t* file_size)
{
    int fd;
    struct stat st;

    fd = open(file_path, O_RDONLY);
    if (fd < 0)
    {
        perror("open");
        return NULL;
    }

    if (fstat(fd, &st) < 0)
    {
        perror("fstat");
        close(fd);
        return NULL;
    }

    *file_size = st.st_size;

    uint8_t* file_mem = mmap(0, *file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_mem == MAP_FAILED)
    {
        perror("mmap");
        close(fd);
        return NULL;
    }

    close(fd);

    return file_mem;
}

void* resolve_ref(uint8_t* file_mem, YR_ARENA_FILE_BUFFER* buffers, YR_ARENA_REF* ref)
{
    if (YR_ARENA_IS_NULL_REF(*ref))
    {
        return NULL;
    }

    return file_mem + buffers[ref->buffer_id].offset + ref->offset;
}


int decompile(const char* file_path)
{
    size_t file_size;
    uint8_t* file_mem = map_file(file_path, &file_size);

    if (file_mem == NULL)
    {
        return 1;
    }

    YR_ARENA_FILE_HEADER* header = (YR_ARENA_FILE_HEADER*) file_mem;

    if (memcmp(header->magic, "YARA", 4) != 0)
    {
        fprintf(stderr, "Invalid file format: bad magic number\n");
        munmap(file_mem, file_size);
        return 1;
    }

    if (header->version != YR_ARENA_FILE_VERSION)
    {
        fprintf(stderr, "Unsupported file version\n");
        munmap(file_mem, file_size);
        return 1;
    }

    YR_ARENA_FILE_BUFFER* buffers = (YR_ARENA_FILE_BUFFER*) (header + 1);
    
    YR_ARENA_REF summary_ref;
    summary_ref.buffer_id = YR_SUMMARY_SECTION;
    summary_ref.offset = 0;
    YR_SUMMARY* summary = (YR_SUMMARY*)resolve_ref(file_mem, buffers, &summary_ref);

    YR_ARENA_REF rules_table_ref;
    rules_table_ref.buffer_id = YR_RULES_TABLE;
    rules_table_ref.offset = 0;
    YR_RULE* rules_table = (YR_RULE*)resolve_ref(file_mem, buffers, &rules_table_ref);

    YR_ARENA_REF strings_table_ref;
    strings_table_ref.buffer_id = YR_STRINGS_TABLE;
    strings_table_ref.offset = 0;
    YR_STRING* strings_table = (YR_STRING*)resolve_ref(file_mem, buffers, &strings_table_ref);

    YR_ARENA_REF code_start_ref;
    code_start_ref.buffer_id = YR_CODE_SECTION;
    code_start_ref.offset = 0;
    const uint8_t* code_start = (const uint8_t*)resolve_ref(file_mem, buffers, &code_start_ref);

    // Build symbol table
    uint8_t* sz_pool = (uint8_t*)resolve_ref(file_mem, buffers, &(YR_ARENA_REF){.buffer_id=YR_SZ_POOL, .offset=0});
    uint32_t sz_pool_size = buffers[YR_SZ_POOL].size;
    uint32_t sz_offset = 0;
    while(sz_offset < sz_pool_size)
    {
        char* s = (char*)(sz_pool + sz_offset);
        if (*s != '\0')
        {
            add_symbol(YR_SZ_POOL, sz_offset, s);
            sz_offset += strlen(s) + 1;
        }
        else
        {
            sz_offset++;
        }
    }

    for (int i = 0; i < summary->num_strings; i++)
    {
        YR_STRING* string = &strings_table[i];
        char* identifier = (char*) resolve_ref(file_mem, buffers, (YR_ARENA_REF*)&string->identifier);
        add_symbol(YR_STRINGS_TABLE, i * sizeof(YR_STRING), identifier);
    }

    for (int i = 0; i < summary->num_rules; i++)
    {
        YR_RULE* rule = &rules_table[i];
        if (RULE_IS_NULL(rule)) continue;
        char* identifier = (char*) resolve_ref(file_mem, buffers, (YR_ARENA_REF*)&rule->identifier);
        add_symbol(YR_RULES_TABLE, i * sizeof(YR_RULE), identifier);
    }

    // Scan for imports
    const uint8_t* ip = code_start;
    while (*ip != OP_HALT)
    {
        if (*ip == OP_IMPORT)
        {
            uint32_t buffer_id = *(uint32_t*)(ip + 1);
            uint32_t offset = *(uint32_t*)(ip + 5);
            char* module_name = find_symbol(buffer_id, offset);
            if (module_name)
            {
                printf("import \"%s\"\n", module_name);
            }
        }
        ip += get_instr_len(ip);
    }
    printf("\n");


    char* current_ns_name = NULL;

    for (int i = 0; i < summary->num_rules; i++)
    {
        YR_RULE* rule = &rules_table[i];
        if (RULE_IS_NULL(rule))
        {
            continue;
        }

        YR_NAMESPACE* ns = (YR_NAMESPACE*) resolve_ref(file_mem, buffers, (YR_ARENA_REF*)&rule->ns);
        char* ns_name = (char*) resolve_ref(file_mem, buffers, (YR_ARENA_REF*)&ns->name);

        if (current_ns_name == NULL || strcmp(current_ns_name, ns_name) != 0)
        {
            if (strcmp(ns_name, "default") != 0)
            {
                printf("// namespace %s\n", ns_name);
            }
            current_ns_name = ns_name;
        }

        char* identifier = (char*) resolve_ref(file_mem, buffers, (YR_ARENA_REF*)&rule->identifier);
        printf("rule %s", identifier);

        char* tags = (char*) resolve_ref(file_mem, buffers, (YR_ARENA_REF*)&rule->tags);
        if (tags != NULL && *tags != '\0')
        {
            printf(" : ");
            char* tag = tags;
            while(*tag)
            {
                printf("%s ", tag);
                tag += strlen(tag) + 1;
            }
        }
        printf("\n{\n");

        YR_META* metas = (YR_META*) resolve_ref(file_mem, buffers, (YR_ARENA_REF*)&rule->metas);
        if (metas != NULL)
        {
            printf("  meta:\n");
            YR_META* meta = metas;
            while(1)
            {
                char* key = (char*) resolve_ref(file_mem, buffers, (YR_ARENA_REF*)&meta->identifier);
                if (meta->type == META_TYPE_STRING)
                {
                    char* value = (char*) resolve_ref(file_mem, buffers, (YR_ARENA_REF*)&meta->string);
                    printf("    %s = \"%s\"\n", key, value);
                }
                else if (meta->type == META_TYPE_INTEGER)
                {
                    printf("    %s = %lld\n", key, meta->integer);
                }
                else if (meta->type == META_TYPE_BOOLEAN)
                {
                    printf("    %s = %s\n", key, meta->integer ? "true" : "false");
                }

                if (META_IS_LAST_IN_RULE(meta))
                {
                    break;
                }
                meta++;
            }
        }

        YR_STRING* strings = (YR_STRING*) resolve_ref(file_mem, buffers, (YR_ARENA_REF*)&rule->strings);
        if (strings != NULL)
        {
            printf("  strings:\n");
            YR_STRING* string = strings;
            while(1)
            {
                char* identifier = (char*) resolve_ref(file_mem, buffers, (YR_ARENA_REF*)&string->identifier);
                uint8_t* value = (uint8_t*) resolve_ref(file_mem, buffers, (YR_ARENA_REF*)&string->string);
                
                if (STRING_IS_HEX(string))
                {
                    printf("    %s = { ", identifier);
                    for (int j = 0; j < string->length; j++)
                    {
                        printf("%02X ", value[j]);
                    }
                    printf("}\n");
                }
                else
                {
                    printf("    %s = \"%.*s\"\n", identifier, string->length, value);
                }

                if (STRING_IS_LAST_IN_RULE(string))
                {
                    break;
                }
                string++;
            }
        }

        printf("  condition:\n");
        decompile_rule_condition(code_start, i);
        printf("}\n");
    }


    munmap(file_mem, file_size);

    return 0;
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <compiled-rule-file>\n", argv[0]);
        return 1;
    }

    decompile(argv[1]);

    return 0;
}
