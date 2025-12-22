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


SYMBOL* symbol_table = NULL;
int num_symbols = 0;
int show_disassembly = 0;
uintptr_t mapped_base = 0;
size_t mapped_size = 0;

void add_symbol(uintptr_t addr, char* name)
{
    if (addr == 0 || name == NULL) return;
    for (int i = 0; i < num_symbols; i++)
    {
        if (symbol_table[i].addr == addr) return;
    }

    symbol_table = realloc(symbol_table, sizeof(SYMBOL) * (num_symbols + 1));
    symbol_table[num_symbols].addr = addr;
    symbol_table[num_symbols].name = strdup(name);
    num_symbols++;
}

char* find_symbol(uintptr_t addr)
{
    if (addr < mapped_base || addr >= mapped_base + mapped_size)
        return NULL;

    for (int i = 0; i < num_symbols; i++)
    {
        if (symbol_table[i].addr == addr)
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

    uint8_t* file_mem = mmap(0, *file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
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

    mapped_base = (uintptr_t)file_mem;
    mapped_size = file_size;

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
    
    uint64_t last_buffer_end = 0;
    for (int i = 0; i < header->num_buffers; i++) {
        if (buffers[i].offset + buffers[i].size > last_buffer_end)
            last_buffer_end = buffers[i].offset + buffers[i].size;
    }
    
    uint8_t* reloc_ptr = file_mem + last_buffer_end;
    while (reloc_ptr + sizeof(YR_ARENA_REF) <= file_mem + file_size)
    {
        YR_ARENA_REF* reloc_ref = (YR_ARENA_REF*)reloc_ptr;
        if (reloc_ref->buffer_id >= header->num_buffers) break;

        void* target_ptr = file_mem + buffers[reloc_ref->buffer_id].offset + reloc_ref->offset;
        YR_ARENA_REF* value_to_patch = (YR_ARENA_REF*)target_ptr;
        
        void* final_ptr = resolve_ref(file_mem, buffers, value_to_patch);
        memcpy(target_ptr, &final_ptr, sizeof(void*));
        
        reloc_ptr += sizeof(YR_ARENA_REF);
    }

    YR_ARENA_REF summary_ref = { .buffer_id = YR_SUMMARY_SECTION, .offset = 0 };
    YR_SUMMARY* summary = (YR_SUMMARY*)resolve_ref(file_mem, buffers, &summary_ref);

    YR_ARENA_REF rules_table_ref = { .buffer_id = YR_RULES_TABLE, .offset = 0 };
    YR_RULE* rules_table = (YR_RULE*)resolve_ref(file_mem, buffers, &rules_table_ref);

    YR_ARENA_REF strings_table_ref = { .buffer_id = YR_STRINGS_TABLE, .offset = 0 };
    YR_STRING* strings_table = (YR_STRING*)resolve_ref(file_mem, buffers, &strings_table_ref);

    YR_ARENA_REF code_start_ref = { .buffer_id = YR_CODE_SECTION, .offset = 0 };
    const uint8_t* code_start = (const uint8_t*)resolve_ref(file_mem, buffers, &code_start_ref);

    uint8_t* sz_pool = (uint8_t*)resolve_ref(file_mem, buffers, &(YR_ARENA_REF){.buffer_id=YR_SZ_POOL, .offset=0});
    uint32_t sz_pool_size = buffers[YR_SZ_POOL].size;
    
    // Improved sz_pool parsing: identifying SIZED_STRINGs
    uint32_t sz_offset = 0;
    while(sz_offset + 8 < sz_pool_size)
    {
        SIZED_STRING* ss = (SIZED_STRING*)(sz_pool + sz_offset);
        // Heuristic: length should be reasonable and c_string should be printable
        if (ss->length > 0 && ss->length < 1024 && ss->c_string[0] != '\0')
        {
            // Add symbol for the SIZED_STRING structure itself
            add_symbol((uintptr_t)ss, ss->c_string);
            sz_offset += 8 + ss->length + 1;
            // Pad to 8-byte alignment if YARA does that? No, usually it's just packed.
            // But let's check for null padding.
            while(sz_offset < sz_pool_size && sz_pool[sz_offset] == '\0') sz_offset++;
        }
        else if (sz_pool[sz_offset] != '\0')
        {
            // Fallback for raw C strings
            add_symbol((uintptr_t)(sz_pool + sz_offset), (char*)(sz_pool + sz_offset));
            sz_offset += strlen((char*)(sz_pool + sz_offset)) + 1;
        }
        else
        {
            sz_offset++;
        }
    }

    for (int i = 0; i < summary->num_strings; i++)
    {
        YR_STRING* string = (YR_STRING*)((uint8_t*)strings_table + i * sizeof(YR_STRING));
        if (string->identifier)
        {
            add_symbol((uintptr_t)string, (char*)string->identifier);
        }
    }

    for (int i = 0; i < summary->num_rules; i++)
    {
        YR_RULE* rule = (YR_RULE*)((uint8_t*)rules_table + i * sizeof(YR_RULE));
        if (RULE_IS_NULL(rule)) continue;
        add_symbol((uintptr_t)rule, (char*)rule->identifier);
    }

    const uint8_t* ip = code_start;
    while (ip < code_start + buffers[YR_CODE_SECTION].size && *ip != OP_HALT)
    {
        if (*ip == OP_IMPORT)
        {
            void* addr = *(void**)(ip + 1);
            char* module_name = find_symbol((uintptr_t)addr);
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
        YR_RULE* rule = (YR_RULE*)((uint8_t*)rules_table + i * sizeof(YR_RULE));
        if (RULE_IS_NULL(rule))
        {
            continue;
        }

        char* ns_name = rule->ns->name;

        if (current_ns_name == NULL || strcmp(current_ns_name, ns_name) != 0)
        {
            if (strcmp(ns_name, "default") != 0)
            {
                printf("// namespace %s\n", ns_name);
            }
            current_ns_name = ns_name;
        }

        printf("rule %s", rule->identifier);

        if (rule->tags != NULL && *rule->tags != '\0')
        {
            printf(" : ");
            char* tag = (char*)rule->tags;
            while(*tag)
            {
                printf("%s ", tag);
                tag += strlen(tag) + 1;
            }
        }
        printf("\n{\n");

        if (rule->metas != NULL)
        {
            printf("  meta:\n");
            YR_META* meta = rule->metas;
            while(1)
            {
                print_meta(meta, file_mem, buffers);
                if (META_IS_LAST_IN_RULE(meta)) break;
                meta++;
            }
        }

        if (rule->strings != NULL)
        {
            printf("  strings:\n");
            YR_STRING* string = rule->strings;
            while(1)
            {
                print_string(string, file_mem, buffers);
                if (STRING_IS_LAST_IN_RULE(string)) break;
                string++;
            }
        }

        printf("  condition:\n");
        if (show_disassembly)
            disassemble(code_start, i);
        
        decompile_rule_condition(code_start, i);
        printf("}\n");
    }


    munmap(file_mem, file_size);

    return 0;
}

int main(int argc, char** argv)
{
    char* file_path = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--disassemble") == 0)
        {
            show_disassembly = 1;
        }
        else
        {
            file_path = argv[i];
        }
    }

    if (file_path == NULL)
    {
        fprintf(stderr, "Usage: %s [--disassemble] <compiled-rule-file>\n", argv[0]);
        return 1;
    }

    decompile(file_path);

    return 0;
}
