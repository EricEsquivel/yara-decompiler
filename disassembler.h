
#ifndef YARA_DISASSEMBLER_H
#define YARA_DISASSEMBLER_H

#include <stdint.h>
#include "yara/libyara/include/yara/types.h"

void disassemble(const uint8_t* code_start, int rule_idx);
int get_instr_len(const uint8_t* ip);

#endif
