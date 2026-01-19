// Edge case tests for numeric values

rule negative_integers
{
    condition:
        int32(0) == -1 or
        int16(0) == -32768 or
        int8(0) == -128
}

rule hex_representations
{
    condition:
        uint16(0) == 0x1234 and
        uint8(0) == 0xFF and
        uint32(0) == 0xCAFEBABE
}

rule arithmetic_operations
{
    condition:
        (10 + 5 == 15) and
        (20 - 8 == 12) and
        (6 * 7 == 42) and
        (17 % 5 == 2)
}

rule bitwise_operations
{
    condition:
        (0xFF & 0x0F == 0x0F) and
        (0xF0 | 0x0F == 0xFF) and
        (0xFF ^ 0xAA == 0x55) and
        (1 << 4 == 16) and
        (256 >> 4 == 16)
}

rule comparison_chain
{
    condition:
        1 < 2 and
        2 <= 2 and
        3 > 2 and
        3 >= 3 and
        4 != 5 and
        5 == 5
}

rule filesize_arithmetic
{
    condition:
        filesize > 0 and
        filesize < 0x7FFFFFFF
}
