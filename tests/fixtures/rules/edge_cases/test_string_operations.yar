// Edge case tests for string count, offset, and length operations

rule string_count_basic
{
    strings:
        $a = "test"
    condition:
        #a > 0 and
        #a < 100 and
        #a >= 1
}

rule string_count_comparison
{
    strings:
        $a = "one"
        $b = "two"
    condition:
        #a == #b or
        #a > #b or
        #a < #b
}

rule string_offset_basic
{
    strings:
        $a = "marker"
    condition:
        @a > 0 and
        @a < filesize
}

rule string_offset_indexed
{
    strings:
        $a = "repeat"
    condition:
        @a[1] > 0 and
        @a[#a] < filesize
}

rule string_at_position
{
    strings:
        $mz = "MZ"
        $pe = "PE"
    condition:
        $mz at 0 or
        $pe at 128
}

rule string_in_range
{
    strings:
        $a = "header"
    condition:
        $a in (0..1024) and
        $a in (0..filesize)
}

rule combined_string_ops
{
    strings:
        $a = "marker"
    condition:
        #a > 0 and
        @a[1] < 1000
}
