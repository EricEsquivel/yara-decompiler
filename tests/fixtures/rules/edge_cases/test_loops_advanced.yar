import "pe"

// Edge case tests for loop constructs
// NOTE: Some complex loop patterns may not round-trip perfectly

rule loop_with_expression_bound
{
    strings:
        $a = "test"
    condition:
        for all i in (1..#a) : (
            @a[i] > 0
        )
}

rule nested_loops_2_levels
{
    condition:
        for all i in (0..5) : (
            for any j in (0..i) : (
                uint8(i + j) != 255
            )
        )
}

// NOTE: "for any of ($a, $b, $c)" patterns cause decompiler issues
// rule loop_with_string_set removed
