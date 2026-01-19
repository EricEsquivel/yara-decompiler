// Edge case tests for complex boolean expressions

rule deeply_nested_and
{
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
        $d = "d"
    condition:
        ($a and ($b and ($c and $d)))
}

rule deeply_nested_or
{
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
        $d = "d"
    condition:
        ($a or ($b or ($c or $d)))
}

rule mixed_precedence
{
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
        $d = "d"
    condition:
        $a and $b or $c and $d
}

rule explicit_precedence
{
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
        $d = "d"
    condition:
        ($a and $b) or ($c and $d)
}

rule not_combinations
{
    strings:
        $a = "a"
        $b = "b"
    condition:
        not $a or $b and
        not ($a and $b) or
        not not $a
}

rule demorgan_test_1
{
    strings:
        $a = "a"
        $b = "b"
    condition:
        not ($a and $b) or ($a and $b)
}

rule demorgan_test_2
{
    strings:
        $a = "a"
        $b = "b"
    condition:
        not ($a or $b) or ($a or $b)
}

rule complex_boolean_chain
{
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
        $d = "d"
        $e = "e"
    condition:
        (($a and $b) or ($c and $d)) and
        (not $e or ($a and $e)) and
        ($b or $c or $d)
}

rule boolean_with_comparisons
{
    condition:
        (1 < 2 and 3 > 2) or
        (4 == 4 and 5 != 6) and
        (7 >= 7 or 8 <= 9)
}

rule short_circuit_test
{
    strings:
        $a = "a"
        $b = "b"
    condition:
        ($a and $b) or (not $a and not $b) or ($a and not $b) or (not $a and $b)
}
