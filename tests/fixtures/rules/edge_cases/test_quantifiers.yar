// Edge case tests for quantifiers

rule percentage_quantifier_50
{
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
        $d = "d"
    condition:
        50% of them
}

rule percentage_quantifier_75
{
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
        $d = "d"
    condition:
        75% of ($a, $b, $c, $d)
}

rule percentage_quantifier_100
{
    strings:
        $a = "a"
        $b = "b"
    condition:
        100% of them
}

rule none_of_quantifier
{
    strings:
        $bad1 = "malicious"
        $bad2 = "evil"
        $good = "safe"
    condition:
        $good and none of ($bad1, $bad2)
}

rule specific_count_of
{
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
        $d = "d"
        $e = "e"
    condition:
        3 of them
}

rule quantifier_with_wildcard
{
    strings:
        $str_1 = "one"
        $str_2 = "two"
        $str_3 = "three"
        $other = "other"
    condition:
        2 of ($str_*) and $other
}

rule all_of_subset
{
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
    condition:
        all of ($a, $b) and $c
}

rule any_of_in_range
{
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
    condition:
        any of them in (0..1024)
}

rule quantifier_at_offset
{
    strings:
        $a = "MZ"
        $b = "PE"
    condition:
        1 of them at 0
}
