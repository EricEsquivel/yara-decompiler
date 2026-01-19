// Test: for any of with offset expression
// This tests string set iteration with @ operator

rule for_any_of_with_offset
{
    strings:
        $a = "one"
        $b = "two"
        $c = "three"
    condition:
        for any of ($a, $b, $c) : (
            @ > 100
        )
}
