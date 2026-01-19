
rule short_circuit
{
    strings:
        $a = "a"
        $b = "b"
    condition:
        $a and $b or not $a
}
