
rule comprehensive_test
{
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
    condition:
        2 of ($a, $b, $c) and $a at 0 and $b in (0..100) and uint32(0) == 0xfeedface
}
