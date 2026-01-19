
rule loop_test
{
    strings:
        $a = "a"
        $b = "b"
    condition:
        for all i in (1..3) : ( @a[i] + 10 == @b[i] )
}
