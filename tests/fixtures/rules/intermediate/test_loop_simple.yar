
rule loop_simple
{
    strings:
        $a = "a"
    condition:
        for all i in (1..10) : ( @a[i] == 0 )
}
