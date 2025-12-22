
rule my_rule
{
    meta:
        author = "test"
    strings:
        $a = "dummy"
    condition:
        $a
}
