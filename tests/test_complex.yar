
rule complex_rule
{
    strings:
        $a = "abc"
        $b = "def"
    condition:
        $a and $b and (1 + 2 == 3)
}
