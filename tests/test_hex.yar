
rule test_hex : tag1 tag2
{
    strings:
        $h = { 01 02 03 04 }
    condition:
        $h
}
