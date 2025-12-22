
rule count_offset_test
{
    strings:
        $a = "abc"
    condition:
        #a > 5 and @a[1] == 100 and filesize > 1024
}
