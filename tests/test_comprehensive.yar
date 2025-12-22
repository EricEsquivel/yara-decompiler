
import "pe"
import "elf"
import "math"

rule detailed_test
{
    meta:
        description = "Comprehensive test for decompiler"
    strings:
        $a = "abc"
        $b = /d.f/
        $c = { 01 02 03 04 }
        $d = "xyz" fullword
    condition:
        $a and not $b or ($c at 0) and ($d in (0..filesize)) and
        #a > 1 and !a[1] == 3 and @a[1] < 100 and
        any of ($a, $b, $c) and
        all of them and
        for all i in (1..#a) : ( @a[i] > 0 ) and
        pe.number_of_sections > 0 and
        math.entropy(0, filesize) > 7.0 and
        (1 + 2 * 3 == 7) and
        (0x1234 & 0xFF == 0x34) and
        ("test" contains "es")
}
