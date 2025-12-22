import "pe"
import "elf"
import "math"

rule detailed_test
{
  meta:
    description = "Comprehensive test for decompiler"
  strings:
    $a = "abc" ascii
    $b = //
    $c = { 01 02 03 04 }
    $d = "xyz" ascii fullword
  condition:
    (all or ((((((0 and for all i in (1..#a) : ( (@a[i] > 0) )) and (pe.number_of_sections > 0)) and (math.entropy(0, filesize) > 7)) and ((1 + (2 * 3)) == 7)) and ((4660 & 255) == 52)) and ("test" contains "es")))
}
