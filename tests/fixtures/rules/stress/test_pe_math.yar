
import "pe"
import "math"

rule pe_math_complex
{
    meta:
        author = "Decompiler Test"
    strings:
        $s1 = "executable"
        $s2 = "library"
    condition:
        pe.is_dll() and 
        pe.number_of_sections > 2 and 
        math.entropy(0, filesize) > 6.5 and
        $s1 in (0..1024) and
        $s2
}
