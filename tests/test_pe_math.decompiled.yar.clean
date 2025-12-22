import "pe"
import "math"

rule pe_math_complex
{
  meta:
    author = "Decompiler Test"
  strings:
    $s1 = "executable" ascii
    $s2 = "library" ascii
  condition:
    (((0 and (filesize() > 6.5)) and $s1 in (0..1024)) and $s2)
}
