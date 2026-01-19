import "pe"
import "math"

rule logic_maze
{
    meta:
        description = "Stress test for boolean precedence and identity suppression"
    strings:
        $a1 = "a1"
        $a2 = "a2"
        $b1 = "b1"
        $b2 = "b2"
    condition:
        ($a1 and not $a2 or ($b1 and ($b2 or not $a1))) and 
        not ($a2 and $b2) or 
        (($a1 or $b1) and ($a2 or $b2) and not ($a1 and $b1))
}

rule nested_loops
{
    meta:
        description = "Stress test for multi-level nested loops"
    condition:
        for all i in (1..5) : (
            for any j in (1..i) : (
                uint32(i * j) == 0xfeedface
            )
        )
}

rule quantifier_edge
{
    meta:
        description = "Stress test for mixed set quantifiers"
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
        $d = "d"
    condition:
        2 of ($a, $b, $c) and 
        all of ($*) and 
        1 of ($a, $b) in (0..1024) and
        none of ($c, $d)
}

rule module_deep_dive
{
    condition:
        pe.is_dll() and 
        pe.number_of_sections > 3 and
        pe.sections[0].name == ".text" and
        math.entropy(pe.sections[pe.section_index(".data")].raw_data_offset, pe.sections[pe.section_index(".data")].raw_data_size) > 7.2
}

rule string_modifier_bomb
{
    strings:
        $s1 = "abc" ascii wide nocase fullword
        $s2 = "def" private
        $s3 = { 01 [2-5] 02 }
        $s4 = /regex[0-9]{3}/ wide
    condition:
        $s1 and $s2 and $s3 and $s4
}