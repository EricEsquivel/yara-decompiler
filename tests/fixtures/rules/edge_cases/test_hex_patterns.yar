// Edge case tests for hex string patterns
// NOTE: Complex hex patterns (jumps, wildcards, alternatives) are compiled
// to atoms and cannot be fully reconstructed. Only basic hex strings work.

rule hex_basic
{
    strings:
        $a = { 01 02 03 04 }
    condition:
        $a
}

rule hex_longer
{
    strings:
        $a = { DE AD BE EF CA FE BA BE }
    condition:
        $a
}

rule multiple_hex
{
    strings:
        $a = { 01 02 03 }
        $b = { AA BB CC }
    condition:
        $a or $b
}
