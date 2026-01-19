// Edge case tests for string modifiers
// NOTE: base64/base64wide strings have their content transformed at compile time
// and cannot be recovered. XOR strings work.

rule xor_basic
{
    strings:
        $a = "secret" xor
    condition:
        $a
}

rule combined_modifiers
{
    strings:
        $a = "test" ascii wide nocase
        $b = "data" ascii fullword
        $c = "info" nocase wide fullword
    condition:
        $a or $b or $c
}

rule private_string
{
    strings:
        $a = "visible"
        $b = "hidden" private
    condition:
        $a and $b
}

rule wide_ascii
{
    strings:
        $a = "unicode" wide
        $b = "plain" ascii
    condition:
        $a or $b
}
