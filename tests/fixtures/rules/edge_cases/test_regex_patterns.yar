// Edge case tests for regex patterns

rule regex_case_insensitive
{
    strings:
        $a = /[Tt]est[Pp]attern/i
    condition:
        $a
}

rule regex_dot_matches_all
{
    strings:
        $a = /start.+end/s
    condition:
        $a
}

rule regex_combined_flags
{
    strings:
        $a = /multi.+line.+pattern/is
    condition:
        $a
}

rule regex_character_classes
{
    strings:
        $a = /[a-zA-Z0-9_]+/
        $b = /[^0-9]+/
        $c = /[\x00-\x1f]/
    condition:
        $a or $b or $c
}

rule regex_quantifiers
{
    strings:
        $a = /a{3}/
        $b = /b{2,5}/
        $c = /c{3,}/
        $d = /d+/
        $e = /e*/
        $f = /f?/
    condition:
        $a or $b or $c or $d or $e or $f
}

rule regex_anchors
{
    strings:
        $a = /^start/
        $b = /end$/
    condition:
        $a or $b
}

rule regex_groups
{
    strings:
        $a = /(foo|bar|baz)+/
        $b = /test(ing)?/
    condition:
        $a or $b
}

rule regex_with_modifiers
{
    strings:
        $a = /pattern/i wide
        $b = /another/s ascii nocase
    condition:
        $a or $b
}
