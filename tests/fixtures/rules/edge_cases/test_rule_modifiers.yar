// Edge case tests for rule modifiers

global rule global_detector
{
    strings:
        $a = "global_marker"
    condition:
        $a
}

private rule private_helper
{
    strings:
        $a = "helper_string"
    condition:
        $a
}

rule uses_private : tag1
{
    condition:
        private_helper
}

private global rule private_global_combo
{
    strings:
        $a = "combo"
    condition:
        $a
}
