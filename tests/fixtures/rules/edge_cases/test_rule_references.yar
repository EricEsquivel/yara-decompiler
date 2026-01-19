// Edge case tests for rule references
// NOTE: Complex rule references moved to test_known_issues.yar

rule base_rule_1
{
    strings:
        $a = "base1"
    condition:
        $a
}

rule base_rule_2
{
    strings:
        $a = "base2"
    condition:
        $a
}
