// Test: Simple rule reference
// BUG: Produces invalid output "( and )" instead of the rule name

rule base_rule
{
    strings:
        $a = "test"
    condition:
        $a
}

rule rule_ref_simple
{
    condition:
        base_rule
}
