// Test: Multiple rule references with boolean ops
// BUG: Produces invalid syntax when combining rule references

rule first_rule
{
    strings:
        $a = "first"
    condition:
        $a
}

rule second_rule
{
    strings:
        $b = "second"
    condition:
        $b
}

rule rule_ref_multiple
{
    condition:
        first_rule and second_rule
}
