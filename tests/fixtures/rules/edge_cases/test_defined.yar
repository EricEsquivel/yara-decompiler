// Test: defined operator
// BUG: defined operator is not handled

rule defined_operator
{
    condition:
        defined entrypoint
}
