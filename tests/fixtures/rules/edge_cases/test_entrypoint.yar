// Test: entrypoint keyword
// BUG: entrypoint produces invalid output

rule entrypoint_basic
{
    strings:
        $mz = "MZ"
    condition:
        $mz at 0 and entrypoint > 0
}
