// Edge case tests for special operators
// NOTE: Some operators like defined, entrypoint have limitations

rule contains_operator
{
    condition:
        "hello world" contains "world" and
        "testing" contains "est"
}

rule icontains_operator
{
    condition:
        "Hello World" icontains "WORLD" and
        "TESTING" icontains "test"
}

rule startswith_operator
{
    condition:
        "hello world" startswith "hello" and
        "testing123" startswith "test"
}

rule endswith_operator
{
    condition:
        "hello world" endswith "world" and
        "testing123" endswith "123"
}

rule iequals_operator
{
    condition:
        "Hello" iequals "HELLO" and
        "TeSt" iequals "test"
}
