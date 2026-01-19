"""
Roundtrip tests for YARA decompiler.

Tests that rules survive the compile -> decompile -> recompile cycle.
"""
import pytest
from pathlib import Path


class TestRoundtrip:
    """Test that all rules survive roundtrip compilation."""

    def test_roundtrip_compiles(self, decompiler, rule_file):
        """
        Test that a rule file survives the roundtrip process:
        1. Original rule compiles successfully
        2. Decompiler produces output without crashing
        3. Decompiled output compiles successfully
        """
        result = decompiler.roundtrip(rule_file)

        # Provide detailed failure messages
        if result.compile_error:
            pytest.fail(f"Original rule failed to compile:\n{result.compile_error}")

        if result.decompile_error:
            pytest.fail(f"Decompiler failed:\n{result.decompile_error}")

        if result.recompile_error:
            pytest.fail(
                f"Decompiled output failed to compile:\n"
                f"--- Decompiled Source ---\n{result.decompiled_source}\n"
                f"--- Compiler Error ---\n{result.recompile_error}"
            )

        assert result.success, "Roundtrip failed for unknown reason"


class TestDecompilerBasics:
    """Basic decompiler functionality tests."""

    def test_decompiler_exists(self, decompiler):
        """Verify the decompiler binary exists."""
        assert decompiler.binary.exists(), f"Decompiler not found at {decompiler.binary}"

    def test_empty_invocation(self, decompiler):
        """Decompiler should handle being called with no arguments."""
        import subprocess
        result = subprocess.run(
            [str(decompiler.binary)],
            capture_output=True,
            text=True
        )
        # Should exit with error or usage message, not crash
        assert result.returncode != -11, "Decompiler crashed (SIGSEGV)"

    def test_nonexistent_file(self, decompiler):
        """Decompiler should handle nonexistent files gracefully."""
        import subprocess
        result = subprocess.run(
            [str(decompiler.binary), "/nonexistent/path/file.compiled"],
            capture_output=True,
            text=True
        )
        assert result.returncode != -11, "Decompiler crashed (SIGSEGV)"

    def test_minimal_rule_true(self, decompiler):
        """Test the simplest possible rule: condition: true."""
        source = 'rule minimal { condition: true }'
        ok, compiled, err = decompiler.compile_source(source)
        assert ok, f"Failed to compile minimal rule: {err}"

        result = decompiler.decompile(compiled)
        assert result.success, f"Decompiler failed: {result.error}"
        assert "true" in result.output.lower(), "Output should contain 'true'"

    def test_minimal_rule_false(self, decompiler):
        """Test rule with condition: false."""
        source = 'rule minimal_false { condition: false }'
        ok, compiled, err = decompiler.compile_source(source)
        assert ok, f"Failed to compile: {err}"

        result = decompiler.decompile(compiled)
        assert result.success, f"Decompiler failed: {result.error}"
        assert "false" in result.output.lower(), "Output should contain 'false'"

    def test_rule_with_string(self, decompiler):
        """Test basic rule with a string."""
        source = '''
        rule with_string {
            strings:
                $a = "test"
            condition:
                $a
        }
        '''
        ok, compiled, err = decompiler.compile_source(source)
        assert ok, f"Failed to compile: {err}"

        result = decompiler.decompile(compiled)
        assert result.success, f"Decompiler failed: {result.error}"
        assert "$a" in result.output or "$" in result.output, "Output should reference string"


class TestConditionPreservation:
    """Test that specific condition patterns are preserved correctly."""

    @pytest.mark.parametrize("condition,expected_fragments", [
        ("true", ["true"]),
        ("false", ["false"]),
        ("filesize > 0", ["filesize"]),
        ("1 + 2 == 3", ["1", "2", "3"]),
        # Note: hex format not preserved, but operators are
        ("0xFF & 0x0F == 0x0F", ["255", "&", "15"]),
    ])
    def test_condition_fragments(self, decompiler, condition, expected_fragments):
        """Test that condition fragments are preserved in output."""
        source = f'rule test {{ condition: {condition} }}'
        ok, compiled, err = decompiler.compile_source(source)
        if not ok:
            pytest.skip(f"Rule didn't compile (may use unsupported feature): {err}")

        result = decompiler.decompile(compiled)
        assert result.success, f"Decompiler failed: {result.error}"

        output_lower = result.output.lower()
        for fragment in expected_fragments:
            assert fragment.lower() in output_lower, \
                f"Expected '{fragment}' in output:\n{result.output}"
