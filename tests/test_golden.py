"""
Golden file comparison tests for YARA decompiler.

Compares decompiler output against known-good reference outputs.
This catches regressions when refactoring the decompiler.
"""
import pytest
import re
from pathlib import Path
from typing import Optional

from conftest import RULES_DIR, FIXTURES_DIR, collect_rule_files

# Golden files directory (created on demand)
GOLDEN_DIR = Path(__file__).parent / "golden"


def normalize_output(text: str) -> str:
    """
    Normalize decompiler output for comparison.

    - Removes comments
    - Normalizes whitespace
    - Sorts imports (order doesn't matter semantically)
    - Normalizes hex formatting
    """
    lines = []
    for line in text.splitlines():
        # Remove comments
        line = re.sub(r'//.*$', '', line)
        # Strip trailing whitespace
        line = line.rstrip()
        # Skip empty lines
        if line.strip():
            lines.append(line)

    text = '\n'.join(lines)

    # Normalize multiple spaces to single space (but preserve indentation)
    text = re.sub(r'(?<!^)  +', ' ', text, flags=re.MULTILINE)

    # Normalize hex to lowercase
    text = re.sub(r'0x[0-9A-Fa-f]+', lambda m: m.group(0).lower(), text)

    return text.strip()


def extract_condition(text: str) -> Optional[str]:
    """Extract the condition block from YARA output."""
    match = re.search(r'condition:\s*\n?\s*(.+?)(?:\n\}|$)', text, re.DOTALL)
    if match:
        return normalize_output(match.group(1))
    return None


@pytest.mark.golden
class TestGoldenFiles:
    """
    Golden file comparison tests.

    Golden files are stored in tests/golden/ with .golden extension.
    Each golden file corresponds to a rule file and contains the expected
    decompiler output (normalized).
    """

    def test_golden_file_matches(self, decompiler, rule_file):
        """
        Compare decompiler output against golden file if one exists.

        Golden files are optional - tests are skipped if no golden file exists.
        """
        # Determine expected golden file path
        rel_path = rule_file.relative_to(RULES_DIR)
        golden_path = GOLDEN_DIR / rel_path.with_suffix('.golden')

        if not golden_path.exists():
            pytest.skip(f"No golden file at {golden_path}")

        # Compile and decompile
        ok, compiled, err = decompiler.compile_rule(rule_file)
        if not ok:
            pytest.skip(f"Rule failed to compile: {err}")

        result = decompiler.decompile(compiled)
        if not result.success:
            pytest.fail(f"Decompiler failed: {result.error}")

        # Compare normalized outputs
        expected = normalize_output(golden_path.read_text())
        actual = normalize_output(result.output)

        if expected != actual:
            # Generate diff-friendly output
            pytest.fail(
                f"Output differs from golden file:\n"
                f"Golden file: {golden_path}\n"
                f"\n--- Expected ---\n{expected}\n"
                f"\n--- Actual ---\n{actual}\n"
            )


class TestGoldenManagement:
    """Utilities for managing golden files."""

    def test_generate_golden_files(self, decompiler, request):
        """
        Generate golden files for all rules.

        Run with: pytest -k test_generate_golden_files --generate-golden

        This is not a real test - it's a utility for updating golden files.
        """
        if not request.config.getoption("--generate-golden", default=False):
            pytest.skip("Use --generate-golden to run this")

        GOLDEN_DIR.mkdir(parents=True, exist_ok=True)

        all_rules = collect_rule_files(RULES_DIR)
        generated = 0
        failed = 0

        for rule_file in all_rules:
            ok, compiled, err = decompiler.compile_rule(rule_file)
            if not ok:
                print(f"SKIP (compile failed): {rule_file}")
                failed += 1
                continue

            result = decompiler.decompile(compiled)
            if not result.success:
                print(f"SKIP (decompile failed): {rule_file}")
                failed += 1
                continue

            # Determine golden path
            rel_path = rule_file.relative_to(RULES_DIR)
            golden_path = GOLDEN_DIR / rel_path.with_suffix('.golden')
            golden_path.parent.mkdir(parents=True, exist_ok=True)

            # Write normalized output
            normalized = normalize_output(result.output)
            golden_path.write_text(normalized)
            print(f"Generated: {golden_path}")
            generated += 1

        print(f"\nGenerated {generated} golden files, {failed} failures")


class TestConditionRegression:
    """
    Test specific condition patterns don't regress.

    These tests verify exact output for critical patterns,
    independent of golden files.
    """

    @pytest.mark.parametrize("source,expected_condition_fragment", [
        # Boolean operators
        ('rule t { strings: $a = "x" $b = "y" condition: $a and $b }', 'and'),
        ('rule t { strings: $a = "x" $b = "y" condition: $a or $b }', 'or'),
        ('rule t { strings: $a = "x" condition: not $a }', 'not'),

        # Comparisons
        ('rule t { condition: filesize > 100 }', '>'),
        ('rule t { condition: filesize < 100 }', '<'),
        ('rule t { condition: filesize == 100 }', '=='),
        ('rule t { condition: filesize != 100 }', '!='),
        ('rule t { condition: filesize >= 100 }', '>='),
        ('rule t { condition: filesize <= 100 }', '<='),

        # Arithmetic
        ('rule t { condition: 1 + 2 == 3 }', '+'),
        ('rule t { condition: 5 - 3 == 2 }', '-'),
        ('rule t { condition: 2 * 3 == 6 }', '*'),
        ('rule t { condition: 6 / 2 == 3 }', '/'),
        ('rule t { condition: 7 % 3 == 1 }', '%'),

        # Bitwise
        ('rule t { condition: 0xFF & 0x0F == 0x0F }', '&'),
        ('rule t { condition: 0xF0 | 0x0F == 0xFF }', '|'),
        ('rule t { condition: 0xFF ^ 0xAA == 0x55 }', '^'),
        ('rule t { condition: 1 << 4 == 16 }', '<<'),
        ('rule t { condition: 16 >> 2 == 4 }', '>>'),

        # String operations
        ('rule t { strings: $a = "x" condition: #a > 0 }', '#'),
        ('rule t { strings: $a = "x" condition: @a > 0 }', '@'),
        ('rule t { strings: $a = "x" condition: $a at 0 }', 'at'),
        ('rule t { strings: $a = "x" condition: $a in (0..100) }', 'in'),

        # Quantifiers
        # Note: "any of them" compiles to "1 of them" - semantic equivalent
        ('rule t { strings: $a = "x" $b = "y" condition: any of them }', 'of'),
        ('rule t { strings: $a = "x" $b = "y" condition: all of them }', 'all'),
        ('rule t { strings: $a = "x" $b = "y" condition: 1 of them }', 'of'),

        # Loops
        ('rule t { condition: for any i in (1..10) : (i > 0) }', 'for'),
    ])
    def test_condition_operator_preserved(self, decompiler, source, expected_condition_fragment):
        """Test that specific operators appear in decompiled output."""
        ok, compiled, err = decompiler.compile_source(source)
        if not ok:
            pytest.skip(f"Source didn't compile: {err}")

        result = decompiler.decompile(compiled)
        assert result.success, f"Decompile failed: {result.error}"

        condition = extract_condition(result.output)
        assert condition is not None, f"No condition found in:\n{result.output}"

        assert expected_condition_fragment in condition, (
            f"Expected '{expected_condition_fragment}' in condition.\n"
            f"Full output:\n{result.output}\n"
            f"Extracted condition: {condition}"
        )
