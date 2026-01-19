"""
Semantic equivalence tests for YARA decompiler.

Tests that decompiled rules produce the same scan results as originals.
"""
import pytest
from pathlib import Path

from conftest import RULES_DIR, SAMPLES_DIR, collect_rule_files


@pytest.mark.semantic
class TestSemanticEquivalence:
    """
    Test that decompiled rules are semantically equivalent to originals.

    This goes beyond syntax validation - it verifies that the decompiled
    rules match the exact same files as the original rules.
    """

    @pytest.fixture
    def rule_files_for_semantic(self):
        """Get rule files suitable for semantic testing (no module dependencies)."""
        # Skip rules that depend on PE/ELF modules since our samples aren't real PEs
        basic_rules = collect_rule_files(
            RULES_DIR / "basic",
            RULES_DIR / "intermediate"
        )
        # Filter out rules with module imports for basic semantic tests
        return [r for r in basic_rules if not self._has_module_imports(r)]

    def _has_module_imports(self, rule_path: Path) -> bool:
        """Check if a rule file has module imports."""
        try:
            content = rule_path.read_text()
            return 'import "' in content
        except Exception:
            return True  # Assume it has imports if we can't read it

    def test_scan_equivalence_basic(self, decompiler, tmp_path):
        """
        Test that basic rules produce same matches before and after decompilation.
        """
        # Create a simple rule that will match our test samples
        source = '''
        rule finds_test {
            strings:
                $a = "test"
            condition:
                $a
        }

        rule finds_marker {
            strings:
                $m = "marker"
            condition:
                $m
        }

        rule finds_nothing {
            strings:
                $x = "ZZZNOTFOUND999"
            condition:
                $x
        }
        '''

        # Compile original
        ok, original_compiled, err = decompiler.compile_source(source)
        assert ok, f"Failed to compile original: {err}"

        # Decompile and recompile
        decompile_result = decompiler.decompile(original_compiled)
        assert decompile_result.success, f"Decompile failed: {decompile_result.error}"

        clean_source = decompiler.clean_decompiled_output(decompile_result.output)
        ok, recompiled, err = decompiler.compile_source(clean_source)
        assert ok, f"Failed to recompile: {err}\n\nDecompiled source:\n{clean_source}"

        # Scan each sample with both versions and compare
        if not SAMPLES_DIR.exists():
            pytest.skip("No sample files available")

        for sample in SAMPLES_DIR.iterdir():
            if not sample.is_file():
                continue

            original_scan = decompiler.scan(original_compiled, sample)
            recompiled_scan = decompiler.scan(recompiled, sample)

            assert original_scan.matches == recompiled_scan.matches, (
                f"Scan mismatch for {sample.name}:\n"
                f"  Original matches: {original_scan.matches}\n"
                f"  Recompiled matches: {recompiled_scan.matches}\n"
                f"  Decompiled source:\n{clean_source}"
            )

    def test_string_match_preservation(self, decompiler):
        """Test that string matching semantics are preserved."""
        # Create a sample file
        sample_content = b"Hello World! Testing 123 test TEST TeSt"
        sample_path = decompiler.tmp_dir / "string_test.bin"
        sample_path.write_bytes(sample_content)

        source = '''
        rule case_sensitive {
            strings:
                $a = "test"
            condition:
                $a
        }

        rule case_insensitive {
            strings:
                $a = "test" nocase
            condition:
                $a
        }
        '''

        ok, original, _ = decompiler.compile_source(source)
        assert ok

        result = decompiler.roundtrip_source(source) if hasattr(decompiler, 'roundtrip_source') else None

        # Simplified: just verify roundtrip works
        decompile_result = decompiler.decompile(original)
        assert decompile_result.success

        clean = decompiler.clean_decompiled_output(decompile_result.output)
        ok, recompiled, err = decompiler.compile_source(clean)
        assert ok, f"Recompile failed: {err}"

        orig_scan = decompiler.scan(original, sample_path)
        new_scan = decompiler.scan(recompiled, sample_path)

        assert orig_scan.matches == new_scan.matches, (
            f"Match difference:\n"
            f"Original: {orig_scan.matches}\n"
            f"Recompiled: {new_scan.matches}"
        )

    def test_count_offset_preservation(self, decompiler):
        """Test that #count and @offset operations are preserved."""
        sample_content = b"AAA test BBB test CCC test DDD"
        sample_path = decompiler.tmp_dir / "count_test.bin"
        sample_path.write_bytes(sample_content)

        source = '''
        rule count_test {
            strings:
                $a = "test"
            condition:
                #a == 3
        }

        rule count_greater {
            strings:
                $a = "test"
            condition:
                #a > 2
        }
        '''

        ok, original, _ = decompiler.compile_source(source)
        assert ok

        decompile_result = decompiler.decompile(original)
        assert decompile_result.success

        clean = decompiler.clean_decompiled_output(decompile_result.output)
        ok, recompiled, err = decompiler.compile_source(clean)
        assert ok, f"Recompile failed: {err}"

        orig_scan = decompiler.scan(original, sample_path)
        new_scan = decompiler.scan(recompiled, sample_path)

        assert orig_scan.matches == new_scan.matches

    def test_boolean_logic_preservation(self, decompiler):
        """Test that boolean logic produces same results."""
        sample_content = b"alpha beta gamma"
        sample_path = decompiler.tmp_dir / "bool_test.bin"
        sample_path.write_bytes(sample_content)

        source = '''
        rule has_alpha_and_beta {
            strings:
                $a = "alpha"
                $b = "beta"
            condition:
                $a and $b
        }

        rule has_alpha_or_delta {
            strings:
                $a = "alpha"
                $d = "delta"
            condition:
                $a or $d
        }

        rule not_has_delta {
            strings:
                $d = "delta"
            condition:
                not $d
        }

        rule complex_bool {
            strings:
                $a = "alpha"
                $b = "beta"
                $g = "gamma"
            condition:
                ($a and $b) or ($b and $g)
        }
        '''

        ok, original, _ = decompiler.compile_source(source)
        assert ok

        decompile_result = decompiler.decompile(original)
        assert decompile_result.success

        clean = decompiler.clean_decompiled_output(decompile_result.output)
        ok, recompiled, err = decompiler.compile_source(clean)
        assert ok, f"Recompile failed: {err}"

        orig_scan = decompiler.scan(original, sample_path)
        new_scan = decompiler.scan(recompiled, sample_path)

        assert orig_scan.matches == new_scan.matches, (
            f"Boolean logic mismatch:\n"
            f"Original: {orig_scan.matches}\n"
            f"Recompiled: {new_scan.matches}\n"
            f"Decompiled:\n{clean}"
        )

    def test_quantifier_preservation(self, decompiler):
        """Test that quantifiers (any of, all of, N of) work correctly."""
        sample_content = b"one two three four"
        sample_path = decompiler.tmp_dir / "quant_test.bin"
        sample_path.write_bytes(sample_content)

        source = '''
        rule any_of_test {
            strings:
                $a = "one"
                $b = "five"
            condition:
                any of them
        }

        rule all_of_test {
            strings:
                $a = "one"
                $b = "two"
            condition:
                all of them
        }

        rule two_of_test {
            strings:
                $a = "one"
                $b = "two"
                $c = "five"
            condition:
                2 of them
        }
        '''

        ok, original, _ = decompiler.compile_source(source)
        assert ok

        decompile_result = decompiler.decompile(original)
        assert decompile_result.success

        clean = decompiler.clean_decompiled_output(decompile_result.output)
        ok, recompiled, err = decompiler.compile_source(clean)
        assert ok, f"Recompile failed: {err}"

        orig_scan = decompiler.scan(original, sample_path)
        new_scan = decompiler.scan(recompiled, sample_path)

        assert orig_scan.matches == new_scan.matches
