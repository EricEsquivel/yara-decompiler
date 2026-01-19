"""
Pytest configuration and shared fixtures for YARA decompiler tests.
"""
import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List

import pytest

# Paths relative to repo root
REPO_ROOT = Path(__file__).parent.parent
DECOMPILER_BIN = REPO_ROOT / "yara-decompiler"
# Look for yarac/yara - prioritize project's compiled version
def find_yara_binary(name):
    # Check parent yara directory first (the project's compiled version)
    parent_yara = REPO_ROOT.parent / name
    if parent_yara.exists():
        return str(parent_yara)
    # Check sibling .libs directory
    libs_path = REPO_ROOT.parent / ".libs" / name
    if libs_path.exists():
        return str(libs_path)
    # Fall back to PATH
    found = shutil.which(name)
    if found:
        return found
    return name  # Fall back to name, will fail if not found

YARAC_BIN = find_yara_binary("yarac")
YARA_BIN = find_yara_binary("yara")

FIXTURES_DIR = Path(__file__).parent / "fixtures"
RULES_DIR = FIXTURES_DIR / "rules"
SAMPLES_DIR = FIXTURES_DIR / "samples"


@dataclass
class DecompileResult:
    """Result of a decompilation operation."""
    success: bool
    output: str
    error: str
    returncode: int


@dataclass
class RoundtripResult:
    """Result of a full roundtrip test."""
    success: bool
    original_compiled: Optional[Path]
    decompiled_source: str
    recompiled: Optional[Path]
    compile_error: str
    decompile_error: str
    recompile_error: str


@dataclass
class ScanResult:
    """Result of scanning a file with YARA rules."""
    matches: List[str]
    returncode: int
    error: str


class Decompiler:
    """Helper class for decompiler operations."""

    def __init__(self, binary_path: Path, yarac_path: str, yara_path: str):
        self.binary = binary_path
        self.yarac = yarac_path
        self.yara = yara_path
        self._tmp_dir = None

    @property
    def tmp_dir(self) -> Path:
        if self._tmp_dir is None:
            self._tmp_dir = Path(tempfile.mkdtemp(prefix="yara_decompiler_test_"))
        return self._tmp_dir

    def cleanup(self):
        if self._tmp_dir and self._tmp_dir.exists():
            shutil.rmtree(self._tmp_dir)
            self._tmp_dir = None

    def compile_rule(self, rule_path: Path, output_path: Optional[Path] = None) -> tuple[bool, Path, str]:
        """Compile a YARA rule file."""
        if output_path is None:
            output_path = self.tmp_dir / f"{rule_path.stem}.compiled"

        result = subprocess.run(
            [self.yarac, str(rule_path), str(output_path)],
            capture_output=True,
            text=True
        )
        return result.returncode == 0, output_path, result.stderr

    def compile_source(self, source: str, output_path: Optional[Path] = None) -> tuple[bool, Path, str]:
        """Compile YARA source code from string."""
        source_path = self.tmp_dir / "temp_rule.yar"
        source_path.write_text(source)
        return self.compile_rule(source_path, output_path)

    def decompile(self, compiled_path: Path) -> DecompileResult:
        """Decompile a compiled YARA binary."""
        result = subprocess.run(
            [str(self.binary), str(compiled_path)],
            capture_output=True,
            text=True
        )
        return DecompileResult(
            success=result.returncode == 0,
            output=result.stdout,
            error=result.stderr,
            returncode=result.returncode
        )

    def clean_decompiled_output(self, output: str) -> str:
        """Remove internal comments from decompiled output."""
        lines = [l for l in output.splitlines() if not l.strip().startswith("//")]
        return "\n".join(lines)

    def roundtrip(self, rule_path: Path) -> RoundtripResult:
        """Perform full roundtrip: compile -> decompile -> recompile."""
        result = RoundtripResult(
            success=False,
            original_compiled=None,
            decompiled_source="",
            recompiled=None,
            compile_error="",
            decompile_error="",
            recompile_error=""
        )

        # Step 1: Compile original
        ok, compiled_path, err = self.compile_rule(rule_path)
        if not ok:
            result.compile_error = err
            return result
        result.original_compiled = compiled_path

        # Step 2: Decompile
        decompile_result = self.decompile(compiled_path)
        if not decompile_result.success:
            result.decompile_error = decompile_result.error
            return result

        result.decompiled_source = self.clean_decompiled_output(decompile_result.output)

        # Step 3: Recompile
        recompiled_path = self.tmp_dir / f"{rule_path.stem}.recompiled"
        ok, recompiled_path, err = self.compile_source(result.decompiled_source, recompiled_path)
        if not ok:
            result.recompile_error = err
            return result

        result.recompiled = recompiled_path
        result.success = True
        return result

    def scan(self, compiled_rules: Path, target_file: Path) -> ScanResult:
        """Scan a file with compiled YARA rules."""
        result = subprocess.run(
            [self.yara, "-C", str(compiled_rules), str(target_file)],
            capture_output=True,
            text=True
        )
        matches = [line.split()[0] for line in result.stdout.strip().splitlines() if line]
        return ScanResult(
            matches=sorted(matches),
            returncode=result.returncode,
            error=result.stderr
        )


@pytest.fixture(scope="session")
def decompiler():
    """Provide a Decompiler instance for the test session."""
    if not DECOMPILER_BIN.exists():
        pytest.skip(f"Decompiler binary not found at {DECOMPILER_BIN}. Run 'make' first.")

    d = Decompiler(DECOMPILER_BIN, YARAC_BIN, YARA_BIN)
    yield d
    d.cleanup()


@pytest.fixture
def tmp_path_decompiler(decompiler, tmp_path):
    """Provide a decompiler with a test-specific temp directory."""
    decompiler._tmp_dir = tmp_path
    return decompiler


def collect_rule_files(*dirs: Path) -> List[Path]:
    """Collect all .yar files from given directories recursively."""
    files = []
    for d in dirs:
        if d.exists():
            files.extend(d.rglob("*.yar"))
    return sorted(files)


def pytest_generate_tests(metafunc):
    """Generate test parameters for parametrized tests."""
    if "rule_file" in metafunc.fixturenames:
        # Collect all rule files recursively from RULES_DIR
        all_rules = collect_rule_files(RULES_DIR)
        ids = [str(f.relative_to(FIXTURES_DIR)) for f in all_rules]
        metafunc.parametrize("rule_file", all_rules, ids=ids)

    if "sample_file" in metafunc.fixturenames:
        samples = list(SAMPLES_DIR.glob("*")) if SAMPLES_DIR.exists() else []
        ids = [f.name for f in samples]
        metafunc.parametrize("sample_file", samples, ids=ids)


# Test markers
def pytest_configure(config):
    config.addinivalue_line("markers", "slow: marks tests as slow")
    config.addinivalue_line("markers", "semantic: marks semantic equivalence tests")
    config.addinivalue_line("markers", "golden: marks golden file comparison tests")

def pytest_addoption(parser):
    """Add custom command line options."""
    try:
        parser.addoption(
            "--generate-golden",
            action="store_true",
            default=False,
            help="Generate golden files instead of comparing against them"
        )
    except ValueError:
        # Option already added
        pass
