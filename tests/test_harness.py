import os
import subprocess
import sys
import shutil

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

DECOMPILER_BIN = "./yara-decompiler/yara-decompiler"
YARAC_BIN = "./yarac"
TEST_DIR = "yara-decompiler/tests/stress_suite"
TMP_DIR = "/tmp/yara_decompiler_tests"

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result

def test_file(file_path):
    print(f"{Colors.BOLD}Testing {file_path}...{Colors.ENDC}")
    
    # 1. Compile original
    compiled_orig = os.path.join(TMP_DIR, "original.compiled")
    res = run_cmd(f"{YARAC_BIN} {file_path} {compiled_orig}")
    if res.returncode != 0:
        print(f"  {Colors.FAIL}FAIL: Original rule failed to compile{Colors.ENDC}")
        print(res.stderr)
        return False

    # 2. Decompile
    decompiled_yar = os.path.join(TMP_DIR, "decompiled.yar")
    res = run_cmd(f"{DECOMPILER_BIN} {compiled_orig}")
    if res.returncode != 0:
        print(f"  {Colors.FAIL}FAIL: Decompiler crashed{Colors.ENDC}")
        print(res.stderr)
        return False
    
    with open(decompiled_yar, "w") as f:
        # Strip internal comments for re-compilation
        lines = [l for l in res.stdout.splitlines() if not l.strip().startswith("//")]
        f.write("\n".join(lines))

    # 3. Re-compile
    recompiled_bin = os.path.join(TMP_DIR, "recompiled.compiled")
    res = run_cmd(f"{YARAC_BIN} {decompiled_yar} {recompiled_bin}")
    if res.returncode != 0:
        print(f"  {Colors.FAIL}FAIL: Decompiled output is invalid YARA syntax{Colors.ENDC}")
        # Print actual decompiled output for debugging
        print(f"{Colors.WARNING}--- DECOMPILED OUTPUT ---{Colors.ENDC}")
        print("\n".join(lines))
        print(f"{Colors.WARNING}--- COMPILER ERROR ---{Colors.ENDC}")
        print(res.stderr)
        return False

    print(f"  {Colors.OKGREEN}PASS: Round-trip successful{Colors.ENDC}")
    return True

def main():
    if not os.path.exists(TMP_DIR):
        os.makedirs(TMP_DIR)

    if not os.path.exists(DECOMPILER_BIN):
        print(f"{Colors.FAIL}Decompiler binary not found. Run make first.{Colors.ENDC}")
        sys.exit(1)

    files = [os.path.join(TEST_DIR, f) for f in os.listdir(TEST_DIR) if f.endswith(".yar")]
    
    total = len(files)
    passed = 0

    for f in files:
        if test_file(f):
            passed += 1

    print("\n" + "="*40)
    print(f"{Colors.BOLD}Results: {passed}/{total} tests passed{Colors.ENDC}")
    print("="*40)

    if passed < total:
        sys.exit(1)

if __name__ == "__main__":
    main()
