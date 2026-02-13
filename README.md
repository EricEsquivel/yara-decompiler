# YARA Decompiler

A tool to decompile compiled YARA rules (`.yarc` files) back into human-readable YARA source. Compatible with YARA 4.1.0+.

## Build Instructions

1.  **Clone with submodules:**
    ```bash
    git clone --recursive https://github.com/YOUR_USERNAME/yara-decompiler.git
    cd yara-decompiler
    ```

2.  **Build YARA dependency:**
    ```bash
    cd yara
    ./bootstrap.sh
    ./configure
    make
    cd ..
    ```

3.  **Build Decompiler:**
    ```bash
    make
    ```

## Usage

```bash
# Decompile to source
./yara-decompiler <compiled_rules_file>

# Disassemble to bytecode
./yara-decompiler --disassemble <compiled_rules_file>
```

## Testing

1.  **Setup:**
    ```bash
    python3 -m venv tests/venv
    source tests/venv/bin/activate
    pip install pytest
    ```

2.  **Run:**
    ```bash
    pytest tests
    ```
