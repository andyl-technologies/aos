##! Exercises target-hosted Rust compilation and offline Cargo inside Linux.
{
  rust,
  llvm ? null,
}:
assert !(rust ? dev) || llvm != null;
  ''
    export PATH=${rust}/bin:$PATH
    export CARGO_HOME=/tmp/cargo-home

    rustc -vV > rustc-version.txt
    grep -Fx 'host: aarch64-unknown-linux-gnu' rustc-version.txt
    cargo --version

    mkdir -p rust-workload/src
    cd rust-workload
    cat > Cargo.toml <<'MANIFEST'
    [package]
    name = "hosted-runtime"
    version = "0.1.0"
    edition = "2021"
    MANIFEST

    # Cargo must compile and execute a build script with the installed toolchain.
    cat > build.rs <<'SOURCE'
    fn main() {
        println!("cargo:rustc-env=HOSTED_BUILD_RESULT=42");
    }
    SOURCE

    cat > src/main.rs <<'SOURCE'
    use std::{fs, panic, thread};

    fn main() {
        let worker = thread::spawn(|| vec![19, 23].into_iter().sum::<i32>());
        let result = worker.join().expect("worker completes");
        assert_eq!(result.to_string(), env!("HOSTED_BUILD_RESULT"));

        // A caught panic exercises the installed unwinder without failing Cargo.
        assert!(panic::catch_unwind(|| panic!("expected unwind")).is_err());
        fs::write("runtime-result.txt", result.to_string()).expect("write result");
        assert_eq!(fs::read_to_string("runtime-result.txt").unwrap(), "42");
        println!("Rust runtime result: {result}");
    }
    SOURCE

    cargo build --offline
    test "$(./target/debug/hosted-runtime)" = 'Rust runtime result: 42'

    # Check rustc directly as well as Cargo's compiler and linker invocation.
    HOSTED_BUILD_RESULT=42 rustc --edition=2021 src/main.rs -o direct-runtime
    test "$(./direct-runtime)" = 'Rust runtime result: 42'

    # Procedural macros must load on the target and honor explicit source remapping.
    cat > qualification_macro.rs <<'SOURCE'
    extern crate proc_macro;

    #[proc_macro]
    pub fn answer(_: proc_macro::TokenStream) -> proc_macro::TokenStream {
        "42".parse().expect("valid expression")
    }
    SOURCE

    rustc --crate-name qualification_macro --crate-type proc-macro \
      --remap-path-prefix="$PWD=/rustc/qualification" \
      "$PWD/qualification_macro.rs" -o libqualification_macro.so
    if grep -a -Fq "$PWD" libqualification_macro.so; then
      echo 'Rust procedural macro retains its build directory' >&2
      exit 1
    fi

    cat > macro-consumer.rs <<'SOURCE'
    fn main() {
        assert_eq!(qualification_macro::answer!(), 42);
        println!("Rust procedural macro result: 42");
    }
    SOURCE
    rustc --edition=2021 --extern qualification_macro=libqualification_macro.so \
      macro-consumer.rs -o macro-consumer
    test "$(./macro-consumer)" = 'Rust procedural macro result: 42'

    printf 'fn main() { let value = ; }\n' > invalid.rs
    if rustc invalid.rs -o invalid-rust >invalid.stdout 2>invalid.stderr; then
      echo 'Rust accepted malformed source' >&2
      exit 1
    fi
    test -s invalid.stderr
    cd /tmp
  ''
  + (
    if rust ? dev
    then ''
      export PATH=${rust.dev}/bin:$PATH
      export RUST_SRC_PATH=${rust.dev}/lib/rustlib/src/rust/library
      test -s "$RUST_SRC_PATH/std/src/lib.rs"

      mkdir -p /tmp/developer-workload/src
      cd /tmp/developer-workload
      cat > Cargo.toml <<'MANIFEST'
      [package]
      name = "developer-workload"
      version = "0.1.0"
      edition = "2021"
      MANIFEST

      printf 'pub fn answer()->u32{42}\n' > src/lib.rs
      if cargo fmt --check > format-before.txt 2>&1; then
        echo 'rustfmt accepted the deliberately unformatted source' >&2
        exit 1
      fi
      cargo fmt
      cargo fmt --check
      grep -Fx 'pub fn answer() -> u32 {' src/lib.rs
      cargo clippy --offline -- --deny warnings

      # A denied lint proves Clippy executes its analysis, not only rustc.
      cp src/lib.rs valid-lib.rs
      cat > src/lib.rs <<'SOURCE'
      #![deny(clippy::eq_op)]
      pub fn same(value: u32) -> bool {
          value == value
      }
      SOURCE
      if cargo clippy --offline > clippy-invalid.txt 2>&1; then
        echo 'Clippy accepted the explicitly denied equality lint' >&2
        exit 1
      fi
      grep -Fq 'equal expressions as operands' clippy-invalid.txt
      mv valid-lib.rs src/lib.rs

      rustdoc --edition=2021 --crate-name developer_workload src/lib.rs -o docs
      test -s docs/developer_workload/fn.answer.html
      rust-analyzer parse < src/lib.rs > syntax-tree.txt
      grep -q '^SOURCE_FILE' syntax-tree.txt
      grep -Fq 'answer' syntax-tree.txt

      cat > wasm.rs <<'SOURCE'
      #[no_mangle]
      pub extern "C" fn qualification_answer() -> u32 {
          42
      }
      SOURCE
      rustc --edition=2021 --target wasm32-unknown-unknown --crate-type cdylib \
        wasm.rs -o qualification.wasm
      test "$(od -An -tx1 -N8 qualification.wasm | tr -d '[:space:]')" = 0061736d01000000

      # Exercise the profiler runtime with the matching LLVM dependency. The
      # Rust install's selected components do not include llvm-tools-preview.
      printf 'fn main() { println!("coverage result: 42"); }\n' > coverage.rs
      rustc -C instrument-coverage coverage.rs -o coverage-runtime
      test "$(LLVM_PROFILE_FILE=coverage.profraw ./coverage-runtime)" = 'coverage result: 42'
      llvm_tools=${llvm}/bin
      "$llvm_tools/llvm-profdata" merge -sparse coverage.profraw -o coverage.profdata
      "$llvm_tools/llvm-cov" report ./coverage-runtime \
        --instr-profile=coverage.profdata > coverage-report.txt
      grep -Fq 'coverage.rs' coverage-report.txt
      cd /tmp
    ''
    else ""
  )
