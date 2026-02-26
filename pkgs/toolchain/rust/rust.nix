##! Rust — the Rust programming language, built from source
{
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
  pkg-config,
  python3,
  bash,
  which,
  llvm,
  rust-1_92,
  openssl,
  zlib,
}: let
  version = "1.93.1";
in
  mkDerivation {
    pname = "rust";
    inherit version;

    src = fetchurl {
      urls = [
        "https://static.rust-lang.org/dist/rustc-${version}-src.tar.gz"
      ];
      hash = "sha256-TCMKRLPZyfPO+VCUNxn4OABY0nyR/aXjapqUfvAT4B8=";
    };

    buildDeps = [
      gnumake
      cmake
      ninja
      pkg-config
      python3
      bash
      which
      rust-1_92
      llvm
      openssl
    ];
    runtimeDeps = [
      llvm
      zlib
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd rustc-${version}-src
        '';
      }
      {
        name = "configure";
        script = ''
          # Create a fake git wrapper so x.py doesn't panic when running git commands
          mkdir -p .fake-bin
          printf '#!/bin/sh\nexit 0\n' > .fake-bin/git
          chmod +x .fake-bin/git
          export PATH="$PWD/.fake-bin:$PATH"
          cat > bootstrap.toml << TOML
          change-id = 148795

          [llvm]
          link-shared = true
          download-ci-llvm = false

          [build]
          docs = false
          extended = true
          tools = ["cargo"]
          vendor = true
          cargo = "${rust-1_92}/bin/cargo"
          rustc = "${rust-1_92}/bin/rustc"

          [install]
          prefix = "$out"
          sysconfdir = "etc"

          [rust]
          channel = "stable"
          codegen-units = 0
          rpath = true
          omit-git-hash = true
          download-rustc = false

          [target.x86_64-unknown-linux-gnu]
          llvm-config = "${llvm}/bin/llvm-config"

          [target.aarch64-unknown-linux-gnu]
          llvm-config = "${llvm}/bin/llvm-config"
          TOML
        '';
      }
      {
        name = "build";
        script = ''
          export PATH="$PWD/.fake-bin:$PATH"
          python3 x.py build -j $NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          export PATH="$PWD/.fake-bin:$PATH"
          python3 x.py install

          # Patch ELF binaries
          INTERP=$(patchelf --print-interpreter $(which bash))
          BT_LIB=$(dirname "$INTERP")
          for f in $out/bin/*; do
            if [ -f "$f" ] && [ ! -L "$f" ]; then
              patchelf --set-interpreter "$INTERP" --set-rpath "$out/lib:${llvm}/lib:${openssl}/lib:${zlib}/lib:$BT_LIB" "$f" 2>/dev/null || true
            fi
          done
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      hello = testing.mkVMTest {
        name = "toolchain-rust-hello";
        rootfsDeps = [self];
        memory = 512;
        testScript = ''
          cat > /tmp/hello.rs << 'EOF'
          fn main() {
              let v: Vec<i32> = vec![3, 1, 4, 1, 5];
              let sum: i32 = v.iter().sum();
              println!("rust-sum={}", sum);
          }
          EOF

          rustc --edition 2021 -o /tmp/hello /tmp/hello.rs
          /tmp/hello
        '';
      };

      cargo = testing.mkVMTest {
        name = "toolchain-rust-cargo";
        rootfsDeps = [self];
        memory = 512;
        testScript = ''
          export CARGO_HOME="/tmp/cargo"
          mkdir -p "$CARGO_HOME"

          mkdir -p /tmp/myproject/src
          cat > /tmp/myproject/Cargo.toml << 'EOF'
          [package]
          name = "myproject"
          version = "0.1.0"
          edition = "2021"
          EOF

          cat > /tmp/myproject/src/main.rs << 'EOF'
          use std::collections::HashMap;
          fn main() {
              let mut map = HashMap::new();
              map.insert("a", 1);
              map.insert("b", 2);
              let total: i32 = map.values().sum();
              println!("cargo-ok={}", total);
          }
          EOF

          cd /tmp/myproject
          cargo build --release 2>&1
          ./target/release/myproject
        '';
      };

      bootstrap-chain = testing.mkVMTest {
        name = "toolchain-rust-bootstrap-chain";
        rootfsDeps = [self];
        memory = 512;
        testScript = ''
          # Verify rustc and cargo versions
          rustc --version
          cargo --version

          # Compile a non-trivial program using multiple std features
          cat > /tmp/chain_test.rs << 'EOF'
          use std::collections::BTreeMap;
          use std::io::Write;

          fn main() {
              let mut map = BTreeMap::new();
              for i in 0..10 {
                  map.insert(i, i * i);
              }
              let mut buf = Vec::new();
              for (k, v) in &map {
                  write!(buf, "{}:{} ", k, v).unwrap();
              }
              let s = String::from_utf8(buf).unwrap();
              assert!(s.contains("9:81"));
              println!("bootstrap-chain-ok");
          }
          EOF

          rustc --edition 2021 -o /tmp/chain_test /tmp/chain_test.rs
          /tmp/chain_test
        '';
      };

      build = testing.mkVMTest {
        name = "cross-cutting-rust-build";
        rootfsDeps = [self];
        memory = 512;
        testScript = ''
          export PATH="${self}/bin:$PATH"
          export LD_LIBRARY_PATH="${self}/lib:$LD_LIBRARY_PATH"

          cat > /tmp/hello.rs << 'EOF'
          fn fibonacci(n: u64) -> u64 {
              match n {
                  0 => 0,
                  1 => 1,
                  _ => fibonacci(n - 1) + fibonacci(n - 2),
              }
          }

          fn main() {
              println!("Hello from Rust");
              let result = fibonacci(10);
              assert_eq!(result, 55, "fibonacci(10) should be 55");
              println!("fibonacci(10) = {}", result);
              println!("Rust build integration: PASS");
          }
          EOF

          echo "==> Compiling Rust program"
          rustc -o /tmp/hello /tmp/hello.rs
          echo "==> Running Rust program"
          /tmp/hello
        '';
      };

      ffi = testing.mkVMTest {
        name = "cross-cutting-rust-ffi";
        rootfsDeps = [
          self
          pkgs.zlib
        ];
        memory = 512;
        testScript = ''
          export PATH="${self}/bin:$PATH"
          export LD_LIBRARY_PATH="${self}/lib:${pkgs.zlib}/lib:$LD_LIBRARY_PATH"
          export LIBRARY_PATH="${pkgs.zlib}/lib:$LIBRARY_PATH"

          cat > /tmp/zlib_ffi.rs << 'EOF'
          use std::ffi::CStr;
          use std::os::raw::c_char;

          extern "C" {
              fn zlibVersion() -> *const c_char;
          }

          fn main() {
              let version = unsafe {
                  let ptr = zlibVersion();
                  CStr::from_ptr(ptr).to_str().expect("invalid UTF-8")
              };
              println!("zlib version from Rust FFI: {}", version);
              assert!(!version.is_empty(), "zlibVersion() returned empty string");
              println!("Rust FFI: PASS");
          }
          EOF

          echo "==> Compiling Rust FFI program"
          rustc -o /tmp/zlib_ffi /tmp/zlib_ffi.rs -L ${pkgs.zlib}/lib -lz
          echo "==> Running Rust FFI program"
          /tmp/zlib_ffi
        '';
      };
    };

    meta = {
      description = "Rust programming language — compiler and cargo";
      homepage = "https://www.rust-lang.org";
      license = "MIT OR Apache-2.0";
    };
  }
