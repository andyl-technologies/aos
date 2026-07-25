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

    # $out is the lean production toolchain (rustc + cargo + std) that every
    # cargo package links against. $dev carries the developer tooling
    # (clippy, rustfmt, rust-analyzer) and the std source — only realized when
    # something references rust.dev (e.g. the dev shell), so it stays out of
    # the build closure of ordinary cargo packages.
    outputs = ["out" "dev"];

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
      openssl
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
          # Fix arc4random: cmake detects it in glibc but the header doesn't declare it
          sed -i 's/check_symbol_exists(arc4random "stdlib.h" HAVE_DECL_ARC4RANDOM)/set(HAVE_DECL_ARC4RANDOM 0 CACHE BOOL "")/' \
            src/llvm-project/llvm/cmake/config-ix.cmake 2>/dev/null || true

          # Fake git — must return exit 1 to avoid canonicalize("") panic
          mkdir -p .fake-bin
          printf '#!/bin/sh\nexit 1\n' > .fake-bin/git
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
          tools = ["cargo", "rustdoc", "clippy", "rustfmt", "rust-analyzer", "src"]
          vendor = true
          cargo = "${rust-1_92}/bin/cargo"
          rustc = "${rust-1_92}/bin/rustc"
          # Build std for the native host plus the bare wasm32 target. The
          # wasm32-unknown-unknown std (core + alloc, with the wasm shims; it
          # has no full libstd, which is expected) lets cargo cross-compile the
          # aos-registry-worker crate to a Cloudflare Worker hermetically.
          target = ["x86_64-unknown-linux-gnu", "wasm32-unknown-unknown"]

          [install]
          prefix = "$out"
          sysconfdir = "etc"

          [rust]
          channel = "stable"
          codegen-units = 0
          rpath = true
          omit-git-hash = true
          download-rustc = false
          # `lld = false`: x.py refuses `rust.lld = true` when configured with an
          # external `llvm-config` (it has no bundled llvm-project to build lld
          # from). The wasm32-unknown-unknown target nonetheless needs `rust-lld`
          # (wasm has no system linker), so the install phase symlinks it from
          # the AOS LLVM's own `lld` driver instead. `use-lld = false` keeps the
          # host (x86_64) target on GCC's `ld` — rust-lld as the default host
          # linker chokes on the zlib-compressed debug sections in GCC 14's
          # libgcc.a.
          lld = false
          use-lld = false

          [target.x86_64-unknown-linux-gnu]
          llvm-config = "${llvm}/bin/llvm-config"

          [target.aarch64-unknown-linux-gnu]
          llvm-config = "${llvm}/bin/llvm-config"

          # The bare wasm32 target needs no external C toolchain or llvm-config;
          # rustc's own LLVM backend emits the wasm directly. Use the pure-Rust
          # compiler-builtins (not the optimized C source), so x.py does not
          # demand Clang to cross-compile compiler-rt C for wasm — we only ship
          # gcc as the host cc, which x.py rejects for wasm C builds.
          [target.wasm32-unknown-unknown]
          optimized-compiler-builtins = false
          TOML
        '';
      }
      {
        name = "build";
        script = ''
          export PATH="$PWD/.fake-bin:$PATH"
          export OPENSSL_DIR=${openssl}
          export OPENSSL_LIB_DIR=${openssl}/lib
          export OPENSSL_INCLUDE_DIR=${openssl}/include
          export OPENSSL_NO_VENDOR=1
          export OPENSSL_STATIC=0
          python3 x.py build -j $NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
                  export PATH="$PWD/.fake-bin:$PATH"
                  export OPENSSL_DIR=${openssl}
                  export OPENSSL_LIB_DIR=${openssl}/lib
                  export OPENSSL_INCLUDE_DIR=${openssl}/include
                  export OPENSSL_NO_VENDOR=1
                  export OPENSSL_STATIC=0
                  # Installs the default extended set selected by `tools` —
                  # including the rust-src component ("src" in tools), consumed
                  # by rust-analyzer via RUST_SRC_PATH. NOT a separate
                  # `x.py install src`: that treats "src" as a path filter,
                  # matches a docs step, and panics on the absent doc dir
                  # (docs = false).
                  python3 x.py install

                  # Supply `rust-lld` for wasm32-unknown-unknown. rustc links the
                  # bare wasm target with the self-contained `rust-lld` found at
                  # lib/rustlib/<host>/bin/rust-lld, invoked as `rust-lld -flavor
                  # wasm` — but x.py cannot build rust-lld against an external
                  # llvm-config (see [rust] lld above). The AOS LLVM ships the
                  # universal `lld` driver, which dispatches on `-flavor wasm`
                  # exactly like wasm-ld, so point rust-lld at it. Without this,
                  # `cargo build --target wasm32-unknown-unknown` fails with
                  # "linker `rust-lld` not found".
                  RUSTLIB_BIN="$out/lib/rustlib/x86_64-unknown-linux-gnu/bin"
                  mkdir -p "$RUSTLIB_BIN"
                  ln -sf ${llvm}/bin/lld "$RUSTLIB_BIN/rust-lld"

                  # No patchelf available — use wrapper scripts
                  LIB_PATH="$out/lib:$out/lib/rustlib/x86_64-unknown-linux-gnu/lib:${llvm}/lib:${openssl}/lib:${zlib}/lib"

                  for f in $out/bin/*; do
                    if [ -f "$f" ] && [ ! -L "$f" ]; then
                      if head -c4 "$f" | grep -q "ELF"; then
                        mv "$f" "$f.unwrapped"
                        cat > "$f" <<WRAP
          #!/bin/sh
          export LD_LIBRARY_PATH="$LIB_PATH''${LD_LIBRARY_PATH:+:}''${LD_LIBRARY_PATH:-}"
          exec "$f.unwrapped" "\$@"
          WRAP
                        chmod +x "$f"
                      elif head -1 "$f" | grep -q '^#!'; then
                        sed -i "s|LD_LIBRARY_PATH=\"[^\"]*\"|LD_LIBRARY_PATH=\"$LIB_PATH\"|" "$f"
                      fi
                    fi
                  done

                  # ── Split developer tooling into the $dev output ──────────
                  # clippy / rustfmt / rust-analyzer and the std source are
                  # only needed in the dev shell — not by the cargo builds that
                  # link $out — so they move to $dev to keep $out lean. Each
                  # binary was wrapped above with $out/lib (where
                  # librustc_driver lives) on LD_LIBRARY_PATH; moving the
                  # wrapper means rewriting the baked .unwrapped path to its
                  # new $dev location. rustc, cargo and rustdoc stay in $out.
                  mkdir -p $dev/bin
                  for t in cargo-clippy clippy-driver cargo-fmt rustfmt rust-analyzer; do
                    [ -e "$out/bin/$t" ] || continue
                    mv "$out/bin/$t" "$dev/bin/$t"
                    if [ -e "$out/bin/$t.unwrapped" ]; then
                      mv "$out/bin/$t.unwrapped" "$dev/bin/$t.unwrapped"
                      sed -i "s|$out/bin/$t.unwrapped|$dev/bin/$t.unwrapped|" "$dev/bin/$t"
                    fi
                  done

                  # rust-src installs the std source under the sysroot; relocate
                  # it to $dev so it is not dragged into every $out consumer.
                  if [ -d "$out/lib/rustlib/src" ]; then
                    mkdir -p $dev/lib/rustlib
                    mv "$out/lib/rustlib/src" "$dev/lib/rustlib/src"
                  fi
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
