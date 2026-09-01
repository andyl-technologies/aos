##! pyrefly — Meta's fast type checker and IDE for Python (Rust)
{
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
  fakeHash,
  jemalloc,
  stdenv,
}: let
  version = "0.64.0";

  src = fetchurl {
    urls = [
      "https://github.com/facebook/pyrefly/archive/refs/tags/${version}.tar.gz"
    ];
    hash = "sha256-9NHewnrEedEQzNjBy6keR2KgKQWCMY5Cx6hdb36KL+8=";
  };

  # tikv-jemalloc-sys consumes JEMALLOC_OVERRIDE pointing at a libjemalloc
  # built with the _rjem_ symbol prefix so the allocator doesn't clash with
  # glibc's malloc. Matches nixpkgs's rust-jemalloc-sys overrideAttrs.
  jemallocRust = jemalloc.overrideAttrs (old: {
    pname = "jemalloc-rust";
    phases =
      builtins.map (
        p:
          if p.name == "configure"
          then {
            name = "configure";
            # jemalloc links its C++ shim through CC and otherwise leaves the
            # Darwin libc++ ABI symbols unresolved.
            script =
              if stdenv.hostPlatform.isDarwin
              then ''
                export LDFLAGS="-lc++ -lc++abi -lunwind"
                ./configure \
                  --prefix=$out \
                  --build=${stdenv.buildPlatform.config} \
                  --host=${stdenv.hostPlatform.config} \
                  --enable-shared \
                  --enable-static \
                  --with-private-namespace=_rjem_ \
                  --with-jemalloc-prefix=_rjem_
              ''
              else ''
                ./configure \
                  --prefix=$out \
                  --enable-shared \
                  --enable-static \
                  --with-private-namespace=_rjem_ \
                  --with-jemalloc-prefix=_rjem_
              '';
          }
          else p
      )
      old.phases;
    checks = null;
  });
in
  mkCargoPackage {
    pname = "pyrefly";
    inherit version src;

    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "pyrefly-vendor-${version}";
      hash = "sha256-g89nMkMsLAVpgfPZ1tRghRq2lcDwzVxzbM2Kum08p1I=";
    };

    # Workspace has many crates; we only want the pyrefly binary.
    cargoFlags = "-p pyrefly";
    doCheck = false;

    # pyrefly's 0.64.0 source uses several rust features that are still
    # nightly-only on our stable rust 1.93.1 (the rust-toolchain.toml pins
    # nightly-2026-02-28). RUSTC_BOOTSTRAP=1 unlocks them but the crates
    # still need explicit #![feature(...)] declarations.
    postPatch = ''
      for f in crates/*/src/lib.rs pyrefly/lib/lib.rs pyrefly/bin/main.rs; do
        [ -f "$f" ] || continue
        sed -i '1i\#![feature(if_let_guard)]' "$f"
      done
    '';

    # tikv-jemalloc-sys' build.rs skips its bundled build when JEMALLOC_OVERRIDE
    # is set, linking directly against our jemallocRust libjemalloc_pic.a.
    JEMALLOC_OVERRIDE = "${jemallocRust}/lib/libjemalloc_pic.a";
    # pyrefly relies on a handful of nightly-only rust features.
    # RUSTC_BOOTSTRAP is the same escape hatch rustc uses to bootstrap itself —
    # it lets stable rustc enable nightly features for this build only.
    RUSTC_BOOTSTRAP = "1";

    meta = {
      description = "pyrefly — fast type checker and IDE for Python";
      homepage = "https://github.com/facebook/pyrefly";
      license = "MIT";
      mainProgram = "pyrefly";
    };
  }
