##! Real compiler invalidation and concurrent-reader/writer coverage.
{
  pkgs,
  lib,
  sccacheOracle ? import ./accache/sccache-oracle.nix {inherit pkgs;},
}: let
  compilers = {
    "${builtins.unsafeDiscardStringContext (toString pkgs.cc)}/bin/gcc" = "c";
    "${builtins.unsafeDiscardStringContext (toString pkgs.llvm)}/bin/clang" = "c";
    "${builtins.unsafeDiscardStringContext (toString pkgs.rust)}/bin/rustc" = "rust";
  };
  cacheEnvironment = pkgs.mkAccacheEnvironment {
    inherit compilers;
    roots = [pkgs.cc pkgs.llvm pkgs.rust];
    cacheDir = "/unused";
    stateDir = "/unused-state";
  };
in
  pkgs.mkDerivation {
    pname = "accache-integration-check";
    version = "1";
    src = null;
    sharedBuildCache = false;
    buildDeps = [pkgs.accache pkgs.cc pkgs.llvm pkgs.rust pkgs.python3 sccacheOracle];
    ACCACHE_MANIFEST = cacheEnvironment.ACCACHE_MANIFEST;
    phases = [
      {
        name = "check";
        script = ''
          ${pkgs.python3}/bin/python3 ${../../tools/accache/tests/integration.py} \
            ${pkgs.accache}/bin/accache ${pkgs.cc}/bin/gcc \
            ${pkgs.llvm}/bin/clang ${pkgs.rust}/bin/rustc
          ${pkgs.python3}/bin/python3 ${../../tools/accache/tests/frontend_integration.py} \
            ${pkgs.accache}/bin/accache ${pkgs.cc}/bin/gcc \
            ${pkgs.llvm}/bin/clang ${pkgs.rust}/bin/rustc
          mkdir -p "$out"
          ACCACHE_ORACLE_REPORT="$out/oracle.json" \
          ${pkgs.python3}/bin/python3 ${../../tools/accache/tests/oracle.py} \
            ${pkgs.accache}/bin/accache ${sccacheOracle}/bin/sccache \
            ${pkgs.cc}/bin/gcc ${pkgs.llvm}/bin/clang ${pkgs.rust}/bin/rustc
          mkdir -p "$out"
          printf 'passed\n' > "$out/result"
        '';
      }
    ];
  }
