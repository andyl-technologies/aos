# Darwin-hosted compiler smoke program for native execution qualification.
{
  pkgs,
  targetSystem ? "x86_64-darwin",
}: let
  darwin = import ../.. {
    system = pkgs.stdenv.buildPlatform.system;
    crossSystem = targetSystem;
  };
in
  darwin.pkgs.mkDerivation {
    pname = "darwin-dev-shell-native-compile-smoke";
    version = "0";
    src = null;
    runtimeDeps = [
      darwin.pkgs.bash
      darwin.pkgs.cc
      darwin.pkgs.coreutils
      darwin.pkgs.rust
    ];
    dontStrip = true;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cat > "$out/bin/aos-darwin-dev-shell-smoke" <<'SMOKE'
          #!${darwin.pkgs.bash}/bin/bash
          set -eu

          work=$(${darwin.pkgs.coreutils}/bin/mktemp -d /tmp/aos-dev-shell.XXXXXX)
          trap '${darwin.pkgs.coreutils}/bin/rm -rf "$work"' EXIT

          printf '%s\n' \
            'fn main() {' \
            '    println!("AOS Darwin native Rust smoke");' \
            '}' > "$work/main.rs"
          ${darwin.pkgs.rust}/bin/rustc \
            -C linker=${darwin.pkgs.cc}/bin/cc \
            "$work/main.rs" -o "$work/rust-smoke"
          "$work/rust-smoke"

          printf '%s\n' \
            'extern int puts(const char *);' \
            'int main(void) {' \
            '    return puts("AOS Darwin native C smoke") < 0;' \
            '}' > "$work/main.c"
          ${darwin.pkgs.cc}/bin/cc "$work/main.c" -o "$work/c-smoke"
          "$work/c-smoke"
          SMOKE
          chmod +x "$out/bin/aos-darwin-dev-shell-smoke"
        '';
      }
    ];
  }
