##! Exercises content-hash freshness for shared development Cargo targets.
##!
##! Every unpack gives source files new mtimes. The shared-target configure
##! phase must give unchanged files an old mtime, keep changed files newer
##! than earlier outputs, and keep files changed by a failed attempt dirty
##! until a build phase completes.
{pkgs}: let
  phaseTemplates = import ../../stdenv/phases.nix;
  vendor = pkgs.runCommand "cargo-cache-freshness-vendor" {} ''
    mkdir -p "$out"
  '';
  cargoPhases = phaseTemplates.cargoPhases {
    cargoDeps = vendor;
    cargoSourceId = "cache-freshness-fixture";
    cargoCacheLock = pkgs.util-linux;
    cargoRoot = "crates";
    cargoBuildCommands = ["build"];
    doCheck = false;
  };
  phaseScript = name:
    (builtins.head (builtins.filter (phase: phase.name == name) cargoPhases)).script;
  configure = phaseScript "configure";
  build = phaseScript "build";
in
  pkgs.mkDerivation {
    pname = "cargo-cache-freshness-check";
    version = "1";
    src = null;
    buildDeps = [pkgs.jq];
    phases = [
      {
        name = "check";
        script = ''
          export CARGO_TARGET_DIR="$TMPDIR/cache/target"
          mkdir -p "$CARGO_TARGET_DIR"
          source="$TMPDIR/source"
          checkTop="$NIX_BUILD_TOP"

          # The build phase only needs Cargo to succeed. Freshness is decided
          # entirely by the surrounding configure and commit logic.
          cargo() {
            :
          }

          # Each attempt starts from a fresh copy whose mtimes are all new,
          # as the ordinary unpack phase produces.
          unpack() {
            rm -rf "$source"
            mkdir -p "$source/crates/fixture/src" "$source/docs"
            printf '%s\n' "$1" > "$source/crates/fixture/src/lib.rs"
            printf '%s\n' 'fn main() {}' > "$source/crates/fixture/src/main.rs"
            printf '%s\n' "$2" > "$source/docs/included.md"
            cd "$source"
          }

          attempt() {
            unpack "$1" "$2"
            (${configure})
            cd "$source"
          }

          succeed() {
            (
              cd "$source/crates"
              ${build}
            )
          }

          mtime() {
            stat -c %Y "$source/$1"
          }

          expectOld() {
            if [ "$(mtime "$1")" != 1 ]; then
              echo "$1 should keep the old freshness mtime" >&2
              exit 1
            fi
          }

          expectNew() {
            if [ "$(mtime "$1")" = 1 ]; then
              echo "$1 should be newer than earlier outputs" >&2
              exit 1
            fi
          }

          # Without recorded state, every file is changed.
          attempt 'pub fn value() -> u8 { 1 }' 'first'
          expectNew crates/fixture/src/lib.rs
          expectNew crates/fixture/src/main.rs
          expectNew docs/included.md
          succeed
          test -s "$CARGO_TARGET_DIR/.aos-source-hashes"

          # An identical source keeps every unit fresh.
          attempt 'pub fn value() -> u8 { 1 }' 'first'
          expectOld crates/fixture/src/lib.rs
          expectOld crates/fixture/src/main.rs
          expectOld docs/included.md

          # A changed file, including one outside the Cargo root, is dirty.
          attempt 'pub fn value() -> u8 { 2 }' 'second'
          expectNew crates/fixture/src/lib.rs
          expectOld crates/fixture/src/main.rs
          expectNew docs/included.md

          # That attempt failed. Returning to the recorded bytes cannot make
          # units it may have compiled look fresh.
          attempt 'pub fn value() -> u8 { 1 }' 'first'
          expectNew crates/fixture/src/lib.rs
          expectOld crates/fixture/src/main.rs
          expectNew docs/included.md
          succeed
          test ! -e "$CARGO_TARGET_DIR/.aos-source-dirty"

          # A completed build clears the dirty set.
          attempt 'pub fn value() -> u8 { 1 }' 'first'
          expectOld crates/fixture/src/lib.rs
          expectOld docs/included.md

          # A new file has no recorded state and is dirty.
          unpack 'pub fn value() -> u8 { 1 }' 'first'
          printf '%s\n' 'pub fn extra() {}' > "$source/crates/fixture/src/extra.rs"
          (${configure})
          expectNew crates/fixture/src/extra.rs
          expectOld crates/fixture/src/lib.rs

          cd "$checkTop"
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
