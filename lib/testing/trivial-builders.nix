# lib/testing/trivial-builders.nix — Sanity checks for the trivial builders
# and derivation-path lib helpers landed in stage 1 of the systemd refactor.
#
# Exercises writeShellScriptBin (as the canonical user of writeTextFile),
# runCommand, runtimeShell, lib.getExe, lib.getExe' and lib.isDerivation.
# Runs at `nix-build -A checks.trivial-builders` and is surfaced through
# the top-level check set in ./default.nix.
#
# This is the stage-1 regression guard described in spec §9.1. Keep it
# lightweight: no host tools, no systemd, no module system — just the
# primitives themselves.
{
  pkgs,
  lib,
}: let
  # --- writeShellScriptBin + lib.getExe ------------------------------------
  #
  # Produces an executable at $out/bin/greeter whose meta.mainProgram is
  # "greeter", so lib.getExe resolves to "$out/bin/greeter" directly.
  greeter = pkgs.writeShellScriptBin "greeter" ''
    echo "hello from greeter: $1"
  '';

  greeterExe = lib.getExe greeter;

  # --- runCommand --------------------------------------------------------
  #
  # Verifies three properties simultaneously:
  #   (a) $out is auto-created by setup.sh (the body never runs `mkdir $out`).
  #   (b) coreutils / findutils are on PATH without being declared — they
  #       come from stdenv.initialPath being appended by mkDerivation.
  #   (c) No fixup phase runs: a plain text file with an accidental "ELF"
  #       marker in the name still passes through untouched, proving that
  #       stripDirs/patchShebangs are not invoked.
  rcArtifact =
    pkgs.runCommand "rc-artifact" {
      preferLocalBuild = true;
      allowSubstitutes = false;
    } ''
      # (a) $out pre-exists
      [ -d "$out" ] || { echo "FAIL: runCommand did not auto-create \$out"; exit 1; }

      # (b) tools from initialPath are visible
      command -v basename >/dev/null || { echo "FAIL: basename not on PATH"; exit 1; }
      command -v find     >/dev/null || { echo "FAIL: find not on PATH";     exit 1; }
      command -v ln       >/dev/null || { echo "FAIL: ln not on PATH";       exit 1; }
      command -v sed      >/dev/null || { echo "FAIL: sed not on PATH";      exit 1; }

      # (c) Write a file with contents that would upset a shebang/ELF patcher
      # if fixup ever ran. The `#!` is intentional.
      cat > "$out/marker" << 'MARKER'
      #!/usr/bin/env nonexistent-interpreter
      ELF\x01\x02\x03 not actually an elf
      MARKER

      ln -s marker "$out/marker-link"

      echo "rc-artifact: ok"
    '';

  # --- runtimeShell ------------------------------------------------------
  #
  # Confirms runtimeShell is a store-path string ending in /bin/bash.
  runtimeShellOk =
    lib.isString pkgs.runtimeShell
    && lib.hasPrefix "/nix/store/" pkgs.runtimeShell
    && lib.hasSuffix "/bin/bash" pkgs.runtimeShell;

  # --- isDerivation ------------------------------------------------------
  isDerivationChecks =
    lib.isDerivation greeter
    && lib.isDerivation rcArtifact
    && !lib.isDerivation "not a derivation"
    && !lib.isDerivation {type = "not a derivation";};

  # --- getExe / getExe' -------------------------------------------------
  #
  # greeter has meta.mainProgram = "greeter", so both helpers return the
  # same path for that binary. We also verify that getExe' accepts a
  # different binary name and substitutes it into the store path.
  getExeChecks =
    lib.getExe greeter
    == "${greeter}/bin/greeter"
    && lib.getExe' greeter "greeter"
    == "${greeter}/bin/greeter"
    && lib.getExe' greeter "alt-name"
    == "${greeter}/bin/alt-name";

  # Fail the whole check-set at eval time if any of these are false. This
  # means `nix-instantiate` catches regressions before the builder even
  # starts, matching the contract used by lib/testing/eval.nix.
  evalAssertions =
    lib.throwIfNot runtimeShellOk "trivial-builders: pkgs.runtimeShell is not a store-path bash"
    (lib.throwIfNot isDerivationChecks "trivial-builders: lib.isDerivation regressed"
      (lib.throwIfNot getExeChecks "trivial-builders: lib.getExe / getExe' regressed"
        true));
in
  # Wrap everything in a single derivation so users can say
  # `nix-build -A checks.trivial-builders` and get one result.
  pkgs.mkDerivation {
    pname = "trivial-builders-check";
    version = "0";
    src = null;

    # Pull both runtime artifacts into the closure so they get built.
    buildDeps = [
      greeter
      rcArtifact
    ];

    phases = [
      {
        name = "check";
        script = ''
          set -eu

          # Force the eval assertions to run (they short-circuit to `true`).
          : ${builtins.toString evalAssertions}

          echo "==> trivial-builders check"

          # Re-verify the runtime artifacts at build time (not just eval).
          test -x "${greeterExe}" \
            || { echo "FAIL: ${greeterExe} is not executable"; exit 1; }

          out="$("${greeterExe}" "world")"
          case "$out" in
            "hello from greeter: world") ;;
            *) echo "FAIL: unexpected greeter output: $out"; exit 1 ;;
          esac

          test -f "${rcArtifact}/marker" \
            || { echo "FAIL: rc-artifact/marker missing"; exit 1; }
          test -L "${rcArtifact}/marker-link" \
            || { echo "FAIL: rc-artifact/marker-link is not a symlink"; exit 1; }

          # Fixup-phase witness: the marker file still contains the bogus
          # shebang and ELF-ish bytes, unmolested.
          grep -q 'nonexistent-interpreter' "${rcArtifact}/marker" \
            || { echo "FAIL: marker file was rewritten (fixup phase ran?)"; exit 1; }

          echo "==> trivial-builders check passed."
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];

    meta.description = "Stage-1 sanity check for writeShellScriptBin / runCommand / lib.getExe";
  }
