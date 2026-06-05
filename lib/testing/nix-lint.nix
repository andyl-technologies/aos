##! lib/testing/nix-lint.nix — Hermeticity & convention linter for `.nix` files.
##!
##! Formatting is handled separately by `checks.format` (alejandra). This
##! check enforces the *semantic* invariants from AGENTS.md that a
##! formatter cannot: no nixpkgs, no NIX_PATH lookups, no host-tool
##! shebangs, no `hostTools`. It is the build behind `aos lint`.
##!
##! The linter is itself hermetic — it greps the source tree using only
##! the AOS-built coreutils/grep/findutils, never host tools.
##!
##! Usage:
##!   nix-build -A checks.lint
{
  pkgs,
  lib,
}: let
  # Only the Nix sources are inputs, so edits to packages/docs/Rust don't
  # invalidate this check. `stdenv/bootstrap/` is excluded: it is the one
  # place where the sandbox `/bin/sh` is the only available shell (see
  # AGENTS.md), so its files legitimately contain bare interpreter paths.
  src = builtins.path {
    name = "aos-nix-sources";
    path = ../..;
    filter = path: type: let
      base = baseNameOf path;
      p = toString path;
    in
      base
      != ".git"
      && base != "target"
      && base != "result"
      && base != ".direnv"
      && base != ".claude"
      # Drop the stdenv/bootstrap directory entirely (children are never
      # walked once the directory is excluded).
      && builtins.match ".*/stdenv/bootstrap" p == null
      && (type == "directory" || lib.hasSuffix ".nix" base);
  };

  # Each rule: a human label, an ERE pattern forbidden in `.nix` files, and
  # the reason shown when it fires. Patterns are matched with `grep -E`.
  rules = [
    {
      label = "nixpkgs-angle-import";
      pattern = "<nixpkgs[/>]";
      reason = "AOS is built entirely from source; nixpkgs must never be imported.";
    }
    {
      label = "nix-path-lookup";
      pattern = "import[[:space:]]+<";
      reason = "Angle-bracket (<...>) imports depend on NIX_PATH and break hermeticity.";
    }
    {
      label = "nixpkgs-input";
      pattern = "(inputs|builtins\\.getFlake)[^;]*nixpkgs";
      reason = "No nixpkgs flake input is permitted anywhere in the tree.";
    }
    {
      label = "host-tools";
      pattern = "hostTools";
      reason = "The hostTools pattern is forbidden — build the dependency as an AOS package.";
    }
    {
      label = "env-shebang";
      pattern = "/usr/bin/env";
      reason = "Use the AOS-built shell/interpreter explicitly, not /usr/bin/env.";
    }
  ];

  ruleScript = builtins.concatStringsSep "\n" (
    builtins.map (
      r: ''
        echo "==> rule: ${r.label}"
        if grep -RInE -- '${r.pattern}' --include='*.nix' source > "$TMPDIR/hits" 2>/dev/null && [ -s "$TMPDIR/hits" ]; then
          echo "FAIL [${r.label}]: ${r.reason}"
          echo "Offending lines:"
          cat "$TMPDIR/hits"
          echo ""
          failed=1
        fi
      ''
    )
    rules
  );
in
  pkgs.mkDerivation {
    pname = "aos-nix-lint";
    version = "0.1.0";
    inherit src;

    buildDeps = [pkgs.grep pkgs.findutils pkgs.coreutils];

    dontStrip = true;
    dontPatchELF = true;

    phases = [
      {
        name = "unpack";
        script = ''
          cp -r "$src" source
          chmod -R u+w source
        '';
      }
      {
        name = "check";
        script = ''
          failed=0
          ${ruleScript}
          if [ "$failed" -ne 0 ]; then
            echo ""
            echo "==> nix-lint FAILED — fix the violations above."
            exit 1
          fi
          echo "==> nix-lint passed: no convention violations."
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          echo "nix-lint: passed" > "$out/result"
        '';
      }
    ];

    meta = {
      description = "AOS Nix hermeticity & convention linter (aos lint)";
    };
  }
