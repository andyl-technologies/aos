# lib/testing/checks.nix — Composable check module system
#
# Provides primitives for building reusable, composable test checks that
# can be shared across VM tests. Checks are shell script fragments with
# metadata (name, description, tags) that get composed into full test scripts.
#
# Primitives:
#   mkCheck      — Create a single named check
#   mkCheckGroup — Group checks under a common prefix
#   flattenChecks — Flatten nested check groups into a flat list
#   composeChecks — Flatten + wrap each check with echo banners
#   validateChecks — Write checks to temp files and run sh -n syntax check
let
  # Flatten nested check groups into a flat list of { path, check } records.
  flattenChecks = let
    go = prefix: items:
      builtins.concatMap (
        item:
          if item._type == "check"
          then [
            {
              path =
                if prefix == ""
                then item.name
                else "${prefix}/${item.name}";
              check = item;
            }
          ]
          else if item._type == "checkGroup"
          then
            go (
              if prefix == ""
              then item.name
              else "${prefix}/${item.name}"
            )
            item.checks
          else throw "Unknown check type: ${item._type or "null"}"
      )
      items;
  in
    checks: go "" checks;
in {
  mkCheck = {
    name,
    description,
    script,
    tags ? [],
  }: {
    _type = "check";
    inherit
      name
      description
      script
      tags
      ;
  };

  mkCheckGroup = {
    name,
    description,
    checks,
  }: {
    _type = "checkGroup";
    inherit name description checks;
  };

  inherit flattenChecks;

  composeChecks = checks: let
    flat = flattenChecks checks;
  in
    builtins.concatStringsSep "\n" (
      builtins.map (
        entry: let
          path = entry.path;
          check = entry.check;
        in ''
          echo "--- check: ${path} ---"
          echo "    ${check.description}"
          ${check.script}
          echo "--- ok: ${path} ---"
          echo ""
        ''
      )
      flat
    );

  validateChecks = {
    pkgs,
    checks,
  }: let
    flat = flattenChecks checks;

    validationScript = builtins.concatStringsSep "\n" (
      builtins.map (
        entry: let
          path = entry.path;
          check = entry.check;
          safeName = builtins.replaceStrings ["/"] ["-"] path;
        in ''
          echo "  validating: ${path}"
          cat > "$TMPDIR/check-${safeName}.sh" << 'CHECKEOF'
          # Assertion stubs for syntax validation
          run_in_guest() { :; }
          assert_success() { :; }
          assert_output_contains() { :; }
          AGENT_SOCK="/dev/null"
          SERIAL_LOG="/dev/null"

          ${check.script}
          CHECKEOF
          sh -n "$TMPDIR/check-${safeName}.sh"
        ''
      )
      flat
    );
  in
    pkgs.mkDerivation {
      pname = "aos-check-validate";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "validate";
          script = ''
            set -eu
            echo "==> Validating ${builtins.toString (builtins.length flat)} check scripts..."
            ${validationScript}
            echo "==> All checks passed syntax validation."
            mkdir -p $out
            echo "PASS" > $out/result
          '';
        }
      ];
    };
}
