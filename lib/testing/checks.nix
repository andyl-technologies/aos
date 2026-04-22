##! lib/testing/checks.nix — Compose a per-test check script
##!
##! A test group is `{ description; checks; instanceMetadata; }` where
##! `checks` is a flat list of `{ name; description; script; }`. The
##! submodule type in `modules/base/system.nix` validates the shape,
##! so this file does no structural checking — it glues `script`
##! fragments together with echo banners for log readability.
##!
##! Banners are `<groupName>/<checkName>` so a failure in the test log
##! points at exactly one check without grepping surrounding journal
##! output.
{
  composeChecks = {
    groupName,
    checks,
  }:
    builtins.concatStringsSep "\n" (
      builtins.map (
        check: let
          path = "${groupName}/${check.name}";
        in ''
          echo "--- check: ${path} ---"
          echo "    ${check.description}"
          ${check.script}
          echo "--- ok: ${path} ---"
          echo ""
        ''
      )
      checks
    );
}
