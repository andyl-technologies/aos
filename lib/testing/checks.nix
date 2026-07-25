##! lib/testing/checks.nix — Compose a per-test check script
##!
##! A test group is `{ description; checks; }` where
##! `checks` is a flat list of `{ name; description; script; }`. The
##! submodule type in `modules/base/system.nix` validates the shape,
##! so this file does no structural checking — it glues `script`
##! fragments together with `print(...)` banners for log readability.
##!
##! `script` is Python source after the v1 harness rewrite; each
##! fragment runs against the system-mode aos-test-driver, with the
##! VM under test exposed as the `vm` module global. Banners are
##! `<groupName>/<checkName>` so a failure in the test log points at
##! exactly one check without grepping surrounding journal output.
##! The check's `description` is not echoed — we deliberately avoid
##! interpolating arbitrary Nix strings into Python source to keep
##! the emit step robust against descriptions that contain quotes.
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
          print("--- check: ${path} ---")
          ${check.script}
          print("--- ok: ${path} ---")
        ''
      )
      checks
    );
}
