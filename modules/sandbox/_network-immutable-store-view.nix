##! modules/sandbox/_network-immutable-store-view.nix — immutable Network ELF view
{lib}: let
  directive = "BindReadOnlyPaths=/usr/lib/aos/nix/store:/nix/store";
  renderedDirectives = unitText:
    builtins.filter (lib.hasPrefix "BindReadOnlyPaths=")
    (map lib.trim (lib.splitString "\n" unitText));
in {
  # PID 1 installs this private bind before exec. The signed logical paths,
  # PT_INTERP, and transitive DSOs then resolve on the stage0-checked EROFS
  # lower store. The enforcing guest gate checks the resulting view is
  # read-only, nodev, and free of nosuid/noexec before admission is opened.
  bind = "/usr/lib/aos/nix/store:/nix/store";

  renderedUnitHasExactBind = unitText: renderedDirectives unitText == [directive];
}
