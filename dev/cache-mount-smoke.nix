# This derivation runs under a real nixbld UID. A host-side permission check
# cannot tell whether the daemon can traverse the chosen cache directory.
let
  pkgs = (import ../default.nix {}).pkgs;
in
  builtins.derivation {
    name = "aos-dev-cache-mount-smoke";
    system = builtins.currentSystem;
    builder = "${pkgs.bash}/bin/bash";
    args = [
      "-c"
      ''
        test -w /aos-build-cache/go || exit 1
        test -w /aos-build-cache/bazel || exit 1
        printf 'ok\n' > "$out"
      ''
    ];
  }
