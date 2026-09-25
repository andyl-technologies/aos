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
        # A normal build umask must still create directories writable by the
        # next nixbld UID. This catches missing default ACLs on the host.
        umask 022
        for backend in go bazel; do
          probe="/aos-build-cache/$backend/.aos-dev-acl-$$"
          ${pkgs.coreutils}/bin/mkdir "$probe" || exit 1
          mode=$(${pkgs.coreutils}/bin/stat -c %a "$probe")
          ${pkgs.coreutils}/bin/rmdir "$probe"
          test "$mode" = 777 || exit 1
        done
        printf 'ok\n' > "$out"
      ''
    ];
  }
