# This derivation runs under a real nixbld UID. A host-side permission check
# cannot tell whether the daemon can traverse the chosen cache directory.
{
  goCacheDir,
  bazelCacheDir,
  rustCacheDir,
}: let
  aos = import ../default.nix {};
  # The bootstrap Bash and coreutils are i686 binaries, usable directly on
  # x86_64. Their identities stay stable across ordinary package revisions.
  # Other hosts use their native AOS packages for the same sandbox probe.
  probeTools =
    if builtins.currentSystem == "x86_64-linux"
    then aos.stdenv.bootstrap
    else aos.pkgs;
  inherit (probeTools) bash coreutils;
  shellQuote = value: "'${builtins.replaceStrings ["'"] ["'\"'\"'"] value}'";
in
  builtins.derivation {
    name = "aos-dev-cache-mount-smoke";
    system = builtins.currentSystem;
    builder = "${bash}/bin/bash";
    args = [
      "-c"
      ''
        test -w ${shellQuote goCacheDir} || exit 1
        test -w ${shellQuote bazelCacheDir} || exit 1
        test -w ${shellQuote rustCacheDir} || exit 1
        # A normal build umask must still create directories writable by the
        # next nixbld UID. This catches missing default ACLs on the host.
        umask 022
        for cache_dir in ${shellQuote goCacheDir} ${shellQuote bazelCacheDir} ${shellQuote rustCacheDir}; do
          probe="$cache_dir/.aos-dev-acl-$$"
          ${coreutils}/bin/mkdir "$probe" || exit 1
          mode=$(${coreutils}/bin/stat -c %a "$probe")
          ${coreutils}/bin/rmdir "$probe"
          test "$mode" = 777 || exit 1
        done
        printf 'ok\n' > "$out"
      ''
    ];
  }
