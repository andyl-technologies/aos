{
  pkgs,
  lib,
}: let
  mkGcc = import ../../stdenv/toolchains/lib/mk-gcc.nix {
    prev = pkgs.stdenv.bootstrap;
    buildPlatform = lib.platform;
    hostPlatform = lib.platform;
    targetPlatform = lib.platform;
  };

  hostileConfigure = builtins.toFile "hostile-configure" ''
    #!/bin/false
    set -eu

    test -n "$BASH_VERSION"
    test "$SHELL" = "$CONFIG_SHELL"
    case "$CONFIG_SHELL" in
      /nix/store/*-bash-*/bin/bash) ;;
      *)
        echo "configure shell is not store-qualified AOS Bash" >&2
        exit 1
        ;;
    esac
    case "$-" in
      *f*) ;;
      *)
        echo "configure did not inherit the hostile noglob fixture" >&2
        exit 1
        ;;
    esac
    printf '%s\n' PASS > "$TMPDIR/config-shell-fixture"
  '';
in
  mkGcc {
    name = "mk-gcc-config-shell-check";
    version = "fixture";
    sourceDir = "gcc-fixture";
    preUnpack = ''
      set -f
      export SHELLOPTS
    '';
    unpackCommands = ''
      mkdir gcc-fixture
      cp ${hostileConfigure} gcc-fixture/configure
      chmod +x gcc-fixture/configure
    '';
    freezeAutotoolsTimestamps = false;
    buildCommands = ''
      test "$(cat "$TMPDIR/config-shell-fixture")" = PASS
    '';
    installCommands = ''
      mkdir -p "$out"
      cp "$TMPDIR/config-shell-fixture" "$out/result"
    '';
    meta = {};
  }
