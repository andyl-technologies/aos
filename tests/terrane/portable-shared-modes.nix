# Nix forbids setting setgid bits. Preserve the exact native mode test in a real
# guest and require it from the owning shared-directory gate.
{
  pkgs,
  lib,
  image,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  vm = testing.mkVMTest {
    name = "terrane-portable-shared-modes-ext4";
    memory = 512;
    extraWritableMiB = 64;
    timeout = 120;
    rootfsDeps = [image pkgs.coreutils pkgs.util-linux pkgs.python3];
    testScript = ''
      set -eu
      mount -o remount,rw /
      mkdir /var/lib/terrane-shared-modes
      chown 840:840 /var/lib/terrane-shared-modes
      chmod 700 /var/lib/terrane-shared-modes
      trap 'rm -rf /var/lib/terrane-shared-modes' EXIT
      export TMPDIR=/var/lib/terrane-shared-modes
      export src=${pkgs.terrane.src}
      cd "$src/crates"
      ${pkgs.util-linux}/bin/setpriv --reuid 840 --regid 840 --clear-groups \
        --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
        ${pkgs.python3}/bin/python3 "$src/tests/terrane/portable_shared_modes_vm.py" ${image} "$src"
    '';
  };
in
  vm.overrideAttrs (previous: {
    phases = map (phase:
      phase
      // {
        script = ''
          timeout --signal=TERM --kill-after=10 300 "$CONFIG_SHELL" -c ${lib.escapeShellArg phase.script}
        '';
      })
    previous.phases;
  })
