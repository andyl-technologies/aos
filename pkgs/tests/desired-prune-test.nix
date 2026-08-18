{
  mkDerivation,
  writeShellScriptBin,
}: let
  start = writeShellScriptBin "desired-prune-test-start" ''
    set -eu

    printf pruned > /var/lib/aos-pkg-desired-prune-test/started
  '';
in
  mkDerivation {
    pname = "desired-prune-test";
    version = "1.0.0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/desired-prune-test"
          printf desired-prune-test > "$out/share/desired-prune-test/payload.txt"
        '';
      }
    ];

    expose = {
      units."desired-prune-test.service" = {
        description = "AOS desired reconciliation prune test";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${start}/bin/desired-prune-test-start";
          RemainAfterExit = true;
          StateDirectory = "aos-pkg-desired-prune-test";
        };
      };

      permissions = {
        network = "private";
        capabilities = [];
        devices = [];
        host-paths = [];
        syscalls = "restricted";
      };
    };

    meta = {
      description = "AOS desired package prune sequencing test payload";
      license = "Apache-2.0";
    };
  }
