{
  mkDerivation,
  writeShellScriptBin,
}: let
  start = writeShellScriptBin "desired-config-test-start" ''
    set -eu

    . /etc/aos/packages/desired-config-test/config.env
    test "$TOKEN" = desired-token
    printf '%s\n' "$TOKEN" > /var/lib/aos-pkg-desired-config-test/started
  '';
in
  mkDerivation {
    pname = "desired-config-test";
    version = "1.0.0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/desired-config-test"
          printf desired-config-test > "$out/share/desired-config-test/payload.txt"
        '';
      }
    ];

    expose = {
      units."desired-config-test.service" = {
        description = "AOS desired reconciliation config sequencing test";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${start}/bin/desired-config-test-start";
          RemainAfterExit = true;
          StateDirectory = "aos-pkg-desired-config-test";
        };
      };

      config.artifacts = [
        {
          name = "env";
          path = "/etc/aos/packages/desired-config-test/config.env";
          format = "env";
          required = ["TOKEN"];
          optional = [];
          units = ["desired-config-test.service"];
          reload = "none";
        }
      ];

      permissions = {
        network = "private";
        capabilities = [];
        devices = [];
        host-paths = [];
        syscalls = "restricted";
      };
    };

    meta.description = "AOS desired package config sequencing test payload";
  }
