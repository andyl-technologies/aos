{
  mkDerivation,
  writeTextFile,
  bash,
  coreutils,
}: let
  consumer = writeTextFile {
    name = "aos-rfc0011-secret-consumer";
    executable = true;
    destination = "/bin/aos-rfc0011-secret-consumer";
    text = ''
      #!${bash}/bin/bash
      set -euo pipefail

      credential="$CREDENTIALS_DIRECTORY/join-token"
      attempts=0
      if [ -s /run/aos-rfc0011-secret-attempt-count ]; then
        attempts=$(${coreutils}/bin/cat /run/aos-rfc0011-secret-attempt-count)
      fi
      attempts=$((attempts + 1))
      ${coreutils}/bin/printf '%s\n' "$attempts" > /run/aos-rfc0011-secret-attempt-count
      test -s "$credential"
      count=0
      if [ -s /run/aos-rfc0011-secret-start-count ]; then
        count=$(${coreutils}/bin/cat /run/aos-rfc0011-secret-start-count)
      fi
      count=$((count + 1))
      ${coreutils}/bin/printf '%s\n' "$count" > /run/aos-rfc0011-secret-start-count
      ${coreutils}/bin/cp "$credential" /run/aos-rfc0011-secret-observed
      ${coreutils}/bin/stat -c '%a' "$credential" > /run/aos-rfc0011-secret-delivery-mode
    '';
  };
in
  mkDerivation {
    pname = "aos-rfc0011-secret";
    version = "0";
    src = null;

    runtimeDeps = [consumer bash coreutils];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          ln -s ${consumer}/bin/aos-rfc0011-secret-consumer \
            "$out/bin/aos-rfc0011-secret-consumer"
        '';
      }
    ];

    expose = {
      units."aos-rfc0011-secret.service" = {
        description = "RFC-0011 system credential consumer";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${consumer}/bin/aos-rfc0011-secret-consumer";
        };
      };

      config.credentials = [
        {
          name = "join-token";
          source = "/run/credstore/rfc0011/join-token";
          encrypted = false;
          units = ["aos-rfc0011-secret.service"];
        }
      ];
    };

    meta.description = "Fleet fixture for RFC-0011 secretRef activation";
  }
