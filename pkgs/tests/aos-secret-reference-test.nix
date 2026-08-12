{
  mkDerivation,
  writeTextFile,
  bash,
  coreutils,
}: let
  consumer = writeTextFile {
    name = "aos-secret-reference-test-consumer";
    executable = true;
    destination = "/bin/aos-secret-reference-test-consumer";
    text = ''
      #!${bash}/bin/bash
      set -euo pipefail

      credential="$CREDENTIALS_DIRECTORY/join-token"
      state_dir=/var/lib/aos-pkg-aos-secret-reference-test
      attempts=0
      if [ -s "$state_dir/attempt-count" ]; then
        attempts=$(${coreutils}/bin/cat "$state_dir/attempt-count")
      fi
      attempts=$((attempts + 1))
      ${coreutils}/bin/printf '%s\n' "$attempts" > "$state_dir/attempt-count"
      test -s "$credential"
      count=0
      if [ -s "$state_dir/start-count" ]; then
        count=$(${coreutils}/bin/cat "$state_dir/start-count")
      fi
      count=$((count + 1))
      ${coreutils}/bin/printf '%s\n' "$count" > "$state_dir/start-count"
      ${coreutils}/bin/cat "$credential" > "$state_dir/observed"
      ${coreutils}/bin/stat -c '%a' "$credential" > "$state_dir/delivery-mode"
    '';
  };
in
  mkDerivation {
    pname = "aos-secret-reference-test";
    version = "0";
    src = null;

    runtimeDeps = [consumer bash coreutils];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          ln -s ${consumer}/bin/aos-secret-reference-test-consumer \
            "$out/bin/aos-secret-reference-test-consumer"
        '';
      }
    ];

    expose = {
      units."aos-secret-reference-test.service" = {
        description = "System credential consumer";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${consumer}/bin/aos-secret-reference-test-consumer";
        };
      };

      config.credentials = [
        {
          name = "join-token";
          source = "/run/credstore/secret-reference-test/join-token";
          encrypted = false;
          units = ["aos-secret-reference-test.service"];
        }
      ];
    };

    meta.description = "Fleet fixture for secretRef activation";
  }
