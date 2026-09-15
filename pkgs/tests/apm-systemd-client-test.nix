{
  lib,
  mkDerivation,
  coreutils,
  systemd,
  writeShellScriptBin,
}: let
  notifyReloadHelper = writeShellScriptBin "apm-test-notify-reload" ''
    set -euo pipefail

    state_dir=$1
    state=$state_dir/apm-test-notify-reload.count
    notify=${systemd}/bin/systemd-notify

    reload() {
      local count
      if [ -r "$state" ]; then
        count="$(cat "$state")"
      else
        count=0
      fi
      count="$((count + 1))"
      printf '%s\n' "$count" > "$state"
      "$notify" --reloading "--status=reload $count started"
      sleep 2
      "$notify" --ready "--status=reload $count done"
    }

    trap reload HUP

    mkdir -p "$state_dir"
    printf '0\n' > "$state"
    "$notify" --ready "--status=started"

    while true; do
      sleep 86400 &
      wait "$!" || true
    done
  '';
in
  mkDerivation {
    pname = "apm-systemd-client-test";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The payload exactly identifies the systemd-client fixture.";
        "files" = {};
        "input" = "The systemd-client test package identity payload.";
        "operation" = "Read the installed payload bytes.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib\npayload = pathlib.Path(\"@out@/share/apm-systemd-client-test/payload.txt\")\nassert payload.read_bytes() == b\"apm-systemd-client-test\"\nprint(\"apm-systemd-client-test data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "apm-systemd-client-test data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The immutable package rejects mutable service state.";
        "files" = {};
        "input" = "A request for runtime service state inside the immutable package.";
        "operation" = "Resolve the absent reload counter.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys\nif pathlib.Path(\"@out@/var/lib/aos-pkg-apm-systemd-client-test/apm-test-notify-reload.count\").exists():\n    raise SystemExit(2)\nsys.stderr.write(\"apm-systemd-client-test rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "apm-systemd-client-test rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    version = "0";
    src = null;

    runtimeDeps = [coreutils systemd notifyReloadHelper];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/apm-systemd-client-test"
          printf apm-systemd-client-test > "$out/share/apm-systemd-client-test/payload.txt"
          mkdir -p "$out/bin"
          ln -s ${notifyReloadHelper}/bin/apm-test-notify-reload \
            "$out/bin/apm-test-notify-reload"
        '';
      }
    ];

    abilities = ./_apm-systemd-client-test/module.nix;

    meta = {
      description = "Manager-neutral service-client integration test package";
      license = "Apache-2.0";
    };
  }
