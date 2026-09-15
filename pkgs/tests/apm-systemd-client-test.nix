{
  mkDerivation,
  coreutils,
  systemd,
  writeShellScriptBin,
}: let
  notifyReloadHelper = writeShellScriptBin "apm-test-notify-reload" ''
    set -euo pipefail

    state_dir=/var/lib/aos-pkg-apm-systemd-client-test
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
      description = "AOS exposed package for apm systemd-client integration tests";
      license = "Apache-2.0";
    };
  }
