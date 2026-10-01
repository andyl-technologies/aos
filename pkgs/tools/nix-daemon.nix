##! Package-owned multi-user Nix service; nix remains the executable payload.
{
  lib,
  mkDerivation,
  nix,
  bash,
  coreutils,
  systemd,
  service-management,
  aos-nix-store-provider,
  writeShellScriptBin,
}: let
  control = writeShellScriptBin "aos-nix-daemon-control" ''
    set -euo pipefail
    set -a
    source /etc/aos/packages/nix-daemon/runtime.env
    set +a

    case "''${1:-}" in
      enabled)
        test "$NIX_DAEMON_ENABLED" = true
        ;;
      policy)
        # Set every property on every generation, including disabled states,
        # so rollback resets prior transient policy. Surviving workers stay
        # beneath this slice and continue to obey its aggregate limits.
        ${systemd}/bin/systemctl set-property --runtime aos-pkg-nix-daemon-builds.slice \
          "CPUQuota=$NIX_DAEMON_CPU_QUOTA" \
          "MemoryHigh=$NIX_DAEMON_MEMORY_HIGH" \
          "MemoryMax=$NIX_DAEMON_MEMORY_MAX" \
          "MemorySwapMax=$NIX_DAEMON_MEMORY_SWAP_MAX"
        ;;
      prepare)
        test "$NIX_DAEMON_ENABLED" = true
        test -f /nix/var/nix/db/db.sqlite
        test -d /nix/store
        test "$(${coreutils}/bin/realpath -m -- "$NIX_DAEMON_BUILD_DIRECTORY")" = "$NIX_DAEMON_BUILD_DIRECTORY"
        ancestor="$NIX_DAEMON_BUILD_DIRECTORY"
        while :; do
          if [[ -e "$ancestor" ]]; then
            test -d "$ancestor"
            test "$(${coreutils}/bin/stat -c %u -- "$ancestor")" = 0
            mode="$(${coreutils}/bin/stat -c %a -- "$ancestor")"
            (( (8#$mode & 0022) == 0 ))
          fi
          if [[ "$ancestor" == / ]]; then break; fi
          ancestor="$(${coreutils}/bin/dirname -- "$ancestor")"
        done
        ${coreutils}/bin/mkdir -p -- "$NIX_DAEMON_BUILD_DIRECTORY"
        test "$(${coreutils}/bin/stat -c %u "$NIX_DAEMON_BUILD_DIRECTORY")" = 0
        ${coreutils}/bin/chmod 0755 -- "$NIX_DAEMON_BUILD_DIRECTORY"
        ;;
      drained)
        refuse_removal() {
          echo "nix-daemon: $*" >&2
          exit 1
        }
        test "$NIX_DAEMON_ENABLED" = false || refuse_removal "disable the daemon before removing its build identities"
        for unit in nix-daemon.socket nix-daemon.service; do
          state="$(${systemd}/bin/systemctl show "$unit" --property=ActiveState --value)"
          case "$state" in
            inactive|failed) ;;
            *) refuse_removal "$unit must be inactive before removing build identities" ;;
          esac
        done

        # An empty slice can disappear. Inspect credentials independently so
        # absent manager state never substitutes for proof that workers drained.
        for status in /proc/[0-9]*/status; do
          if [ ! -r "$status" ]; then
            [ ! -e "$status" ] || refuse_removal "cannot verify Nix build process credentials"
            continue
          fi
          uid_seen=false
          while read -r key real_uid rest; do
            if [ "$key" = Uid: ]; then
              uid_seen=true
              case "$real_uid" in
                ""|*[!0-9]*) refuse_removal "cannot verify Nix build process credentials" ;;
              esac
              if [ "$real_uid" -ge 30001 ] && [ "$real_uid" -le 30064 ]; then
                refuse_removal "a reserved Nix build identity is still running; wait for it to complete"
              fi
            fi
          done < "$status"
          if [ "$uid_seen" = false ] && [ -e "$status" ]; then
            refuse_removal "cannot verify Nix build process credentials"
          fi
        done

        slice=aos-pkg-nix-daemon-builds.slice
        group="$(${systemd}/bin/systemctl show "$slice" --property=ControlGroup --value)"
        slice_state="$(${systemd}/bin/systemctl show "$slice" --property=ActiveState --value)"
        case "$group" in
          "")
            case "$slice_state" in
              inactive|failed) ;;
              *) refuse_removal "cannot verify the retained Nix worker slice" ;;
            esac
            ;;
          /*/aos-pkg-nix-daemon-builds.slice) ;;
          *) refuse_removal "cannot verify the retained Nix worker cgroup" ;;
        esac
        events="/sys/fs/cgroup$group/cgroup.events"
        if [ -n "$group" ] && [ -r "$events" ]; then
          populated=
          while read -r key value; do
            if [ "$key" = populated ]; then
              [ "$value" = 0 ] || refuse_removal "workers remain in the retained Nix package slice"
              populated=$value
            fi
          done < "$events"
          [ "$populated" = 0 ] || refuse_removal "cannot verify Nix worker population"
        elif [ -n "$group" ]; then
          [ ! -e "/sys/fs/cgroup$group" ] || refuse_removal "cannot read Nix worker population"
          case "$slice_state" in
            inactive|failed) ;;
            *) refuse_removal "cannot verify the retired Nix package slice" ;;
          esac
        fi
        ;;
      *) echo "usage: aos-nix-daemon-control {enabled|policy|prepare|drained}" >&2; exit 64 ;;
    esac
  '';
in
  mkDerivation {
    pname = "nix-daemon";
    version =
      if (nix.versionRequirement or null) == null
      then "=${nix.version}"
      else nix.versionRequirement;
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          cpu = ["x86_64" "aarch64"];
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    src = null;
    buildDeps = [];
    runtimeDeps = [nix bash coreutils systemd control];
    propagatedDeps = [];
    passthru.evidenceSources = [./nix-daemon.nix ./_nix-daemon-config];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/nix-support"
          ln -s ${control}/bin/aos-nix-daemon-control "$out/bin/aos-nix-daemon-control"
          # The configuration module authenticates this shell as a direct
          # dependency; the control script retains it only transitively.
          printf '%s\n' '${bash}' > "$out/nix-support/config-shell"
        '';
      }
    ];

    module = ./_nix-daemon-config;
    moduleDeps = [service-management systemd aos-nix-store-provider];

    checks = {
      testing,
      self,
      pkgs,
      ...
    }:
      import ./_nix-daemon-checks.nix {inherit lib testing self pkgs;};

    meta = {
      description = "Package-owned multi-user Nix daemon";
      homepage = "https://nix.dev/manual/nix/2.24/installation/multi-user";
      license = "LGPL-2.1-or-later";
    };
  }
