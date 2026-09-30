##! Package-owned multi-user Nix service; nix remains the executable payload.
{
  lib,
  mkDerivation,
  nix,
  bash,
  coreutils,
  systemd,
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
        ${systemd}/bin/systemctl set-property --runtime aos-pkg-nix-daemon.slice \
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
      *) echo "usage: aos-nix-daemon-control {enabled|policy|prepare}" >&2; exit 64 ;;
    esac
  '';
  identities = builtins.genList (index: "nixbld${toString (index + 1)}") 64;
in
  mkDerivation {
    pname = "nix-daemon";
    version = nix.version;
    src = null;
    buildDeps = [];
    runtimeDeps = [nix bash coreutils systemd control];
    propagatedDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          ln -s ${control}/bin/aos-nix-daemon-control "$out/bin/aos-nix-daemon-control"
        '';
      }
    ];

    expose = {
      units = {
        "nix-daemon-policy.service" = {
          description = "Apply Nix build resource policy, including retained workers";
          before = ["nix-daemon.service"];
          restartIfChanged = true;
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            User = "root";
            Group = "root";
            EnvironmentFile = "/etc/aos/packages/nix-daemon/runtime.env";
            ExecStart = "${control}/bin/aos-nix-daemon-control policy";
          };
        };
        "nix-daemon.socket" = {
          description = "Multi-user Nix daemon socket";
          after = ["aos-nix-db.service"];
          requires = ["aos-nix-db.service"];
          unitConfig.ConditionPathExists = "/etc/aos/packages/nix-daemon/enabled";
          restartIfChanged = true;
          stopOnRemoval = true;
          socketConfig = {
            ListenStream = "/nix/var/nix/daemon-socket/socket";
            SocketMode = "0666";
            DirectoryMode = "0755";
            RemoveOnStop = true;
            Service = "nix-daemon.service";
          };
        };
        "nix-daemon.service" = {
          description = "Root multi-user Nix daemon";
          after = ["aos-nix-db.service" "nix-daemon.socket" "nix-daemon-policy.service"];
          requires = ["aos-nix-db.service" "nix-daemon.socket" "nix-daemon-policy.service"];
          restartIfChanged = true;
          stopOnRemoval = true;
          serviceConfig = {
            Type = "simple";
            User = "root";
            Group = "root";
            Environment = "NIX_CONF_DIR=/etc/aos/packages/nix-daemon NIX_REMOTE=local";
            EnvironmentFile = "/etc/aos/packages/nix-daemon/runtime.env";
            ExecCondition = "${control}/bin/aos-nix-daemon-control enabled";
            ExecStartPre = "${control}/bin/aos-nix-daemon-control prepare";
            ExecStart = "${nix}/bin/nix-daemon --daemon";
            # The listener process owns admission; connection workers and builds
            # can complete using the old executable after replacing the listener.
            KillMode = "process";
            Restart = "on-failure";
            UMask = "0022";
            LimitNOFILE = 1048576;
          };
        };
      };
      config.artifacts = [
        {
          name = "runtime";
          path = "/etc/aos/packages/nix-daemon/runtime.env";
          format = "env";
          required = [
            "NIX_DAEMON_ENABLED"
            "NIX_DAEMON_BUILD_DIRECTORY"
            "NIX_DAEMON_CPU_QUOTA"
            "NIX_DAEMON_MEMORY_HIGH"
            "NIX_DAEMON_MEMORY_MAX"
            "NIX_DAEMON_MEMORY_SWAP_MAX"
            "NIX_DAEMON_CONFIG_GENERATION"
          ];
          units = ["nix-daemon.socket" "nix-daemon.service" "nix-daemon-policy.service"];
          reload = "restart";
        }
      ];
      permissions = {
        network = "host";
        privileged-users = true;
        capabilities = ["CAP_SYS_ADMIN" "CAP_SETUID" "CAP_SETGID" "CAP_CHOWN" "CAP_DAC_OVERRIDE" "CAP_FOWNER" "CAP_SYS_RESOURCE"];
        host-paths = [
          {
            path = "/nix";
            mode = "rw";
          }
          {
            path = "/etc/aos/packages/nix-daemon";
            mode = "read-only";
          }
        ];
        syscalls = "system-service";
      };
    };

    configModule = {
      src = ./_nix-daemon-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      dependencies = {inherit bash;};
      declares = [
        "nix-daemon.enable"
        "nix-daemon.buildUsers.count"
        "nix-daemon.buildDirectory"
        "nix-daemon.clients.enable"
        "nix-daemon.settings"
        "nix-daemon.resources.cpuQuotaCores"
        "nix-daemon.resources.memoryHigh"
        "nix-daemon.resources.memoryMax"
        "nix-daemon.resources.memorySwapMax"
        "nix-daemon.scheduling.cpuPolicy"
        "nix-daemon.scheduling.ioClass"
        "nix-daemon.scheduling.ioPriority"
        "nix-daemon.scheduling.oomScoreAdjust"
      ];
      ownsRoots = [
        {
          root = "nix-daemon";
          interfaceAbi = 1;
          contributable = [];
        }
      ];
      artifacts = {
        etc = [
          "aos/packages/nix-daemon/nix.conf"
          "aos/packages/nix-daemon/enabled"
          "profile.d/nix-daemon.sh"
          "systemd/system/nix-daemon.service.d/30-aos-mount.conf"
          "systemd/system/nix-daemon.service.d/30-aos-scheduling.conf"
          "systemd/system/aos-pkg-nix-daemon.slice.d/30-aos-resources.conf"
        ];
        users = identities;
        groups = ["nixbld"];
        units = [];
      };
      documentation = {
        summary = "Root multi-user Nix daemon with isolated build accounts";
        sections.lifecycle = lib.aosDoc.section "Build and identity lifecycle" [
          (lib.aosDoc.paragraph "The package retains its fixed build account pool while disabled. Disable before uninstalling, then wait for surviving workers to leave the package slice. Build identities remain permanently reserved. Listener restart permits existing connections to continue; there is no automatic drain.")
        ];
      };
    };

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
