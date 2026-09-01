##! containerd — Container runtime
{
  mkDerivation,
  fetchurl,
  gnumake,
  go,
  runc,
  kmod,
  bash,
  lib,
}: let
  version = "2.2.1";
  payload = mkDerivation {
    pname = "containerd-payload";
    inherit version;
    src = fetchurl {
      urls = [
        "https://github.com/containerd/containerd/archive/v${version}/containerd-${version}.tar.gz"
      ];
      hash = "sha256-r1cHomiRSGMyFCzAreTwxUP3B9OVSDj1zs7nO4M8+bQ=";
    };
    buildDeps = [gnumake go];
    runtimeDeps = [runc];
    disallowedReferences = [go];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd containerd-${version}
        '';
      }
      {
        name = "setup-gopath";
        script = ''
          export GOPATH=$TMPDIR/go
          mkdir -p $GOPATH/src/github.com/containerd
          ln -sf $PWD $GOPATH/src/github.com/containerd/containerd
        '';
      }
      {
        name = "build";
        script = ''
          export GOPATH=$TMPDIR/go
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=0
          export GOPROXY=off
          export GOFLAGS="-trimpath"
          mkdir -p "$GOCACHE"
          make SHELL="$CONFIG_SHELL" VERSION=v${version} \
            REVISION=v${version} \
            STATIC=1 \
            GO_BUILD_FLAGS="-trimpath" \
            binaries
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin $out/lib/systemd/system
          install -m 755 bin/* $out/bin/
          sed \
            -e 's|/usr/local/bin/containerd|'"$out/bin/containerd"'|g' \
            -e 's|/sbin/modprobe|${kmod}/sbin/modprobe|g' \
            containerd.service > $out/lib/systemd/system/containerd.service
        '';
      }
    ];
  };
in
  mkDerivation {
    pname = "containerd";
    inherit version;

    src = null;
    runtimeDeps = [payload runc kmod bash];
    propagatedDeps = [];

    # Pure stage-2 inventory: generateUnits can reproduce the historical
    # systemd.packages symlink farm without inspecting this output at eval
    # time (and therefore without import-from-derivation).
    passthru.systemdUnitInventory.system = [
      "lib/systemd/system/containerd.service"
    ];

    expose = {
      units."containerd.service" = {
        description = "containerd standalone container runtime";
        after = ["network.target"];
        serviceConfig = {
          Type = "notify";
          EnvironmentFile = "/etc/aos/packages/containerd/runtime.env";
          ExecCondition = "${bash}/bin/bash -c 'test \"$CONTAINERD_ENABLED\" = true'";
          ExecStart = "${payload}/bin/containerd --config /etc/aos/packages/containerd/config.toml";
          Restart = "always";
          RestartSec = "5s";
          Delegate = true;
          KillMode = "process";
          OOMScoreAdjust = -999;
          LimitNOFILE = 1048576;
          LimitNPROC = "infinity";
          LimitCORE = "infinity";
          TasksMax = "infinity";
          StateDirectory = "containerd";
          RuntimeDirectory = "containerd";
        };
      };

      config.artifacts = [
        {
          name = "runtime";
          path = "/etc/aos/packages/containerd/runtime.env";
          format = "env";
          required = ["CONTAINERD_ENABLED"];
          units = ["containerd.service"];
          reload = "restart";
        }
        {
          name = "config";
          path = "/etc/aos/packages/containerd/config.toml";
          format = "toml";
          required = ["version" "root" "state" "grpc" "plugins"];
          optional = ["metrics" "disabled_plugins" "required_plugins"];
          units = ["containerd.service"];
          reload = "restart";
        }
      ];

      prepareHostPathDirectories = [
        "/var/lib/containerd"
        "/run/containerd"
      ];
      permissions = {
        network = "host";
        privileged-users = true;
        cgroup-delegate = true;
        capabilities = [
          "CAP_SYS_ADMIN"
          "CAP_SYS_CHROOT"
          "CAP_NET_ADMIN"
          "CAP_NET_RAW"
          "CAP_MKNOD"
          "CAP_SETUID"
          "CAP_SETGID"
          "CAP_CHOWN"
        ];
        devices = ["/dev/null" "/dev/random" "/dev/urandom"];
        host-paths = [
          {
            path = "/var/lib/containerd";
            mode = "rw";
          }
          {
            path = "/run/containerd";
            mode = "rw";
          }
          {
            path = "/etc/containerd";
            mode = "read-only";
          }
          {
            path = "/sys/fs/cgroup";
            mode = "rw";
          }
          {
            path = "/lib/modules";
            mode = "read-only";
          }
        ];
        kernel-modules = ["overlay"];
        syscalls = "privileged";
        security-label = "aos-pkg-containerd";
      };
      kernel.modules = ["overlay"];
    };

    configModule = {
      src = ./_containerd-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "containerd.defaultRuntime"
        "containerd.disabledPlugins"
        "containerd.enable"
        "containerd.grpcAddress"
        "containerd.metricsAddress"
        "containerd.registryConfigPath"
        "containerd.requiredPlugins"
        "containerd.root"
        "containerd.sandboxImage"
        "containerd.snapshotter"
        "containerd.state"
        "containerd.systemdCgroup"
      ];
      ownsRoots = [
        {
          root = "containerd";
          interfaceAbi = 1;
          contributable = [];
        }
      ];
      documentation = {
        summary = "containerd — industry-standard container runtime";
        sections = {
          enablement = lib.aosDoc.section "Standalone runtime" [
            (lib.aosDoc.paragraph "Installing containerd is inert. Enable this package only for a standalone host runtime; k3s consumes containerd binaries as subordinate payloads and does not enable this service.")
          ];
          isolation = lib.aosDoc.section "Privilege and state" [
            (lib.aosDoc.paragraph "This is an explicit root-equivalent workload with kernel, cgroup, state, runtime, and socket access. Durable state uses /var/lib/containerd and volatile state uses /run/containerd.")
          ];
          registries = lib.aosDoc.section "Registry configuration" [
            (lib.aosDoc.paragraph "Provision hosts.toml beneath registryConfigPath using host policy. Registry passwords must use an external credential helper or platform-managed file, never runtime Nix values.")
          ];
        };
      };
    };

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p $out/bin $out/lib/systemd/system
          for program in ${payload}/bin/*; do
            ln -s "$program" "$out/bin/$(basename "$program")"
          done
          ln -s ${payload}/lib/systemd/system/containerd.service \
            $out/lib/systemd/system/containerd.service
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-containerd";
        tool = self;
        command = "containerd --version";
      };
      config-module-contract = import ./_containerd-tests/contract.nix {
        inherit pkgs lib self;
      };
      runtime-contract = import ./_containerd-tests/lifecycle.nix {
        inherit testing self;
        inherit (pkgs) coreutils grep iproute2;
      };
    };

    meta = {
      description = "containerd — industry-standard container runtime";
      homepage = "https://containerd.io";
      license = "Apache-2.0";
    };
  }
