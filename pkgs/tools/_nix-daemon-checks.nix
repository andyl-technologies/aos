##! Configuration authorization and real multi-user Nix build checks.
{
  lib,
  pkgs,
  self,
  testing,
  ...
}: let
  aos = import ../.. {system = pkgs.stdenv.buildPlatform.system;};
  definition = import ./nix-daemon.nix {
    inherit lib;
    inherit (pkgs) nix bash coreutils systemd writeShellScriptBin;
    mkDerivation = value: value;
  };
  packageModule = {
    name = "nix-daemon";
    configRoot = ./_nix-daemon-config;
    module = ./_nix-daemon-config/module.nix;
    authorization = {
      owns = ["nix-daemon"];
      contributes = {};
      artifacts = definition.configModule.artifacts;
    };
    outputs = {
      self = toString self;
      dependencies = {bash = toString pkgs.bash;};
    };
  };
  mkEvaluation = host:
    aos.mkSystem {
      modules = [
        ../../systems/server.nix
        {
          options.nix-daemon.config = lib.mkOption {
            type = lib.types.attrs;
            default = {};
            internal = true;
          };
        }
      ];
      packageModules = [packageModule];
      operatorModules = [host];
    };
  enabled = mkEvaluation {
    nix-daemon = {
      enable = true;
      buildUsers.count = 4;
      settings = {
        max-jobs = 4;
        cores = 2;
        http-connections = 7;
        auto-optimise-store = true;
        narinfo-cache-negative-ttl = 30;
      };
      resources = {
        cpuQuotaCores = 3;
        memoryHigh = "60%";
        memoryMax = "75%";
        memorySwapMax = "1G";
      };
      scheduling.cpuPolicy = "idle";
    };
  };
  disabled = mkEvaluation {nix-daemon.enable = false;};
  remoteOnly = mkEvaluation {nix-daemon.settings.max-jobs = 0;};
  manifest = enabled.config.system.build.configManifest;
  native = manifest.etc."aos/packages/nix-daemon/nix.conf".text;
  fails = host: !(builtins.tryEval (builtins.toJSON (mkEvaluation host).config.system.build.configManifest)).success;
  rejects = [
    {nix-daemon.buildUsers.count = 65;}
    {nix-daemon.settings.max-jobs = 9;}
    {nix-daemon.settings.build-users-group = "root";}
    {nix-daemon.settings.build-dir = "/tmp";}
    {nix-daemon.settings.sandbox-paths = [];}
    {nix-daemon.settings.extra-sandbox-paths = ["/bin/sh=/host-shell"];}
    {nix-daemon.settings."bad\nname" = true;}
    {nix-daemon.settings.builders = "host\ntrusted-users = *";}
    {nix-daemon.resources.memoryMax = "101%";}
    {nix-daemon.scheduling.oomScoreAdjust = -1000;}
    {nix-daemon.buildDirectory = "/nix/store";}
    {
      aos.users.users.intruder = {
        uid = 30001;
        group = "root";
      };
    }
    {aos.users.groups.intruder.gid = 30000;}
  ];
  changed = mkEvaluation {nix-daemon.settings.http-connections = 26;};
  legacy = lib.evalModules {
    specialArgs.outputs = packageModule.outputs;
    modules = [
      ./_nix-daemon-config/module.nix
      {
        options = {
          assertions = lib.mkOption {
            type = lib.types.listOf lib.types.attrs;
            default = [];
          };
          environment.etc = lib.mkOption {
            type = lib.types.attrs;
            default = {};
          };
          aos.users.users = lib.mkOption {
            type = lib.types.attrs;
            default = {};
          };
          aos.users.groups = lib.mkOption {
            type = lib.types.attrs;
            default = {};
          };
          nix-daemon.config = lib.mkOption {
            type = lib.types.attrs;
            default = {};
          };
        };
      }
    ];
  };
  nativeFile = pkgs.runCommand "nix-daemon-test.conf" {nativeConfig = native;} ''
    printf '%s' "$nativeConfig" > "$out/nix.conf"
  '';
  contract = assert builtins.all fails rejects;
  assert lib.hasInfix "max-jobs = 0" remoteOnly.config.system.build.configManifest.etc."aos/packages/nix-daemon/nix.conf".text;
  assert !(builtins.tryEval legacy.config.environment.etc."aos/packages/nix-daemon/nix.conf".text).success;
  assert manifest.ownership.etc."aos/packages/nix-daemon/nix.conf" == "nix-daemon";
  assert manifest.ownership.etc."systemd/system/nix-daemon.service.d/30-aos-mount.conf" == "nix-daemon";
  assert manifest.ownership.users.nixbld64 == "nix-daemon";
  assert enabled.config.aos.users.users.nixbld64.uid == 30064;
  assert enabled.config.aos.users.groups.nixbld.members == ["nixbld1" "nixbld2" "nixbld3" "nixbld4"];
  assert disabled.config.aos.users.users.nixbld64.uid == 30064;
  assert !(disabled.config.environment.etc ? "aos/packages/nix-daemon/enabled");
  assert lib.hasInfix "build-users-group = nixbld" native;
  assert lib.hasInfix "sandbox = true" native;
  assert lib.hasInfix "sandbox-fallback = false" native;
  assert lib.hasInfix "sandbox-paths = /bin/sh=${pkgs.bash}/bin/bash" native;
  assert lib.hasInfix "narinfo-cache-negative-ttl = 30" native;
  assert disabled.config.nix-daemon.config.runtime.NIX_DAEMON_CONFIG_GENERATION != changed.config.nix-daemon.config.runtime.NIX_DAEMON_CONFIG_GENERATION; true;
in {
  frozen-evaluation =
    pkgs.runCommand "nix-daemon-frozen-manifest-assertions" {
      baseLibrary = enabled.config.aos.config.evalAtBoot.baseLib;
      buildDeps = [pkgs.nix];
    } ''
      export NIX_REMOTE=local
      export NIX_CONF_DIR="$TMPDIR/nix-conf"
      export NIX_STATE_DIR="$TMPDIR/nix-state"
      export NIX_PATH=""
      export NIX_CONFIG=""
      export HOME="$TMPDIR/home"
      mkdir -p "$NIX_CONF_DIR" "$HOME"
      printf 'build-users-group =\n' > "$NIX_CONF_DIR/nix.conf"
      ${pkgs.nix}/bin/nix-instantiate --eval --strict --json \
        --option restrict-eval true --option allow-import-from-derivation false \
        -I "aos-base=$baseLibrary" \
        --expr "let base = import <aos-base>; in (base.evalHostConfig {}).config.system.build.configManifest" \
        > "$out/manifest.json"
      if ${pkgs.nix}/bin/nix-instantiate --eval --strict --json \
        --option restrict-eval true --option allow-import-from-derivation false \
        -I "aos-base=$baseLibrary" \
        --expr "let base = import <aos-base>; result = base.evalHostConfig { operatorModules = [{ aos.users.users.collision = { uid = 30001; group = \"root\"; }; }]; }; in result.config.system.build.configManifest" \
        > "$TMPDIR/invalid.json" 2> "$TMPDIR/invalid.log"; then
        echo "invalid frozen manifest unexpectedly passed" >&2
        exit 1
      fi
      grep -F 'Failed assertions:' "$TMPDIR/invalid.log"
    '';

  config = assert contract;
    pkgs.runCommand "nix-daemon-config-authorization" {
      nixDaemonExpose = self.expose;
      buildDeps = [pkgs.jq];
    } ''
      test -f "$nixDaemonExpose/manifest.json"
      ${pkgs.jq}/bin/jq -e '.expose.config.artifacts[0].reload == "restart" and (.expose.config.artifacts[0].units | index("nix-daemon-policy.service")) != null' "$nixDaemonExpose/manifest.json"
      ${pkgs.jq}/bin/jq -e '.expose.units | index("aos-pkg-nix-daemon.slice") != null' "$nixDaemonExpose/manifest.json"
      grep -F 'KillMode=process' "$nixDaemonExpose/units/nix-daemon.service"
      grep -F 'ListenStream=/nix/var/nix/daemon-socket/socket' "$nixDaemonExpose/units/nix-daemon.socket"
      grep -F 'ConditionPathExists=/etc/aos/packages/nix-daemon/enabled' "$nixDaemonExpose/units/nix-daemon.socket"
      grep -F 'After=' "$nixDaemonExpose/units/nix-daemon.service"
      touch "$out"
    '';

  multi-user = testing.mkVMTest {
    name = "nix-daemon-multi-user-builds";
    memory = 1024;
    rootfsDeps = [self pkgs.nix pkgs.bash pkgs.coreutils pkgs.util-linux nativeFile];
    testScript = ''
      set -euo pipefail
      mkdir -p /dev/pts
      mount -t devpts devpts /dev/pts -o newinstance,ptmxmode=0666,mode=0620
      ln -sf pts/ptmx /dev/ptmx
      mkdir -p /etc/aos/packages/nix-daemon /var/cache/nix-build /nix/var/nix/daemon-socket
      cp ${nativeFile}/nix.conf /etc/aos/packages/nix-daemon/nix.conf
      cat > /etc/passwd <<'PASSWD'
      root:x:0:0:root:/root:${pkgs.bash}/bin/bash
      client:x:1000:100:client:/tmp:${pkgs.bash}/bin/bash
      second-client:x:1001:100:second client:/tmp:${pkgs.bash}/bin/bash
      nixbld1:x:30001:30000:Nix build user:/var/empty:/sbin/nologin
      nixbld2:x:30002:30000:Nix build user:/var/empty:/sbin/nologin
      nixbld3:x:30003:30000:Nix build user:/var/empty:/sbin/nologin
      nixbld4:x:30004:30000:Nix build user:/var/empty:/sbin/nologin
      PASSWD
      cat > /etc/group <<'GROUP'
      root:x:0:root
      users:x:100:client,second-client
      nixbld:x:30000:nixbld1,nixbld2,nixbld3,nixbld4
      GROUP
      printf 'nixbld1:!*:::::::\nnixbld2:!*:::::::\nnixbld3:!*:::::::\nnixbld4:!*:::::::\n' > /etc/shadow
      export NIX_CONF_DIR=/etc/aos/packages/nix-daemon
      export NIX_REMOTE=local
      ${pkgs.nix}/bin/nix-store --init --option build-users-group ""
      ${pkgs.nix}/bin/nix-store --load-db < /aos-registration

      start_daemon() {
        ${pkgs.nix}/bin/nix-daemon --daemon > /tmp/daemon.log 2>&1 &
        daemon_pid=$!
        for attempt in {1..100}; do
          if test -S /nix/var/nix/daemon-socket/socket && \
             ${pkgs.util-linux}/bin/setpriv --reuid=1000 --regid=100 --clear-groups \
               ${pkgs.nix}/bin/nix-store --store daemon --query --hash ${pkgs.bash} >/dev/null 2>&1; then
            return
          fi
          sleep 0.1
        done
        cat /tmp/daemon.log >&2
        return 1
      }

      cat > /tmp/build.nix <<'EXPRESSION'
      { name }: let
        bash = builtins.storePath "${pkgs.bash}";
        coreutils = builtins.storePath "${pkgs.coreutils}";
      in builtins.derivation {
        inherit name;
        system = builtins.currentSystem;
        builder = "''${bash}/bin/bash";
        args = [ "-c" '''
          set -euo pipefail
          test ! -e /etc/aos/packages/nix-daemon/nix.conf
          test ! -e /tmp/host-only-sentinel
          ''${coreutils}/bin/sleep 15
          ''${coreutils}/bin/mkdir "$out"
          ''${coreutils}/bin/id -u > "$out/sandbox-uid"
        ''' ];
      }
      EXPRESSION
      chmod 0644 /tmp/build.nix
      touch /tmp/host-only-sentinel
      start_daemon

      ${pkgs.util-linux}/bin/setpriv --reuid=1001 --regid=100 --clear-groups \
        ${pkgs.nix}/bin/nix-build --store daemon --no-out-link /tmp/build.nix \
          --argstr name nix-daemon-builder-one >/tmp/build-one.out 2>/tmp/build-one.log &
      first_client=$!
      ${pkgs.util-linux}/bin/setpriv --reuid=1000 --regid=100 --clear-groups \
        ${pkgs.nix}/bin/nix-build --store daemon --no-out-link /tmp/build.nix \
          --argstr name nix-daemon-builder-two >/tmp/build-two.out 2>/tmp/build-two.log &
      second_client=$!

      # The sandbox may remap each builder to the same namespace UID. Inspect
      # overlapping host credentials to prove distinct non-root build identities.
      found=0
      for attempt in {1..100}; do
        declare -A host_builders=()
        for status in /proc/[0-9]*/status; do
          while read -r key real_uid _; do
            if test "$key" = Uid: && test "$real_uid" -ge 30001 && test "$real_uid" -le 30004; then
              host_builders[$real_uid]=1
            fi
          done < "$status" 2>/dev/null || true
        done
        if test "''${#host_builders[@]}" -ge 2; then found=1; break; fi
        sleep 0.1
      done
      if test "$found" != 1; then
        cat /tmp/build-one.log /tmp/build-two.log /tmp/daemon.log >&2
        exit 1
      fi
      kill "$daemon_pid"
      wait "$daemon_pid" || true
      start_daemon
      wait "$first_client" || { cat /tmp/build-one.log >&2; exit 1; }
      wait "$second_client" || { cat /tmp/build-two.log >&2; exit 1; }
      test -f "$(cat /tmp/build-one.out)/sandbox-uid"
      test -f "$(cat /tmp/build-two.out)/sandbox-uid"
      kill "$daemon_pid"
      wait "$daemon_pid" || true
      echo 'Nix daemon: non-root clients, distinct concurrent build identities, sandbox isolation, and listener restart PASS'
    '';
  };
}
