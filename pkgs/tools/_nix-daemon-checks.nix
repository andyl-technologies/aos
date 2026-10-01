##! Configuration authorization and real multi-user Nix build checks.
{
  lib,
  pkgs,
  self,
  testing,
  ...
}: let
  artifactLib = import ../../lib/packages/artifacts.nix {};
  artifact = name: package: {
    inherit name;
    version = "1.0.0";
    path = toString package;
    outputs.out = toString package;
    mainProgram = package.meta.mainProgram or name;
  };
  record = name: source: package: dependencies: let
    retained = builtins.path {
      path = source;
      name = "${name}-module";
    };
  in {
    inherit name;
    version = "1.0.0";
    configRoot = toString retained;
    module = "${retained}/module.nix";
    artifacts = {
      package = artifact name package;
      inherit dependencies;
    };
  };
  handlers = {
    aos.abilities = {
      serviceManagement.operations.realize.handler.program = artifactLib.value ((artifact "systemd" pkgs.systemd) // {mainProgram = "aos-service-handler";});
      configuration.operations.file.handler.program = artifactLib.value ((artifact "systemd" pkgs.systemd) // {mainProgram = "aos-service-handler";});
      identity.operations = builtins.listToAttrs (map (name: {
        inherit name;
        value.handler.program = artifactLib.value ((artifact "systemd" pkgs.systemd) // {mainProgram = "aos-systemd-native-resources";});
      }) ["group" "principal" "membership"]);
      mount.operations.ensure.handler.program = artifactLib.value ((artifact "systemd" pkgs.systemd) // {mainProgram = "aos-systemd-native-resources";});
    };
  };
  # Source-backed records keep pure checks independent of module-output builds.
  mkEvaluation = host:
    lib.evalPackageModules {
      scope = ["profile" "nix-daemon-test"];
      packageModules = [
        (record "service-management" ../system/_service-management pkgs.service-management {})
        (record "filesystem" ../filesystem/_aos-filesystem-provider pkgs.aos-filesystem-provider {})
        (record "aos-nix-store-provider" ./_aos-nix-store-provider pkgs.aos-nix-store-provider {})
        (record "nix-daemon" ./_nix-daemon-config self (builtins.mapAttrs artifact {
          inherit (pkgs) nix bash coreutils systemd;
        }))
      ];
      operatorModules = [handlers host];
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
  files = evaluation: evaluation.config.aos.abilities.configuration.operations.file.effects;
  native = (files enabled).nix-daemon-config.input.content;
  fails = host: !(builtins.tryEval (builtins.toJSON (mkEvaluation host).deployment)).success;
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
      aos.abilities.identity.operations.principal.effects.intruder.input = {
        name = "intruder";
        requested_id = 30001;
      };
    }
    {
      aos.abilities.identity.operations.group.effects.intruder.input = {
        name = "intruder";
        requested_id = 30000;
      };
    }
  ];
  changed = mkEvaluation {nix-daemon.settings.http-connections = 26;};
  rejectsSlice = group:
    fails {
      aos.abilities.serviceManagement.operations.realize.effects.nix-daemon.input.resources.resource_group = lib.mkForce group;
    };
  nativeFile = pkgs.runCommand "nix-daemon-test.conf" {nativeConfig = native;} ''
    printf '%s' "$nativeConfig" > "$out/nix.conf"
  '';
  securityScript = pkgs.writeTextFile {
    name = "nix-daemon-security-fixture";
    destination = "/security.sh";
    text =
      builtins.replaceStrings
      ["@nix@" "@util-linux@" "@sed@" "@grep@" "@bash@" "@coreutils@"]
      (map toString [pkgs.nix pkgs.util-linux pkgs.sed pkgs.grep pkgs.bash pkgs.coreutils])
      (builtins.readFile ./_nix-daemon-security.sh.in);
  };
  contract = assert builtins.all fails rejects;
  assert builtins.all rejectsSlice ["system" "aos-pkg-other-builds" "aos-pkg-nix-daemon-undeclared"];
  assert lib.hasInfix "max-jobs = 0" (files remoteOnly).nix-daemon-config.input.content;
  assert enabled.config.aos.abilities.identity.operations.principal.effects.nixbld64.input.requested_id == 30064;
  assert disabled.config.aos.abilities.identity.operations.principal.effects.nixbld64.lifetime == "persistent";
  assert builtins.length enabled.config.aos.abilities.identity.operations.membership.effects.nix-daemon-builders.input.members == 4;
  assert !disabled.config.aos.abilities.serviceManagement.operations.realize.effects.nix-daemon.input.enabled;
  assert (files disabled).nix-daemon-slice.lifetime == "persistent";
  assert lib.hasInfix "build-users-group = nixbld" native;
  assert lib.hasInfix "sandbox = true" native;
  assert lib.hasInfix "sandbox-fallback = false" native;
  assert lib.hasInfix "sandbox-paths = /bin/sh=${pkgs.bash}/bin/bash" native;
  assert lib.hasInfix "narinfo-cache-negative-ttl = 30" native;
  assert (files disabled).nix-daemon-runtime.input.content != (files changed).nix-daemon-runtime.input.content; true;
in {
  config = assert contract;
    pkgs.runCommand "nix-daemon-native-contract" {
      nativePlan = builtins.toJSON enabled.deployment;
      buildDeps = [pkgs.jq];
    } ''
      printf '%s' "$nativePlan" > "$out/deployment.json"
      ${pkgs.jq}/bin/jq -e '.schema == "aos.package.transaction" and (.graph.nodes | length) >= 70' "$out/deployment.json"
    '';

  multi-user = testing.mkVMTest {
    name = "nix-daemon-multi-user-builds";
    memory = 1024;
    rootfsDeps = [self pkgs.nix pkgs.bash pkgs.coreutils pkgs.util-linux pkgs.sed pkgs.grep nativeFile securityScript];
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
      ${pkgs.nix}/bin/nix-store --load-db < /usr/lib/aos/nix-registration

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
      source ${securityScript}/security.sh
    '';
  };
}
