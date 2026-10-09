# Once-only privileged fixture producer; it never activates shared-host swap.
{
  pkgs,
  parentFixture,
  externalSource,
}: let
  valid = builtins.all (name:
    externalSource ? ${name}
    && builtins.isInt externalSource.${name}
    && externalSource.${name} > 0) ["residentBytes" "backingBytes" "tasks" "descriptors"];
  memoryBytes = 21474836480 + externalSource.residentBytes;
  descriptorBound = externalSource.tasks * 1024;
in
  assert valid;
  assert externalSource == parentFixture.passthru.externalSource;
  assert externalSource.descriptors >= descriptorBound;
    pkgs.mkDerivation {
      pname = "crucible-private-parent-original-operator";
      version = "0";
      src = null;
      buildDeps = [pkgs.bash pkgs.coreutils];
      runtimeDeps = [parentFixture pkgs.systemd];
      phases = [
        {
          name = "publish-original-operator-entry";
          script = ''
            mkdir -p "$out/bin" "$out/nix-support"
            cat > "$out/bin/crucible-private-parent-original" <<'OPERATOR'
            #!${pkgs.bash}/bin/bash
            set -eu
            # The enclosing owner must account runtime dispatch and setup before
            # this unit exists, then retain the original deadline through physical
            # retirement. This unit contains descendants only; it is not the
            # complete-work counter. Loaded parents are never migrated here.
            test "$(${pkgs.coreutils}/bin/id -u)" -eq 0
            exec ${pkgs.systemd}/bin/systemd-run --wait --collect \
              --unit=crucible-private-parent.service \
              --property=Type=exec \
              --property=ExitType=cgroup \
              --property=Delegate=cpu,memory,pids \
              --property=DelegateSubgroup=guardian \
              --property=MemoryMax=${toString memoryBytes} \
              --property=MemorySwapMax=0 \
              --property=CPUQuota=1000% \
              --property=CPUQuotaPeriodSec=100ms \
              --property=TasksMax=${toString externalSource.tasks} \
              --property=LimitNOFILE=1024:1024 \
              --property=RuntimeMaxSec=3900s \
              --property=KillMode=control-group \
              --property=KillSignal=SIGKILL \
              --property=FinalKillSignal=SIGKILL \
              --property=TimeoutStopSec=0 \
              ${parentFixture}/bin/crucible-private-parent
            OPERATOR
            chmod +x "$out/bin/crucible-private-parent-original"
            ln -s ${parentFixture} "$out/parent-fixture"
            cat > "$out/nix-support/aos-release-policy" <<'POLICY'
            policy_version=1
            artifact_role=private-test-fixture
            standalone_release=false
            POLICY
          '';
        }
      ];
      passthru = {
        inherit parentFixture externalSource memoryBytes descriptorBound;
        privateFixture = true;
        runtimeAdmission = false;
      };
    }
