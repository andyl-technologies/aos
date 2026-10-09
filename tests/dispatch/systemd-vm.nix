##! Boots the real system manager and tests Dispatch's cgroup enforcement.
##!
##! KVM is required by the qualification check. The explicit TCG variant runs
##! the same guest and assertions on development machines without /dev/kvm.
{
  pkgs,
  lib,
  testing,
  system,
  allowTcg ? false,
  probePackage ? pkgs.dispatch.passthru.tests,
}: let
  fixtureSource = pkgs.writeTextFile {
    name = "dispatch-systemd-worker-fixture";
    destination = "/worker.py";
    text = builtins.readFile ./systemd-worker.py;
  };
  fixtureRunner = pkgs.writeShellScriptBin "dispatch-systemd-fixture-runner" ''
    exec ${pkgs.python3}/bin/python3 ${fixtureSource}/worker.py "$@"
  '';
  fixtureNative = pkgs.writeShellScriptBin "dispatch-systemd-fixture-native" ''
    exec ${pkgs.python3}/bin/python3 ${fixtureSource}/worker.py --native
  '';
  fixture = system.extendModules {
    modules = [
      {
        aos.dispatch = {
          enable = true;
          applications.vm = {
            ownerService = "dispatch-owner";
            aggregate = {
              cpuWeight = 400;
              memoryHighBytes = 402653184;
              memoryMaxBytes = 536870912;
              tasksMax = 128;
            };
            solvers = {
              cpuWeight = 100;
              memoryHighBytes = 268435456;
              memoryMaxBytes = 402653184;
              tasksMax = 64;
            };
            worker = {
              cpuWeight = 250;
              cpuQuotaPercent = 150;
              memoryHighBytes = 67108864;
              memoryMaxBytes = 100663296;
              tasksMax = 16;
              lifetimeSeconds = 120;
              startupTimeoutSeconds = 15;
              cleanupTimeoutSeconds = 5;
            };
          };
        };

        environment.systemPackages = [probePackage fixtureRunner fixtureNative];
        systemd.services.dispatch-owner = {
          description = "Dispatch containment fixture resource owner";
          wantedBy = ["multi-user.target"];
          serviceConfig = {
            Type = "simple";
            ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
          };
        };
        systemd.services.dispatch-containment-test = {
          description = "Dispatch managed worker containment assertions";
          wantedBy = ["multi-user.target"];
          wants = ["dispatch-owner.service" "dbus.service"];
          after = ["dispatch-owner.service" "dbus.service"];
          serviceConfig = {
            Type = "oneshot";
            TimeoutStartSec = 180;
            StandardOutput = "journal+console";
            StandardError = "journal+console";
          };
          script = ''
            status=0
            DISPATCH_SYSTEMCTL=${pkgs.systemd}/bin/systemctl \
              ${probePackage}/bin/dispatch-systemd-probe \
              ${fixtureRunner}/bin/dispatch-systemd-fixture-runner \
              ${fixtureNative}/bin/dispatch-systemd-fixture-native || status=$?
            if [ "$status" -eq 0 ]; then
              echo DISPATCH_SYSTEMD_VM_PASS
            else
              echo "DISPATCH_SYSTEMD_VM_FAIL: $status"
            fi
            ${pkgs.systemd}/bin/systemctl --no-block poweroff
            exit "$status"
          '';
        };
      }
    ];
  };
  disk = testing.mkTestDisk {system = fixture;};
  kernel = fixture.config.system.build.kernel;
  initrd = fixture.config.system.build.initrd;
  kernelArguments = lib.concatStringsSep " " fixture.config.aos.image.platform.testKernelParams;
in
  pkgs.mkDerivation {
    pname = "dispatch-systemd-vm${lib.optionalString allowTcg "-tcg"}";
    version = "0.1.0";
    src = null;
    buildDeps = [pkgs.bash pkgs.qemu pkgs.coreutils pkgs.grep];
    requiredSystemFeatures = lib.optionals (!allowTcg) ["kvm"];

    phases = [
      {
        name = "test";
        script = ''
          set -eu
          cp ${disk}/disk.img "$TMPDIR/disk.img"
          chmod u+w "$TMPDIR/disk.img"
          mkdir -p "$out"

          kernel_image=
          for candidate in ${kernel}/boot/vmlinuz-*; do
            kernel_image=$candidate
            break
          done
          test -n "$kernel_image"

          ${pkgs.bash}/bin/bash -o pipefail -c '
            serial_log=$1
            shift
            ${pkgs.coreutils}/bin/timeout 900 "$@" 2>&1 \
              | ${pkgs.coreutils}/bin/tee "$serial_log"
          ' dispatch-vm "$out/serial.log" ${pkgs.qemu}/bin/qemu-system-x86_64 \
            -machine q35,accel=${
            if allowTcg
            then "tcg"
            else "kvm"
          } \
            -cpu ${
            if allowTcg
            then "max"
            else "host"
          } \
            -m 2048 -smp 2 -nographic -no-reboot \
            -kernel "$kernel_image" \
            -initrd ${initrd}/initrd.img \
            -append ${lib.escapeShellArg kernelArguments} \
            -drive file="$TMPDIR/disk.img",format=raw,if=virtio \
            -nic none || {
              cat "$out/serial.log" >&2
              exit 1
            }

          ${pkgs.grep}/bin/grep -Fq DISPATCH_SYSTEMD_VM_PASS "$out/serial.log" || {
            cat "$out/serial.log" >&2
            exit 1
          }
          if ${pkgs.grep}/bin/grep -Fq DISPATCH_SYSTEMD_VM_FAIL "$out/serial.log"; then
            cat "$out/serial.log" >&2
            exit 1
          fi
          echo PASS >"$out/result"
        '';
      }
    ];
  }
