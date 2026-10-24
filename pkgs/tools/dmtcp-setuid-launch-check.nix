##! Real setuid copied-executable launch and child retirement in a disposable VM
{
  mkDerivation,
  stdenv,
  buildPackages,
  lib,
  dmtcp-selected-writer-park,
  coreutils,
  findutils,
  diffutils,
  iproute2,
  bash,
  gcc-libs,
}: let
  # Compile with the same checked-in controls as the ordinary launcher check.
  # Only the guest creates the setuid inode; no host sandbox exception is used.
  controls = mkDerivation {
    pname = "dmtcp-setuid-launch-controls";
    version = "1";
    runtimeDeps = [gcc-libs];
    meta.license = "LGPL-3.0-or-later";
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin" "$out/share/licenses/dmtcp-setuid-launch-controls"
          $CXX -std=c++17 -Wall -Wextra -Werror -pedantic -UNDEBUG -O2 \
            ${./_dmtcp/source-unselected-probe.cpp} -o "$out/bin/source-unselected-probe"
          $CXX -std=c++17 -Wall -Wextra -Werror -pedantic -UNDEBUG -O2 \
            -I${./_dmtcp} ${./_dmtcp/source-unselected-controls.cpp} \
            -o "$out/bin/source-unselected-controls"
          cp ${dmtcp-selected-writer-park.source}/licenses/COPYING.LESSER \
            "$out/share/licenses/dmtcp-setuid-launch-controls/LICENSE"
          cp ${./dmtcp-setuid-launch-check.nix} \
            "$out/share/licenses/dmtcp-setuid-launch-controls/recipe.nix"
          ln -s ${dmtcp-selected-writer-park.source} "$out/share/corresponding-source"
        '';
      }
    ];
  };

  testing = import ../../lib/testing/vm.nix {
    pkgs = buildPackages;
    inherit lib;
  };
in
  (testing.mkVMTest {
    name = "dmtcp-setuid-launch";
    memory = 256;
    extraWritableMiB = 64;
    timeout = 150;
    rootfsDeps = [controls dmtcp-selected-writer-park coreutils findutils diffutils iproute2 bash];
    testScript = ''
      set -eu
      test "$(id -u)" -eq 0
      # DMTCP includes the hostname in its executable-copy directory. Give this
      # minimal guest a normal hostname before exercising that launcher path.
      printf '%s\n' dmtcp-launch-check > /proc/sys/kernel/hostname
      # Headless guests start without an active loopback interface. The real
      # coordinator connection stays within this disposable guest.
      ${iproute2}/sbin/ip link set lo up
      export DMTCP_COORD_HOST=127.0.0.1
      mkdir -p /var/lib/dmtcp-setuid-launch/ordinary /var/lib/dmtcp-setuid-launch/setuid
      cd /var/lib/dmtcp-setuid-launch
      report_failure() {
        status=$?
        trap - EXIT
        if test "$status" -ne 0; then
          for log in "$PWD"/ordinary/*-console "$PWD"/setuid/*-console; do
            if test -f "$log"; then
              printf '%s\n' "$log"
              cat "$log"
            fi
          done
        fi
        exit "$status"
      }
      trap report_failure EXIT

      # Keep the ordinary route as an independent inverse, using real children.
      ${coreutils}/bin/timeout -k 5 60 ${controls}/bin/source-unselected-controls \
        ${dmtcp-selected-writer-park} ${controls}/bin/source-unselected-probe "$PWD/ordinary"

      # The real mode bit forces DMTCP's copied-executable route. Both launcher
      # and coordinator must still exit normally and be reaped by the control.
      ${coreutils}/bin/cp ${controls}/bin/source-unselected-probe source-setuid-probe
      ${coreutils}/bin/chmod 4755 source-setuid-probe
      test "$(${coreutils}/bin/stat -c %a source-setuid-probe)" = 4755
      ${coreutils}/bin/timeout -k 5 60 ${controls}/bin/source-unselected-controls \
        ${dmtcp-selected-writer-park} "$PWD/source-setuid-probe" "$PWD/setuid"

      copied=$(${findutils}/bin/find "$PWD/setuid" -type f -name source-setuid-probe)
      test -n "$copied"
      test -f "$copied"
      test ! "$copied" -ef "$PWD/source-setuid-probe"
      ${diffutils}/bin/cmp "$PWD/source-setuid-probe" "$copied"

      echo actual_setuid_copied_launcher_exit_and_reaping=true
    '';
  }).overrideAttrs (_: {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = [stdenv.buildPlatform.constraints.cpu];
          os = ["linux"];
        }
      ];
      target = [];
      role = "build-input";
    };
  })
