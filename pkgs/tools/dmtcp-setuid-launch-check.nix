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
  tar,
  gcc-libs,
}: let
  # Compile with the same checked-in controls as the ordinary launcher check.
  # Only the guest creates the setuid inode; no host sandbox exception is used.
  controls = mkDerivation {
    pname = "dmtcp-setuid-launch-controls";
    version = "1";
    buildDeps = [tar];
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
          ${tar}/bin/tar -xOf ${dmtcp-selected-writer-park.source}/dmtcp-patched-source.tar.gz \
            ./src/dmtcp_source_command.h > dmtcp_source_command.h
          $CXX -std=c++17 -Wall -Wextra -Werror -pedantic -UNDEBUG -O2 \
            -I. -L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib -pthread -ldl \
            ${./_dmtcp/source-command-controls.cpp} -o "$out/bin/source-command-controls"
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
      # Punctuation in DMTCP's executable-copy directory must stay literal.
      printf '%s\n' 'dmtcp-(copy)' > /proc/sys/kernel/hostname
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

      mkdir command-control
      ${coreutils}/bin/timeout -k 5 60 ${controls}/bin/source-command-controls \
        ${bash}/bin/bash ${coreutils}/bin/readlink "$PWD/command-control" ${coreutils}/bin/cp

      # Keep the ordinary route as an independent inverse, using real children.
      ${coreutils}/bin/timeout -k 5 60 ${controls}/bin/source-unselected-controls \
        ${dmtcp-selected-writer-park} ${controls}/bin/source-unselected-probe "$PWD/ordinary"

      # The real mode bit forces DMTCP's copied-executable route. Both launcher
      # and coordinator must still exit normally and be reaped by the control.
      probe="$PWD/source-setuid-probe (original)'"
      ${coreutils}/bin/cp ${controls}/bin/source-unselected-probe "$probe"
      ${coreutils}/bin/chmod 4755 "$probe"
      test "$(${coreutils}/bin/stat -c %a "$probe")" = 4755
      ${coreutils}/bin/timeout -k 5 60 ${controls}/bin/source-unselected-controls \
        ${dmtcp-selected-writer-park} "$probe" "$PWD/setuid"

      copied=$(${findutils}/bin/find "$PWD/setuid" -type f -name "source-setuid-probe (original)'")
      test -n "$copied"
      test -f "$copied"
      test ! "$copied" -ef "$probe"
      ${diffutils}/bin/cmp "$probe" "$copied"

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
