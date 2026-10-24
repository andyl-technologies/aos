##! Original source-owned thread and shared-area exec mechanism checks
{
  mkDerivation,
  dmtcp-selected-writer-park,
  dmtcp-setuid-launch-check,
  coreutils,
  tar,
  gzip,
  grep,
  bash,
  readline,
  ncurses,
  gcc-libs,
}:
mkDerivation {
  pname = "dmtcp-source-owners-check";
  version = "1";

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
        cpu = ["x86_64" "aarch64"];
        os = ["linux"];
      }
    ];
    target = [];
    role = "public-package";
  };

  buildDeps = [coreutils bash tar gzip grep dmtcp-setuid-launch-check];
  runtimeDeps = [readline ncurses gcc-libs];

  phases = [
    {
      name = "check";
      script = ''
        mkdir native-source
        cd native-source
        ${tar}/bin/tar --no-same-owner -xf "${dmtcp-selected-writer-park.source}/dmtcp-patched-source.tar.gz"
        $CONFIG_SHELL ./configure --prefix="$PWD/unused-install"

        $CXX -std=c++17 -DHAVE_CONFIG_H -Wall -Wextra -Werror -pedantic -UNDEBUG -O2 \
          -pthread -I./src -I./include -I./jalib \
          ${./_dmtcp/shared-area-controls.cpp} -o shared-area-controls
        for mode in 0 1 2 3 4 5 6 7; do
          ${coreutils}/bin/timeout 120 ./shared-area-controls "$mode" "$PWD/shared-control-$mode"
        done

        $CXX -std=c++17 -DHAVE_CONFIG_H -Wall -Wextra -Werror -pedantic -UNDEBUG -O2 \
          -pthread -I./src -I./include -I./jalib \
          ${./_dmtcp/thread-owner-controls.cpp} -o thread-owner-controls
        ${coreutils}/bin/timeout 120 ./thread-owner-controls

        $CXX -std=c++17 -Wall -Wextra -Werror -pedantic -UNDEBUG -O2 -I./src \
          ${./_dmtcp/source-launch-probe.cpp} -o source-launch-probe
        $CXX -std=c++17 -Wall -Wextra -Werror -pedantic -UNDEBUG -O2 \
          -I${./_dmtcp} ${./_dmtcp/source-launch-controls.cpp} -o source-launch-controls
        mkdir selected-launch
        ${coreutils}/bin/timeout 120 ./source-launch-controls \
          ${dmtcp-selected-writer-park} "$PWD/source-launch-probe" "$PWD/selected-launch"

        # The ordinary route retains its original zero-exit behavior. Keep
        # this inverse independent of the selected refusal-on-EOF lifecycle.
        $CXX -std=c++17 -Wall -Wextra -Werror -pedantic -UNDEBUG -O2 \
          ${./_dmtcp/source-unselected-probe.cpp} -o source-unselected-probe
        $CXX -std=c++17 -Wall -Wextra -Werror -pedantic -UNDEBUG -O2 \
          -I${./_dmtcp} ${./_dmtcp/source-unselected-controls.cpp} -o source-unselected-controls
        mkdir nonselected-launch
        ${coreutils}/bin/timeout 120 ./source-unselected-controls \
          ${dmtcp-selected-writer-park} "$PWD/source-unselected-probe" "$PWD/nonselected-launch"

        # Exercise the source-selected shell, wait/signal statuses and real
        # canceled-child retirement with one coherent source-built C++ runtime.
        $CXX -std=c++17 -DHAVE_CONFIG_H -Wall -Wextra -Werror -pedantic -UNDEBUG -O2 \
          -I./src -L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib -pthread -ldl \
          ${./_dmtcp/source-command-controls.cpp} -o source-command-controls
        mkdir source-command-control
        ${coreutils}/bin/timeout 120 ./source-command-controls \
          ${bash}/bin/bash ${coreutils}/bin/readlink "$PWD/source-command-control"

        # Nix forbids setting setuid bits in its host build sandbox. Require
        # the real copied-executable control in a disposable guest instead.
        test "$(cat ${dmtcp-setuid-launch-check}/result)" = PASS
        ${grep}/bin/grep -Eq '^actual_setuid_copied_launcher_exit_and_reaping=true[[:space:]]*$' \
          ${dmtcp-setuid-launch-check}/serial.log

        mkdir -p "$out/share/checks" "$out/share/licenses/dmtcp-source-owners-check"
        printf '%s\n' 'Source-owned thread/shared-area controls and actual selected launcher/library exec observation passed; no whole-node issuance or readiness.' \
          > "$out/share/checks/source-owners"
        cp COPYING.LESSER "$out/share/licenses/dmtcp-source-owners-check/LICENSE"
      '';
    }
  ];

  meta = {
    description = "Checks original native source-resource births and complete exec preservation without granting whole-node cut issuance, restored-account adoption or readiness";
    license = "LGPL-3.0-or-later";
  };
}
