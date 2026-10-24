##! Selected native exec preservation codec and kernel identity controls
{
  mkDerivation,
  dmtcp-selected-writer-park,
  coreutils,
  tar,
  gzip,
  bash,
  readline,
  ncurses,
  gcc-libs,
}:
mkDerivation {
  pname = "dmtcp-exec-custody-check";
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

  buildDeps = [coreutils bash tar gzip];
  runtimeDeps = [readline ncurses gcc-libs];

  phases = [
    {
      name = "check";
      script = ''
        # Creating an inherited high descriptor must precede reducing both
        # limits. Declare the regression's builder precondition explicitly.
        ${bash}/bin/bash -c '
          descriptor_limit=$(ulimit -H -n)
          if [ "$descriptor_limit" != unlimited ] && [ "$descriptor_limit" -lt 2048 ]; then
            printf "%s\n" "exec custody check requires hard RLIMIT_NOFILE >= 2048" >&2
            exit 1
          fi
        '

        mkdir native-source
        cd native-source
        ${tar}/bin/tar xf ${dmtcp-selected-writer-park.source}/dmtcp-patched-source.tar.gz
        $CONFIG_SHELL ./configure --prefix="$PWD/unused-install"

        # Upstream headers contain unused placement-new parameters. All other
        # compiler warnings remain errors in the actual production-header test.
        $CXX -std=c++14 -DHAVE_CONFIG_H -Wall -Wextra -Werror \
          -Wno-unused-parameter -UNDEBUG -O2 \
          -I./src -I./include -I./jalib \
          ${./_dmtcp/exec-custody-controls.cpp} -o exec-custody-controls
        ${coreutils}/bin/timeout 120 ./exec-custody-controls

        mkdir -p "$out/share/checks" "$out/share/licenses/dmtcp-exec-custody-check"
        printf '%s\n' 'Eight exec preservation and kernel identity control groups passed.' \
          > "$out/share/checks/exec-custody"
        cp COPYING.LESSER "$out/share/licenses/dmtcp-exec-custody-check/LICENSE"
      '';
    }
  ];

  meta = {
    description = "Checks original selected producer exec state preservation without granting source issuance, restored-account adoption, or node readiness";
    license = "LGPL-3.0-or-later";
  };
}
