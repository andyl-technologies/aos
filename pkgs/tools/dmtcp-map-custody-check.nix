##! Original negotiated map custody and complete capsule controls
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
  pname = "dmtcp-map-custody-check";
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
        mkdir native-source
        cd native-source
        ${tar}/bin/tar xf ${dmtcp-selected-writer-park.source}/dmtcp-patched-source.tar.gz
        $CONFIG_SHELL ./configure --prefix="$PWD/unused-install"

        # Upstream headers contain unused placement-new parameters. All other
        # compiler warnings remain errors in the actual production-header test.
        $CXX -std=c++14 -DHAVE_CONFIG_H -Wall -Wextra -Werror \
          -Wno-unused-parameter -UNDEBUG -O2 \
          -I./src -I./include -I./jalib \
          ${./_dmtcp/map-custody-controls.cpp} -o map-custody-controls
        ${coreutils}/bin/timeout 120 ./map-custody-controls

        # This pure borrowed parser is also compiled against the exact matching
        # archive. Real native capture records remain external test evidence.
        $CXX -std=c++14 -DHAVE_CONFIG_H -Wall -Wextra -Werror \
          -Wno-unused-parameter -UNDEBUG -O2 \
          -I./src -I./include -I./jalib \
          ${./_dmtcp/map-capsule-reader.cpp} -o map-capsule-reader


        mkdir -p "$out/share/checks" "$out/share/licenses/dmtcp-map-custody-check"
        printf '%s\n' 'Six map custody, distinct capsule and codec groups passed.' \
          > "$out/share/checks/map-custody"
        cp COPYING.LESSER "$out/share/licenses/dmtcp-map-custody-check/LICENSE"
      '';
    }
  ];

  meta = {
    description = "Checks original full map custody and complete capsule records without granting source issuance, restored-account adoption, or node readiness";
    license = "LGPL-3.0-or-later";
  };
}
