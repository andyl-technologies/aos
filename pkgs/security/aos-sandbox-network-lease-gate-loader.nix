##! aos-sandbox-network-lease-gate-loader — fixed disarmed TCX gate installer
{
  lib,
  mkDerivation,
  stdenv,
  targetPackages,
  pkg-config,
  linux-headers,
  libbpf,
  aos-sandbox-network-lease-gate,
}: let
  source = ./aos-sandbox-network-lease-gate-loader.c;
  rtnetlinkTest = ../../tests/sandbox/network-lease-gate-loader-rtnetlink.c;
  targetLinuxHeaders =
    if stdenv.isCross
    then targetPackages.linux-headers
    else linux-headers;
  gateObject = "${aos-sandbox-network-lease-gate}/lib/bpf/aos-sandbox-network-lease-gate.bpf.o";
in
  mkDerivation {
    pname = "aos-sandbox-network-lease-gate-loader";
    version = "1";
    src = null;

    buildDeps =
      [pkg-config]
      ++ lib.optional (!stdenv.isCross) linux-headers;
    runtimeDeps = [
      libbpf
      aos-sandbox-network-lease-gate
    ];
    propagatedDeps = [];
    disallowedReferences = [source rtnetlinkTest];

    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -O2 -Wall -Wextra -Werror \
            -DAOS_NETWORK_LEASE_GATE_OBJECT='"${gateObject}"' \
            -I${aos-sandbox-network-lease-gate}/include \
            -I${targetLinuxHeaders}/include \
            ${source} \
            -o aos-sandbox-network-lease-gate-loader \
            $(pkg-config --cflags --libs libbpf)
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-sandbox-network-lease-gate-loader $out/bin/
        '';
      }
      {
        name = "check";
        script =
          if stdenv.isCross
          then ''
            # The target executable is exercised by the architecture-specific VM gate.
            true
          ''
          else ''
            $CC -std=c17 -O2 -Wall -Wextra -Werror \
              -DAOS_NETWORK_LEASE_GATE_OBJECT='"${gateObject}"' \
              -DAOS_NETWORK_LOADER_SOURCE='"${source}"' \
              -I${aos-sandbox-network-lease-gate}/include \
              -I${targetLinuxHeaders}/include \
              ${rtnetlinkTest} \
              -o network-lease-gate-loader-rtnetlink \
              $(pkg-config --cflags --libs libbpf)
            ./network-lease-gate-loader-rtnetlink
          '';
      }
    ];

    passthru = {
      inherit gateObject;
      evidenceSources = [
        (builtins.path {
          path = ./aos-sandbox-network-lease-gate-loader.nix;
          name = "aos-sandbox-network-lease-gate-loader.nix";
        })
        (builtins.path {
          path = source;
          name = "aos-sandbox-network-lease-gate-loader.c";
        })
        (builtins.path {
          path = rtnetlinkTest;
          name = "network-lease-gate-loader-rtnetlink.c";
        })
      ];
    };

    meta = {
      description = "Fixed disarmed TCX lease-gate installer for sandbox networking";
      license = "Apache-2.0";
    };
  }
