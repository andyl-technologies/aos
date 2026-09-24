##! aos-namespace-inspector-manager-query — Bounded systemd 261 manager query helper
{
  lib,
  mkDerivation,
  stdenv,
  pkg-config,
  systemd,
}: let
  helperDirectory = builtins.path {
    path = ./_aos-namespace-inspector-manager-query;
    name = "aos-namespace-inspector-manager-query-source";
  };
  manifestDirectory = builtins.path {
    path = ../../crates/aos-sandbox-network/src/namespace_inspector/manager_query;
    name = "aos-namespace-inspector-manager-query-manifest";
    filter = path: type:
      type == "directory" || builtins.baseNameOf path == "systemd_v259_properties.def";
  };
  manifest = manifestDirectory + "/systemd_v259_properties.def";
  fixtureDirectory = builtins.path {
    path = ../../tests/sandbox;
    name = "aos-namespace-inspector-manager-query-fixture-source";
    filter = path: type:
      type == "directory"
      || lib.hasPrefix "namespace-inspector-manager-query-fixture" (builtins.baseNameOf path);
  };
  helperSources = [
    (helperDirectory + "/main.c")
    (helperDirectory + "/protocol.c")
    (helperDirectory + "/systemd-query.c")
    (helperDirectory + "/fd-table.c")
  ];
  brokerSources = [
    (helperDirectory + "/broker-query.c")
    (helperDirectory + "/fd-table.c")
  ];
  fixtureSources = [
    (fixtureDirectory + "/namespace-inspector-manager-query-fixture.c")
    (fixtureDirectory + "/namespace-inspector-manager-query-fixture-bus.c")
    (fixtureDirectory + "/namespace-inspector-manager-query-fixture-cases.c")
  ];
in
  assert systemd.version == "261.2";
    mkDerivation {
      pname = "aos-namespace-inspector-manager-query";
      version = "1";
      src = null;

      buildDeps = [pkg-config];
      runtimeDeps = [systemd];
      propagatedDeps = [];
      disallowedReferences = [helperDirectory fixtureDirectory manifestDirectory];

      phases = [
        {
          name = "build";
          script = ''
            helper=$out/libexec/aos-namespace-inspector-manager-query
            common_flags="-std=c17 -O2 -Wall -Wextra -Werror"
            include_flags="-I${helperDirectory} -I${fixtureDirectory} -I${manifestDirectory}"

            $CC $common_flags $include_flags \
              -DAOS_MANAGER_QUERY_PROGRAM="\"$helper\"" \
              ${lib.concatStringsSep " " (map toString helperSources)} \
              -o aos-namespace-inspector-manager-query \
              $(pkg-config --cflags --libs libsystemd)

            broker_helper=$out/libexec/aos-network-broker-manager-query
            $CC $common_flags $include_flags \
              -DAOS_BROKER_QUERY_PROGRAM="\"$broker_helper\"" \
              ${lib.concatStringsSep " " (map toString brokerSources)} \
              -o aos-network-broker-manager-query \
              $(pkg-config --cflags --libs libsystemd)

            $CC $common_flags $include_flags \
              ${lib.concatStringsSep " " (map toString fixtureSources)} \
              -o namespace-inspector-manager-query-fixture \
              $(pkg-config --cflags --libs libsystemd)
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p $out/libexec
            cp aos-namespace-inspector-manager-query $out/libexec/
            cp aos-network-broker-manager-query $out/libexec/
          '';
        }
        {
          name = "check";
          script = lib.optionalString (!stdenv.isCross) ''
            ./namespace-inspector-manager-query-fixture \
              $out/libexec/aos-namespace-inspector-manager-query

            # The broker mode is separately linked and has no ambient entry.
            broker_status=0
            $out/libexec/aos-network-broker-manager-query || broker_status=$?
            test "$broker_status" -eq 254
          '';
        }
      ];

      passthru.evidenceSources =
        map
        (source:
          builtins.path {
            path = source;
            name = builtins.baseNameOf source;
          })
        (
          helperSources
          ++ brokerSources
          ++ fixtureSources
          ++ [
            (helperDirectory + "/helper.h")
            (fixtureDirectory + "/namespace-inspector-manager-query-fixture.h")
            manifest
            ./aos-namespace-inspector-manager-query.nix
          ]
        );

      meta = {
        description = "Bounded inspector-self and broker-owned systemd manager query helpers";
        license = "Apache-2.0";
        platforms = ["x86_64-linux" "aarch64-linux"];
      };
    }
