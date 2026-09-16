##! aos-namespace-inspector-manager-query — Bounded systemd 261 manager query helper
{
  lib,
  mkDerivation,
  stdenv,
  pkg-config,
  systemd,
}: let
  helperDirectory = ./_aos-namespace-inspector-manager-query;
  manifest = ../../crates/aos-sandbox-network/src/namespace_inspector/manager_query/systemd_v259_properties.def;
  fixtureDirectory = ../../tests/sandbox;
  helperSources = [
    (helperDirectory + "/main.c")
    (helperDirectory + "/protocol.c")
    (helperDirectory + "/systemd-query.c")
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
      disallowedReferences =
        helperSources
        ++ fixtureSources
        ++ [
          (helperDirectory + "/helper.h")
          (fixtureDirectory + "/namespace-inspector-manager-query-fixture.h")
          manifest
        ];

      phases = [
        {
          name = "build";
          script = ''
            helper=$out/libexec/aos-namespace-inspector-manager-query
            common_flags="-std=c17 -O2 -Wall -Wextra -Werror"
            include_flags="-I${helperDirectory} -I${fixtureDirectory} -I${builtins.dirOf manifest}"

            $CC $common_flags $include_flags \
              -DAOS_MANAGER_QUERY_PROGRAM="\"$helper\"" \
              ${lib.concatStringsSep " " (map toString helperSources)} \
              -o aos-namespace-inspector-manager-query \
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
          '';
        }
        {
          name = "check";
          script = lib.optionalString (!stdenv.isCross) ''
            ./namespace-inspector-manager-query-fixture \
              $out/libexec/aos-namespace-inspector-manager-query
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
          ++ fixtureSources
          ++ [
            (helperDirectory + "/helper.h")
            (fixtureDirectory + "/namespace-inspector-manager-query-fixture.h")
            manifest
            ./aos-namespace-inspector-manager-query.nix
          ]
        );

      meta = {
        description = "Bounded fixed-manifest systemd manager query helper";
        license = "Apache-2.0";
        platforms = ["x86_64-linux" "aarch64-linux"];
      };
    }
