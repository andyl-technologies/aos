##! Exercises realized ELF artifact-consumption evidence and its fail-closed checks.
{
  pkgs,
  lib,
}: let
  buildPkgs = pkgs.buildPackages or pkgs;
  platform = pkgs.stdenv.hostPlatform;
  architecture = platform.constraints.cpu;
  loader = "${pkgs.stdenv.glibc}/lib/${platform.dynamicLinker}";
  rawLinker = "${pkgs.stdenv.binutils}/bin/ld";
  soname = "libaos-contract.so.1";
  symbolVersion = "AOS_CONTRACT_1";

  # Keep the dynamic symbol table larger than a typical pipe buffer. This
  # catches partial readelf pipelines that spuriously fail under pipefail.
  generatedSymbols = builtins.concatStringsSep "\n" (
    builtins.genList
    (index: "int aos_contract_symbol_${builtins.toString index}(void) { return ${builtins.toString index}; }")
    2048
  );
  providerSource = builtins.toFile "artifact-consumption-provider.c" ''
    int aos_contract_value(void) { return 7; }
    ${generatedSymbols}
  '';
  consumerSource = builtins.toFile "artifact-consumption-consumer.c" ''
    extern int aos_contract_value(void);

    __attribute__((used)) void _start(void) {
      volatile int value = aos_contract_value();
      (void)value;
      for (;;) {}
    }
  '';
  emptyConsumerSource = builtins.toFile "artifact-consumption-empty-consumer.c" ''
    __attribute__((used)) void _start(void) {
      for (;;) {}
    }
  '';
  versionScript = builtins.toFile "artifact-consumption.map" ''
    ${symbolVersion} {
      global: aos_contract_*;
      local: *;
    };
  '';

  provider = pkgs.mkDerivation {
    pname = "aos-artifact-consumption-provider";
    version = "1";
    src = null;
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "install";
        script = ''
          set -eu
          mkdir -p "$out/lib"
          gcc -fPIC -ffreestanding -fno-stack-protector -c \
            ${providerSource} -o provider.o
          ${rawLinker} -shared -z noexecstack -z relro -z now \
            -soname ${soname} --version-script ${versionScript} \
            -o "$out/lib/${soname}" provider.o
          ln -s ${soname} "$out/lib/libaos-contract.so"
        '';
      }
    ];
  };

  mkConsumer = {
    name,
    source ? consumerSource,
    searchPath,
    linkProvider ? true,
    runtimeDeps ? [],
  }:
    pkgs.mkDerivation {
      pname = "aos-artifact-consumption-${name}";
      version = "1";
      src = null;
      inherit runtimeDeps;
      dontStrip = true;
      dontNukeRefs = true;
      dontPatchELF = true;

      phases = [
        {
          name = "install";
          script = ''
            set -eu
            mkdir -p "$out/bin"
            gcc -ffreestanding -fno-pie -fno-stack-protector -c \
              ${source} -o consumer.o
            ${rawLinker} -z noexecstack -z relro -z now \
              --dynamic-linker ${loader} --enable-new-dtags \
              -rpath ${lib.escapeShellArg (builtins.concatStringsSep ":" searchPath)} \
              -e _start -o "$out/bin/consumer" consumer.o \
              ${lib.optionalString linkProvider "-L${provider}/lib -laos-contract"}
          '';
        }
      ];
    };

  consumer = mkConsumer {
    name = "consumer";
    searchPath = ["${provider}/lib"];
    runtimeDeps = [provider];
  };

  positive = import ../../lib/build/artifact-consumption-audit.nix {
    inherit pkgs lib consumer provider loader;
    name = "fixture-linkage";
    consumerPath = "/bin/consumer";
    providerPath = "/lib/${soname}";
    targetPlatform = {
      system = platform.constraints.os;
      inherit architecture;
    };
    inherit soname;
    needed = [soname];
    searchPath = ["${provider}/lib"];
    searchPathKind = "runpath";
    symbols = [
      {
        name = "aos_contract_value";
        version = symbolVersion;
      }
    ];
    inspector = buildPkgs.aos;
  };

  wrongMachine = pkgs.mkDerivation {
    pname = "aos-artifact-consumption-wrong-machine";
    version = "1";
    src = null;
    runtimeDeps = [provider];
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "install";
        script = ''
          set -eu
          mkdir -p "$out/lib"
          cp ${provider}/lib/${soname} "$out/lib/${soname}"
          chmod u+w "$out/lib/${soname}"
          printf '${
            if platform.isx86_64
            then "\\267\\000"
            else "\\076\\000"
          }' | dd of="$out/lib/${soname}" bs=1 seek=18 conv=notrunc status=none
        '';
      }
    ];
  };

  shadowProvider = pkgs.mkDerivation {
    pname = "aos-artifact-consumption-shadow-provider";
    version = "1";
    src = null;
    runtimeDeps = [provider];
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "install";
        script = ''
          set -eu
          mkdir -p "$out/lib"
          cp ${provider}/lib/${soname} "$out/lib/${soname}"
        '';
      }
    ];
  };

  shadowConsumer = mkConsumer {
    name = "shadow-consumer";
    searchPath = ["${shadowProvider}/lib" "${provider}/lib"];
    runtimeDeps = [shadowProvider provider];
  };

  missingNeededConsumer = mkConsumer {
    name = "missing-needed-consumer";
    source = emptyConsumerSource;
    searchPath = ["${provider}/lib"];
    linkProvider = false;
    runtimeDeps = [provider];
  };

  negative = buildPkgs.mkDerivation {
    pname = "aos-artifact-consumption-negative-checks";
    version = "1";
    src = null;
    buildDeps = [buildPkgs.bash buildPkgs.binutils buildPkgs.coreutils buildPkgs.grep buildPkgs.jq buildPkgs.sed];
    runtimeDeps = [consumer provider wrongMachine shadowConsumer shadowProvider missingNeededConsumer];
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "check";
        script = ''
          set -eu

          write_config() {
            destination=$1
            consumer_root=$2
            provider_root=$3
            search_path=$4
            needed=$5

            jq -cn \
              --arg consumer_root "$consumer_root" \
              --arg provider_root "$provider_root" \
              --arg loader ${lib.escapeShellArg loader} \
              --arg architecture ${lib.escapeShellArg architecture} \
              --arg soname ${lib.escapeShellArg soname} \
              --arg search_path "$search_path" \
              --argjson needed "$needed" \
              '{
                consumer: {artifact: {store_path: $consumer_root}, path: "/bin/consumer"},
                provider: {artifact: {store_path: $provider_root}, path: "/lib/${soname}"},
                platforms: {target: {architecture: $architecture}},
                contract: {
                  loader: $loader,
                  needed: $needed,
                  search_path: ($search_path | split(":")),
                  search_path_kind: "runpath",
                  soname: $soname,
                  symbols: [{name: "aos_contract_value", version: "${symbolVersion}"}]
                }
              }' > "$destination"
          }

          expect_failure() {
            label=$1
            config=$2
            expected=$3
            if ${buildPkgs.bash}/bin/bash ${../../lib/build/artifact-consumption-elf-check.sh} \
              "$config" "$label.json" 2> "$label.stderr"; then
              echo "artifact consumption negative check unexpectedly passed: $label" >&2
              exit 1
            fi
            if ! grep -F "$expected" "$label.stderr" >/dev/null; then
              echo "unexpected $label diagnostic:" >&2
              cat "$label.stderr" >&2
              exit 1
            fi
          }

          write_config wrong-machine.json ${consumer} ${wrongMachine} \
            ${provider}/lib '["${soname}"]'
          expect_failure wrong-machine wrong-machine.json "machine"

          write_config shadow.json ${shadowConsumer} ${provider} \
            '${shadowProvider}/lib:${provider}/lib' '["${soname}"]'
          expect_failure shadow shadow.json "earlier same-SONAME artifact"

          write_config missing-needed.json ${missingNeededConsumer} ${provider} \
            ${provider}/lib '[]'
          expect_failure missing-needed missing-needed.json \
            "provider SONAME is absent from the consumer DT_NEEDED set"

          graph_root=/nix/store/00000000000000000000000000000000-root
          graph_dependency=/nix/store/11111111111111111111111111111111-dependency
          graph_disconnected=/nix/store/22222222222222222222222222222222-disconnected
          jq -cn \
            --arg root "$graph_root" \
            --arg dependency "$graph_dependency" \
            --arg disconnected "$graph_disconnected" \
            '[
              {path:$root,narHash:"sha256:root",narSize:1,references:[$dependency]},
              {path:$dependency,narHash:"sha256:dependency",narSize:2,references:[$dependency]},
              {path:$disconnected,narHash:"sha256:disconnected",narSize:3,references:[]}
            ]' > graph-valid.json

          expect_graph_failure() {
            label=$1
            if jq -c --arg root "$graph_root" \
              -f ${../../pkgs/build-support/_ability-closure-graph.jq} \
              "graph-$label.json" > /dev/null 2> "graph-$label.stderr"; then
              echo "ability closure graph negative check unexpectedly passed: $label" >&2
              exit 1
            fi
            grep -F "ability closure export graph is malformed or incomplete" \
              "graph-$label.stderr" > /dev/null
          }

          jq '.[2].path = .[1].path' graph-valid.json > graph-duplicate.json
          expect_graph_failure duplicate

          jq 'del(.[0])' graph-valid.json > graph-missing-root.json
          expect_graph_failure missing-root

          jq 'del(.[1])' graph-valid.json > graph-missing-reference.json
          expect_graph_failure missing-reference

          jq '.[2].path = "/nix/store/not-a-store-path"' \
            graph-valid.json > graph-malformed-path.json
          expect_graph_failure malformed-path

          jq -c --arg root "$graph_root" \
            -f ${../../pkgs/build-support/_ability-closure-graph.jq} \
            graph-valid.json > graph-reachable.jsonl
          test "$(wc -l < graph-reachable.jsonl)" -eq 2
          grep -Fq "$graph_root" graph-reachable.jsonl
          grep -Fq "$graph_dependency" graph-reachable.jsonl
          if grep -Fq "$graph_disconnected" graph-reachable.jsonl; then
            echo "ability closure graph retained a disconnected export member" >&2
            exit 1
          fi

          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  };
in
  buildPkgs.mkDerivation {
    pname = "aos-artifact-consumption-check";
    version = "1";
    src = null;
    buildDeps = [positive negative];

    phases = [
      {
        name = "check";
        script = ''
          test -s ${positive}/evidence.json
          test -s ${positive}/explanation.json
          grep -Fqx PASS ${negative}/result
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];

    passthru = {inherit positive negative consumer provider;};
  }
