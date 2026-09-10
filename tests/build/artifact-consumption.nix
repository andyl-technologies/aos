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
  pathProviderSource = builtins.toFile "artifact-consumption-path-provider.c" ''
    const char *aos_plugin_value(void) { return "plugin-ok\n"; }
  '';
  pathConsumerSource = builtins.toFile "artifact-consumption-path-consumer.c" ''
    #include <dlfcn.h>
    #include <fcntl.h>
    #include <stdio.h>
    #include <string.h>
    #include <sys/wait.h>
    #include <unistd.h>

    // The multi-mode fixture retains every runtime provider in its own output.
    // The audit separately proves that each exact path is actually consumed.
    __attribute__((used)) static const char *const retained_provider_paths[] = {
      AOS_PLUGIN_PROVIDER_PATH,
      AOS_HELPER_PROVIDER_PATH,
      AOS_DATA_PROVIDER_PATH,
    };

    static int plugin(const char *path) {
      void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
      if (handle == NULL) return 10;
      const char *(*value)(void) = dlsym(handle, "aos_plugin_value");
      if (value == NULL) return 11;
      fputs(value(), stdout);
      return dlclose(handle) == 0 ? 0 : 12;
    }

    static int helper(const char *path) {
      int pipefd[2];
      if (pipe(pipefd) != 0) return 20;
      pid_t child = fork();
      if (child < 0) return 21;
      if (child == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(22);
        close(pipefd[1]);
        char *const arguments[] = {(char *)path, NULL};
        execv(path, arguments);
        _exit(23);
      }
      close(pipefd[1]);
      char buffer[128];
      ssize_t count;
      while ((count = read(pipefd[0], buffer, sizeof buffer)) > 0) {
        if (write(STDOUT_FILENO, buffer, (size_t)count) != count) return 24;
      }
      close(pipefd[0]);
      int status;
      return waitpid(child, &status, 0) == child && WIFEXITED(status)
        ? WEXITSTATUS(status) : 25;
    }

    static int data(const char *path) {
      int fd = open(path, O_RDONLY);
      if (fd < 0) return 30;
      char buffer[128];
      ssize_t count;
      while ((count = read(fd, buffer, sizeof buffer)) > 0) {
        if (write(STDOUT_FILENO, buffer, (size_t)count) != count) return 31;
      }
      return close(fd) == 0 ? 0 : 32;
    }

    int main(int argc, char **argv) {
      if (argc != 3) return 2;
      if (strcmp(argv[1], "plugin") == 0) return plugin(argv[2]);
      if (strcmp(argv[1], "helper") == 0) return helper(argv[2]);
      if (strcmp(argv[1], "data") == 0) return data(argv[2]);
      return 3;
    }
  '';
  falsePluginConsumerSource = builtins.toFile "artifact-consumption-false-plugin-consumer.c" ''
    #include <fcntl.h>
    #include <stdio.h>
    #include <string.h>
    #include <unistd.h>

    int main(int argc, char **argv) {
      if (argc != 3) return 2;
      if (strcmp(argv[1], "failed-exec") == 0) {
        char *const arguments[] = {argv[2], NULL};
        execv(argv[2], arguments);
        return fputs("helper-ok\n", stdout) < 0 ? 3 : 0;
      }
      if (strcmp(argv[1], "open-only") == 0) {
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0) return 4;
        if (close(fd) != 0) return 5;
        return fputs("data-ok\n", stdout) < 0 ? 6 : 0;
      }
      int flags = strcmp(argv[1], "failed-open") == 0 ? O_WRONLY | O_TRUNC : O_RDONLY;
      int fd = open(argv[2], flags);
      if (strcmp(argv[1], "failed-open") == 0) {
        if (fd >= 0) return 7;
      } else {
        if (fd < 0) return 8;
        char byte;
        if (read(fd, &byte, 1) != 1) return 9;
        if (close(fd) != 0) return 10;
      }
      return fputs("plugin-ok\n", stdout) < 0 ? 11 : 0;
    }
  '';
  buildToolSource = builtins.toFile "artifact-consumption-build-tool.c" ''
    #include <ctype.h>
    #include <stdio.h>

    int main(int argc, char **argv) {
      if (argc != 2) return 2;
      FILE *input = fopen(argv[1], "rb");
      if (input == NULL) return 3;
      int byte;
      while ((byte = fgetc(input)) != EOF) {
        if (fputc(toupper((unsigned char)byte), stdout) == EOF) return 4;
      }
      return fclose(input) == 0 ? 0 : 5;
    }
  '';
  buildInput = builtins.toFile "artifact-consumption-build-input" "build-tool-ok\n";

  pluginProvider = pkgs.mkDerivation {
    pname = "aos-artifact-consumption-plugin-provider";
    version = "1";
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib"
          gcc -shared -fPIC ${pathProviderSource} -o "$out/lib/plugin.so"
        '';
      }
    ];
  };

  helperProvider = pkgs.mkDerivation {
    pname = "aos-artifact-consumption-helper-provider";
    version = "1";
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cat > "$out/bin/helper" <<'EOF'
          #!${pkgs.bash}/bin/bash
          printf 'helper-ok\n'
          EOF
          chmod +x "$out/bin/helper"
        '';
      }
    ];
  };

  dataProvider = pkgs.mkDerivation {
    pname = "aos-artifact-consumption-data-provider";
    version = "1";
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share"
          printf 'data-ok\n' > "$out/share/input"
        '';
      }
    ];
  };

  pathConsumer = pkgs.mkDerivation {
    pname = "aos-artifact-consumption-path-consumer";
    version = "1";
    src = null;
    runtimeDeps = [pluginProvider helperProvider dataProvider];
    dontNukeRefs = true;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          gcc \
            -DAOS_PLUGIN_PROVIDER_PATH=\"${pluginProvider}/lib/plugin.so\" \
            -DAOS_HELPER_PROVIDER_PATH=\"${helperProvider}/bin/helper\" \
            -DAOS_DATA_PROVIDER_PATH=\"${dataProvider}/share/input\" \
            ${pathConsumerSource} -ldl -o "$out/bin/consumer"
        '';
      }
    ];
  };

  falsePluginConsumer = pkgs.mkDerivation {
    pname = "aos-artifact-consumption-false-plugin-consumer";
    version = "1";
    src = null;
    runtimeDeps = [pluginProvider dataProvider];
    dontNukeRefs = true;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          gcc ${falsePluginConsumerSource} -o "$out/bin/consumer"
        '';
      }
    ];
  };

  buildToolProvider = pkgs.mkDerivation {
    pname = "aos-artifact-consumption-build-tool";
    version = "1";
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          gcc ${buildToolSource} -o "$out/bin/tool"
        '';
      }
    ];
  };

  buildToolConsumer = pkgs.mkDerivation {
    pname = "aos-artifact-consumption-build-tool-consumer";
    version = "1";
    src = null;
    buildDeps = [buildToolProvider];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share"
          ${buildToolProvider}/bin/tool ${buildInput} > "$out/share/output"
        '';
      }
    ];
  };

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

  mkObservedPathAudit = {
    name,
    mechanism,
    consumer,
    consumerPath,
    provider,
    providerPath,
    arguments,
    expectedOutput,
  }:
    import ../../lib/build/artifact-consumption-audit.nix {
      inherit pkgs lib name mechanism consumer consumerPath provider providerPath arguments;
      targetPlatform = {
        system = platform.constraints.os;
        inherit architecture;
      };
      expectedOutputSha256 = "sha256:${builtins.hashString "sha256" expectedOutput}";
      inspector = buildPkgs.aos;
    };

  pluginLoad = mkObservedPathAudit {
    name = "fixture-plugin-load";
    mechanism = "runtime-plugin-load";
    consumer = pathConsumer;
    consumerPath = "/bin/consumer";
    provider = pluginProvider;
    providerPath = "/lib/plugin.so";
    arguments = ["plugin" "${pluginProvider}/lib/plugin.so"];
    expectedOutput = "plugin-ok\n";
  };

  helperExecution = mkObservedPathAudit {
    name = "fixture-helper-execution";
    mechanism = "helper-execution";
    consumer = pathConsumer;
    consumerPath = "/bin/consumer";
    provider = helperProvider;
    providerPath = "/bin/helper";
    arguments = ["helper" "${helperProvider}/bin/helper"];
    expectedOutput = "helper-ok\n";
  };

  immutableData = mkObservedPathAudit {
    name = "fixture-immutable-data";
    mechanism = "immutable-data-input";
    consumer = pathConsumer;
    consumerPath = "/bin/consumer";
    provider = dataProvider;
    providerPath = "/share/input";
    arguments = ["data" "${dataProvider}/share/input"];
    expectedOutput = "data-ok\n";
  };

  buildToolExecution = mkObservedPathAudit {
    name = "fixture-build-tool-execution";
    mechanism = "build-tool-execution";
    consumer = buildToolConsumer;
    consumerPath = "/share/output";
    provider = buildToolProvider;
    providerPath = "/bin/tool";
    arguments = ["${buildInput}"];
    expectedOutput = "BUILD-TOOL-OK\n";
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
    buildDeps = [buildPkgs.bash buildPkgs.binutils buildPkgs.coreutils buildPkgs.grep buildPkgs.jq buildPkgs.sed buildPkgs.strace];
    runtimeDeps = [consumer provider wrongMachine shadowConsumer shadowProvider missingNeededConsumer falsePluginConsumer pluginProvider];
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

          write_path_config() {
            destination=$1
            mode=$2
            jq -cn \
              --arg consumer_root ${lib.escapeShellArg (builtins.toString falsePluginConsumer)} \
              --arg provider_root ${lib.escapeShellArg (builtins.toString pluginProvider)} \
              --arg mode "$mode" \
              --arg output_sha256 "sha256:${builtins.hashString "sha256" "plugin-ok\n"}" \
              '{
                mechanism: "runtime-plugin-load",
                consumer: {artifact: {store_path: $consumer_root}, path: "/bin/consumer"},
                provider: {artifact: {store_path: $provider_root}, path: "/lib/plugin.so"},
                contract: {
                  arguments: [$mode, ($provider_root + "/lib/plugin.so")],
                  output_sha256: $output_sha256,
                  retention: "required"
                }
              }' > "$destination"
          }

          expect_path_failure() {
            label=$1
            config=$2
            expected=$3
            if ${buildPkgs.bash}/bin/bash ${../../lib/build/artifact-consumption-path-check.sh} \
              "$config" "$label.json" 2> "$label.stderr"; then
              echo "observed path negative check unexpectedly passed: $label" >&2
              exit 1
            fi
            grep -F "$expected" "$label.stderr" >/dev/null
          }

          write_path_config failed-plugin-open.json failed-open
          expect_path_failure failed-plugin-open failed-plugin-open.json \
            "did not successfully open the exact provider"

          write_path_config raw-plugin-read.json raw-read
          expect_path_failure raw-plugin-read raw-plugin-read.json \
            "did not map an executable segment from the exact provider"

          jq -cn \
            --arg consumer_root ${lib.escapeShellArg (builtins.toString falsePluginConsumer)} \
            --arg provider_root ${lib.escapeShellArg (builtins.toString dataProvider)} \
            --arg output_sha256 "sha256:${builtins.hashString "sha256" "helper-ok\n"}" \
            '{
              mechanism: "helper-execution",
              consumer: {artifact: {store_path: $consumer_root}, path: "/bin/consumer"},
              provider: {artifact: {store_path: $provider_root}, path: "/share/input"},
              contract: {
                arguments: ["failed-exec", ($provider_root + "/share/input")],
                output_sha256: $output_sha256,
                retention: "required"
              }
            }' > failed-helper-exec.json
          expect_path_failure failed-helper-exec failed-helper-exec.json \
            "did not successfully execute the exact provider"

          jq -cn \
            --arg consumer_root ${lib.escapeShellArg (builtins.toString falsePluginConsumer)} \
            --arg provider_root ${lib.escapeShellArg (builtins.toString dataProvider)} \
            --arg output_sha256 "sha256:${builtins.hashString "sha256" "data-ok\n"}" \
            '{
              mechanism: "immutable-data-input",
              consumer: {artifact: {store_path: $consumer_root}, path: "/bin/consumer"},
              provider: {artifact: {store_path: $provider_root}, path: "/share/input"},
              contract: {
                arguments: ["open-only", ($provider_root + "/share/input")],
                output_sha256: $output_sha256,
                retention: "required"
              }
            }' > open-only-data.json
          expect_path_failure open-only-data open-only-data.json \
            "did not successfully read from the exact provider"

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
    buildDeps = [positive pluginLoad helperExecution immutableData buildToolExecution negative];

    phases = [
      {
        name = "check";
        script = ''
          test -s ${positive}/evidence.json
          test -s ${positive}/explanation.json
          for evidence in \
            ${pluginLoad} ${helperExecution} ${immutableData} ${buildToolExecution}; do
            test -s "$evidence/evidence.json"
            test -s "$evidence/explanation.json"
          done
          grep -Fqx PASS ${negative}/result
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];

    passthru = {
      inherit
        positive
        pluginLoad
        helperExecution
        immutableData
        buildToolExecution
        negative
        consumer
        provider
        ;
    };
  }
