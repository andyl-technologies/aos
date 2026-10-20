##! Source build of the Workers runtime used by current Wrangler.
{
  mkBazelPackage,
  buildPackages,
  runCommand,
  tcl,
  fetchurl,
  fetchCargoVendor,
  callPackage,
  lib,
  stdenv,
  glibc,
  python3,
  rust,
  llvm,
  binutils,
  nodejs,
  openjdk,
  bash,
  coreutils,
  findutils,
  diffutils,
  sed,
  gawk,
  grep,
  patch,
  tar,
  gzip,
  xz,
  unzip,
  git,
  perl,
  gnumake,
  pkg-config,
  glibc-locales,
} @ packageArgs: let
  version = "1.20260801.1";
  src = fetchurl {
    urls = ["https://github.com/cloudflare/workerd/archive/refs/tags/v${version}.tar.gz"];
    hash = "0w6dy0k7bxr8ar54hw82makqbpp66nj1c6s5q2rfn0r6jx5zxiws";
  };
  isArmCross = stdenv.isCross && stdenv.hostPlatform.system == "aarch64-linux";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  isSupportedCross = isArmCross || isDarwinCross;
  crossRepositoryName =
    if isDarwinCross
    then "aos_darwin_toolchain"
    else "aos_arm64_toolchain";
  crossToolchain = callPackage (
    if isDarwinCross
    then ./_darwin-toolchain.nix
    else ./_cross-toolchain.nix
  ) {};
  targetRustRepository = callPackage ./_rust-repository.nix {};
  targetGcc = stdenv.cc.cc;
  # Generators execute on the build platform even when their output is compiled
  # for another target. Keep these tools separate from target runtime inputs.
  buildScope =
    if stdenv.isCross
    then buildPackages
    else packageArgs;
  cargoVendorRaw = buildScope.fetchCargoVendor {
    inherit src;
    sourceRoot = "workerd-${version}/deps/rust";
    name = "workerd-modern-cargo-vendor";
    hash = "sha256-qCOe+muhvyVsxmsQeHPLNgXh6vhyY/XdA5iyz0/G3Zs=";
  };
  sourceOnlyCargoVendor = nativeCallPackage ../../build-support/_cargo-source-vendor.nix {};
  cargoVendor = sourceOnlyCargoVendor {
    name = "workerd-modern-cargo-source-only";
    vendor = cargoVendorRaw;
    # This gzip corruption fixture is not needed for a production runtime.
    excludedFiles = ["source-registry-0/flate2-1.1.9/tests/corrupt-gz-file.bin"];
  };
  inherit
    (buildScope)
    runCommand
    tcl
    python3
    rust
    llvm
    binutils
    nodejs
    openjdk
    bash
    coreutils
    findutils
    diffutils
    sed
    gawk
    grep
    patch
    tar
    gzip
    xz
    unzip
    git
    perl
    gnumake
    pkg-config
    glibc-locales
    ;
  nativeStdenv =
    if stdenv.isCross
    then buildPackages.stdenv
    else stdenv;
  nativeCallPackage = path: overrides:
    if !stdenv.isCross
    then callPackage path overrides
    else let
      expression = import path;
      scope = buildPackages // {callPackage = nativeCallPackage;};
    in
      expression ((builtins.intersectAttrs (builtins.functionArgs expression) scope) // overrides);

  nativeClang = nativeCallPackage ./_native-clang.nix {};
  tclBuildTool = runCommand "workerd-modern-tcl-build-tool" {} ''
    mkdir -p "$out/bin"
    test -x "${tcl}/bin/tclsh9.0"
    ln -s "${tcl}/bin/tclsh9.0" "$out/bin/tclsh"
  '';
  cargoBazel = nativeCallPackage ./_cargo-bazel.nix {};
  rustRepository = nativeCallPackage ./_rust-repository.nix {};
  nodeRepository = nativeCallPackage ./_node-repository.nix {};
  esbuildRepository = nativeCallPackage ./_esbuild-repository.nix {};
  pythonRepositories = nativeCallPackage ./_python-repositories.nix {};
  pyodide = nativeCallPackage ./_pyodide.nix {};
  utilityRepositories = nativeCallPackage ./_utility-repositories.nix {};

  repositories =
    {
      "yq.bzl++yq+yq_linux_amd64" = "${utilityRepositories}/yq";
      "tar.bzl++toolchains+bsd_tar_toolchains_linux_amd64" = "${utilityRepositories}/tar";
      "bazel_lib++toolchains+coreutils_linux_amd64" = "${utilityRepositories}/coreutils";
      "bazel_lib++toolchains+copy_directory_linux_amd64" = "${utilityRepositories}/copy_directory";
      "rules_rust++rust+rust_linux_x86_64__x86_64-unknown-linux-gnu__stable_tools" = rustRepository;
      "rules_nodejs++node+nodejs_linux_amd64" = nodeRepository;
      "aspect_rules_esbuild++esbuild+esbuild_linux-x64" = esbuildRepository;
      "rules_python++pip+v8_python_deps_314_jinja2_py3_none_any_85ece445" = "${pythonRepositories}/jinja2";
      "rules_python++pip+v8_python_deps_314_markupsafe_sdist_594c6780" = "${pythonRepositories}/markupsafe";
      "+pyodide+pyodide-314.0.0" = pyodide;
    }
    // lib.optionalAttrs isSupportedCross {
      "rules_rust++rust+rust_linux_x86_64__${stdenv.hostPlatform.config}__stable_tools" = targetRustRepository;
    };

  # Keep the dependency archive independent of the source-built tool outputs.
  # The build phase restores these placeholders using the same map.
  scrub = builtins.unsafeDiscardStringContext;
  scrubMap =
    {
      "${scrub python3}" = "__AOS_PYTHON__";
      "${scrub bash}" = "__AOS_BASH__";
      "${scrub binutils}" = "__AOS_BINUTILS__";
      "${scrub openjdk}" = "__AOS_JDK__";
      "${scrub nativeClang}" = "__AOS_CLANG_WRAPPER__";
      "${scrub llvm}" = "__AOS_LLVM__";
      "${scrub rust}" = "__AOS_RUST__";
      "${scrub cargoBazel}" = "__AOS_CARGO_BAZEL__";
      "${scrub nativeStdenv.gcc}" = "__AOS_BOOTSTRAP_GCC__";
      "${scrub nativeStdenv.glibc}" = "__AOS_BOOTSTRAP_GLIBC__";
    }
    // lib.optionalAttrs isSupportedCross {
      "${scrub crossToolchain}" = "__AOS_ARM64_TOOLCHAIN__";
    };

  prepareSource =
    ''
      ${python3}/bin/python3 ${./prepare-modern-toolchains.py} \
        --python ${python3}/bin/python3 --rust ${rust} --bash ${bash}/bin/bash
    ''
    + lib.optionalString isSupportedCross ''
      ${python3}/bin/python3 ${./prepare-modern-cross.py} --toolchain ${crossToolchain} \
        --repository-name ${crossRepositoryName} --target-os ${
        if isDarwinCross
        then "darwin"
        else "linux"
      }
    '';

  configureEnvironment = ''
    export CARGO_BAZEL_GENERATOR_URL="file://${cargoBazel}/bin/cargo-bazel"
    export CARGO_BAZEL_GENERATOR_SHA256="$(sha256sum ${cargoBazel}/bin/cargo-bazel | cut -d ' ' -f 1)"
    export LOCPATH="${glibc-locales}/lib/locale"
    export LC_ALL=C.UTF-8 LANG=C.UTF-8
  '';
in
  assert (!stdenv.isCross && stdenv.hostPlatform.system == "x86_64-linux") || isSupportedCross;
    mkBazelPackage {
      pname = "workerd-modern-source";
      platformSupport = {
        build = [{abi = ["gnu"]; os = ["linux"];}];
        host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
        target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
        role = "public-package";
      };
      qualification.packageProbe = lib.qualification.commandProbe {
        "primary" = {
          "artifacts" = [];
          "expected" = "The Worker computes and returns the JSON result 42 with HTTP status 200.";
          "files" = {
            "worker.capnp" = "using Workerd = import \"/workerd/workerd.capnp\";\nconst config :Workerd.Config = (\n  services = [(name = \"main\", worker = (\n    modules = [(name = \"worker\", esModule = embed \"worker.js\")],\n    compatibilityDate = \"2024-09-09\"\n  ))],\n  sockets = [(name = \"http\", http = (), service = \"main\")]\n);\n";
            "worker.js" = "export default {\n  async fetch(request) {\n    const result = Number(await request.text()) + 2;\n    return new Response(JSON.stringify({ result }), {\n      headers: { \"content-type\": \"application/json\" }\n    });\n  }\n};\n";
          };
          "input" = "A local Worker module and an HTTP POST containing the number 40.";
          "operation" = "Start the runtime on an inherited loopback socket, execute the Worker through HTTP, and stop the service.";
          "steps" = [
            {
              "argv" = [
                "@python@"
                "-c"
                "import http.client, json, socket, subprocess, tempfile, time\n\nwith socket.socket() as listener, tempfile.TemporaryFile() as log:\n    listener.bind((\"127.0.0.1\", 0))\n    listener.listen()\n    port = listener.getsockname()[1]\n    command = [\"@out@/bin/workerd\", \"serve\", \"worker.capnp\",\n               \"--socket-fd\", f\"http={listener.fileno()}\"]\n    process = subprocess.Popen(command, pass_fds=(listener.fileno(),),\n                               stdout=log, stderr=log)\n    try:\n        deadline = time.monotonic() + 20\n        while True:\n            if process.poll() is not None or time.monotonic() >= deadline:\n                log.seek(0)\n                raise AssertionError(log.read().decode(errors=\"replace\"))\n\n            connection = http.client.HTTPConnection(\"127.0.0.1\", port, timeout=2)\n            try:\n                connection.request(\"POST\", \"/qualification\", body=\"40\")\n                response = connection.getresponse()\n                body = response.read()\n                assert response.status == 200, (response.status, body)\n                assert response.getheader(\"content-type\") == \"application/json\"\n                assert json.loads(body) == {\"result\": 42}, body\n                break\n            except (OSError, http.client.HTTPException):\n                time.sleep(0.1)\n            finally:\n                connection.close()\n    finally:\n        process.terminate()\n        try:\n            process.wait(timeout=10)\n        except subprocess.TimeoutExpired:\n            process.kill()\n            process.wait(timeout=5)\n\nprint(\"workerd-source operation passed\")\n"
              ];
              "exit_code" = 0;
              "stderr" = {
                "exact" = "";
              };
              "stdout" = {
                "exact" = "workerd-source operation passed\n";
              };
            }
          ];
        };
        "badInput" = {
          "artifacts" = [];
          "expected" = "Workerd rejects the malformed configuration with a parse error.";
          "files" = {
            "invalid.capnp" = "this is not capnp\n";
          };
          "input" = "A service configuration containing bytes that are not valid Cap'n Proto source.";
          "operation" = "Parse the malformed configuration before starting the runtime.";
          "steps" = [
            {
              "argv" = [
                "@python@"
                "-c"
                "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/workerd\", \"serve\", \"invalid.capnp\"], capture_output=True, text=True, timeout=10)\noutput = result.stdout + result.stderr\nassert result.returncode != 0 and (\"error\" in output.lower() or \"failed\" in output.lower())\n\nsys.stderr.write(\"workerd-source rejected invalid input\\n\")\nraise SystemExit(7)\n"
              ];
              "exit_code" = 7;
              "observes_rejection" = true;
              "stderr" = {
                "exact" = "workerd-source rejected invalid input\n";
              };
              "stdout" = {
                "exact" = "";
              };
            }
          ];
        };
      };

      # Keep module compatibility at this release until a broader policy is reviewed.
      version = "=${version}";
      inherit src;

      tools = [
        tclBuildTool
        nativeClang
        llvm
        binutils
        python3
        rust
        nodejs
        bash
        coreutils
        findutils
        diffutils
        sed
        gawk
        grep
        patch
        tar
        gzip
        xz
        unzip
        git
        perl
        gnumake
        pkg-config
      ];
      # The linked runtime uses LLVM's C++ ABI and unwind shared libraries.
      # Preserve their runpaths when build-only references are scrubbed.
      runtimeDeps =
        if isDarwinCross
        then [stdenv.darwinRuntimes]
        else if isArmCross
        then [glibc]
        else [llvm];
      inherit scrubMap;
      populateBCR = false;
      captureModuleLock = true;
      removeRepos =
        [
          "bazel_tools"
          "embedded_jdk"
          "local_config_cc"
          "local_jdk"
          "+local_runtime_repo+aos_python"
          "rules_java++toolchains+local_jdk"
          "rules_cc++cc_configure_extension+local_config_cc"
          "rules_cc++cc_configure_extension+local_config_cc_toolchains"
        ]
        ++ lib.optionals isSupportedCross ["+local_repository+${crossRepositoryName}"];
      # Native Linux and ARM64 cross analysis produce distinct snapshots;
      # both Darwin architectures share a third dependency snapshot.
      # Local toolchain repositories are regenerated for the selected target.
      depsHash =
        if isDarwinCross
        then "sha256-pWz9mz8EtXsux1K9bQlViPpX/89BzmtqsOiRFBDgiLE="
        else if isArmCross
        then "sha256-FGjai5OCbqKGqWMdBnDrpcNsH7MfSk0WaVNPWbrDSqw="
        else "sha256-B2XsKE5brhw4DMbw0F8VHfKzVm2N6VR2ptqZIEp+FS8=";
      bazelTarget = "//src/workerd/server:workerd";
      bazelFlags =
        [
          # The dependency snapshot owns repository contents. Bazel 9's shared
          # cache otherwise replaces them with temporary external symlinks.
          "--repo_contents_cache="
          "--extra_toolchains=@@protobuf+//bazel/private/oss/toolchains:protoc_sources_toolchain"
          "--@rules_python//python/config_settings:python_version=3.14"
          "--repo_env=CC=${nativeClang}/bin/clang"
        ]
        ++ lib.mapAttrsToList (name: path: "--override_repository=${name}=${path}") repositories
        ++ lib.optionals isSupportedCross [
          "--platforms=@${crossRepositoryName}//:target-platform"
          "--extra_toolchains=@${crossRepositoryName}//:registered-toolchain"
          "--@v8//bazel/config:v8_target_cpu=${
            if stdenv.hostPlatform.isAarch64
            then "arm64"
            else "x64"
          }"
        ];

      postPatch = prepareSource;
      fetchPostPatch = configureEnvironment;
      postFetch = ''
        ${python3}/bin/python3 ${./clean-bazel-tool-downloads.py} "$bazelOut/external"
        ${python3}/bin/python3 ${./strip-opaque-deps.py} "$bazelOut/external"
      '';
      preBazelBuild =
        configureEnvironment
        + lib.optionalString isSupportedCross ''
          # Shared Bazel setup supplies native compatibility libraries for Rust
          # generators. Target links must resolve their own platform libraries.
          sed -i "\\|^build --linkopt=-L$TMPDIR/rust-link-libs$|d" .bazelrc
          if grep -Fqx "build --linkopt=-L$TMPDIR/rust-link-libs" .bazelrc; then
            echo "Native compatibility libraries leaked into the target link" >&2
            exit 1
          fi

          # ARM64 memcopy uses CHAR_BIT; declare its defining header instead
          # of depending on transitive includes from the C++ standard library.
          patch -d "$TMPDIR/repo-overrides/+http_archive+v8" -p1 < ${./v8-memcopy-climits.patch}
          patch -d "$TMPDIR/repo-overrides/+http+ncrypto" -p1 < ${./ncrypto-climits.patch}
          ${lib.optionalString isDarwinCross ''
            # V8 defaults generator tools to its target configuration to share
            # compilation. Cross builds must execute those generators on Linux.
            python3 - "$TMPDIR/repo-overrides/+http_archive+v8/bazel/defs.bzl" <<'PY'
            from pathlib import Path
            import sys

            definitions = Path(sys.argv[1])
            source = definitions.read_text()
            original = '    return "target"\n'
            if source.count(original) != 1:
                raise SystemExit("Unexpected V8 generator configuration")
            definitions.write_text(source.replace(original, '    return "exec"\n'))
            PY
          ''}
        ''
        + ''
          sed -i '1s|^#!/usr/bin/env bash$|#!${bash}/bin/bash|' tools/unix/workspace-status.sh
          # Patch the generator templates before Bazel creates executable launchers.
          sed -i '1s|^#!/usr/bin/env bash$|#!${bash}/bin/bash|' \
            "$TMPDIR/repo-overrides/aspect_rules_js+/js/private/js_binary.sh.tpl" \
            "$TMPDIR/repo-overrides/aspect_rules_js+/js/private/node_wrapper.sh"
          sed -i 's|^DEFAULT_STUB_SHEBANG = "#!/usr/bin/env python3"$|DEFAULT_STUB_SHEBANG = "#!${python3}/bin/python3"|' \
            "$TMPDIR/repo-overrides/rules_python+/python/private/py_runtime_info.bzl"

          # The generator is an AOS-built store input. Bazel rejects even a
          # file:// download when downloads are disabled for the offline build.
          python3 - "$TMPDIR/repo-overrides/rules_rust+/crate_universe/extensions.bzl" <<'PY'
          from pathlib import Path
          import sys

          extension = Path(sys.argv[1])
          source = extension.read_text()
          download = "    module_ctx.download(**download_kwargs)\n    return output"
          local = (
              "    if generator_url.startswith(\"file://\"):\n"
              "        return module_ctx.path(generator_url[len(\"file://\"):])\n"
              "    module_ctx.download(**download_kwargs)\n"
              "    return output"
          )
          if source.count(download) != 1:
              raise SystemExit("Unexpected rules_rust generator download path")
          extension.write_text(source.replace(download, local))
          PY

          # The module extension splices Cargo manifests before generating
          # Bazel repositories. Feed its manifest the pinned source vendor.
          sed 's|@vendor@|${cargoVendor}|g' \
            ${cargoVendor}/.cargo/config.toml > "$TMPDIR/cargo-vendor-config.toml"
          export CARGO_BAZEL_ISOLATED=false
          export CARGO_HOME="$TMPDIR/cargo-home"
          for index in index.crates.io-1949cf8c6b5b557f index.crates.io-6f17d22bba15001f; do
            mkdir -p "$CARGO_HOME/registry/index/$index"
            printf '%s\n' '{"dl":"https://static.crates.io/crates/{crate}/{crate}-{version}.crate"}' \
              > "$CARGO_HOME/registry/index/$index/config.json"
          done
          python3 - \
            "$TMPDIR/repo-overrides/rules_rust+/crate_universe/extensions.bzl" \
            "$TMPDIR/repo-overrides/rules_rust+/crate_universe/private/common_utils.bzl" \
            "$TMPDIR/cargo-vendor-config.toml" "$CARGO_HOME" <<'PY'
          from pathlib import Path
          import json
          import sys

          extension = Path(sys.argv[1])
          source = extension.read_text()
          config_argument = '            cargo_config = cfg.cargo_config,\n'
          replacement = f'            cargo_config = {json.dumps(sys.argv[3])},\n'
          if source.count(config_argument) != 1:
              raise SystemExit("Unexpected rules_rust Cargo config input")
          extension.write_text(source.replace(config_argument, replacement))

          common = Path(sys.argv[2])
          source = common.read_text()
          rust_environment = '                "RUSTC": str(rustc_path),\n'
          replacement = (
              rust_environment
              + '                "CARGO_NET_OFFLINE": "true",\n'
              + f'                "CARGO_HOME": {json.dumps(sys.argv[4])},\n'
          )
          if source.count(rust_environment) != 1:
              raise SystemExit("Unexpected rules_rust Cargo environment")
          common.write_text(source.replace(rust_environment, replacement))
          PY

        '';
      bazelBuildFlags =
        [
          "-c opt"
          "--spawn_strategy=processwrapper-sandbox,standalone"
          "--java_runtime_version=local_jdk"
          "--tool_java_runtime_version=local_jdk"
        ]
        ++ lib.optionals (!isSupportedCross) [
          "--linkopt=-lc++abi"
          "--linkopt=-lunwind"
        ]
        # Rust links C++ bridge archives with implicit driver libraries disabled.
        ++ lib.optionals isArmCross ["--linkopt=-lstdc++"]
        ++ [
          "--host_linkopt=-lc++abi"
          "--host_linkopt=-lunwind"
        ];

      installPhase =
        (
          if isDarwinCross
          then ''
            mkdir -p "$out/bin" "$out/share/licenses/workerd"
            cp bazel-bin/src/workerd/server/workerd "$out/bin/workerd"
            cp LICENSE "$out/share/licenses/workerd/LICENSE"
          ''
          else if isArmCross
          then ''
            mkdir -p "$out/bin" "$out/lib" "$out/share/licenses/workerd"
            cp bazel-bin/src/workerd/server/workerd "$out/bin/workerd"
            chmod u+w "$out/bin/workerd"
            cp LICENSE "$out/share/licenses/workerd/LICENSE"
            for library in libstdc++.so.6 libgcc_s.so.1 libatomic.so.1; do
              cp -L "${targetGcc}/${stdenv.hostPlatform.config}/lib64/$library" "$out/lib/$library"
              chmod u+w "$out/lib/$library"
              patchelf --set-rpath "${glibc}/lib:$out/lib" "$out/lib/$library"
            done
            mkdir -p "$out/share/licenses/workerd/gcc-runtime"
            cp ${targetGcc.src}/COPYING3 ${targetGcc.src}/COPYING.RUNTIME \
              "$out/share/licenses/workerd/gcc-runtime/"
            patchelf --set-rpath "${glibc}/lib:$out/lib" "$out/bin/workerd"
          ''
          else ''
            mkdir -p "$out/bin" "$out/share/licenses/workerd"
            cp bazel-bin/src/workerd/server/workerd "$out/bin/workerd"
            cp LICENSE "$out/share/licenses/workerd/LICENSE"
            "$out/bin/workerd" --version
          ''
        )
        + ''
          ${python3}/bin/python3 ${./install-modern-notices.py} \
            "$TMPDIR/repo-overrides" ${pyodide} \
            "$out/share/licenses/workerd/dependencies"
        '';

      meta = {
        description = "Cloudflare Workers runtime built from source";
        license = "Apache-2.0";
      };
    }
