##! Source build of the Workers runtime used by current Wrangler.
{
  mkBazelPackage,
  buildPackages,
  runCommand,
  tcl,
  fetchurl,
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
  isArmCross = stdenv.isCross && stdenv.hostPlatform.system == "aarch64-linux";
  crossToolchain = callPackage ./_cross-toolchain.nix {};
  targetRustRepository = callPackage ./_rust-repository.nix {};
  targetGcc = stdenv.cc.cc;
  # Generators execute on the build platform even when their output is compiled
  # for another target. Keep these tools separate from target runtime inputs.
  buildScope =
    if stdenv.isCross
    then buildPackages
    else packageArgs;
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
    // lib.optionalAttrs isArmCross {
      "rules_rust++rust+rust_linux_x86_64__aarch64-unknown-linux-gnu__stable_tools" = targetRustRepository;
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
    // lib.optionalAttrs isArmCross {
      "${scrub crossToolchain}" = "__AOS_ARM64_TOOLCHAIN__";
    };

  prepareSource =
    ''
      ${python3}/bin/python3 ${./prepare-modern-toolchains.py} \
        --python ${python3}/bin/python3 --rust ${rust} --bash ${bash}/bin/bash
    ''
    + lib.optionalString isArmCross ''
      ${python3}/bin/python3 ${./prepare-modern-cross.py} --toolchain ${crossToolchain}
    '';

  configureEnvironment = ''
    export CARGO_BAZEL_GENERATOR_URL="file://${cargoBazel}/bin/cargo-bazel"
    export CARGO_BAZEL_GENERATOR_SHA256="$(sha256sum ${cargoBazel}/bin/cargo-bazel | cut -d ' ' -f 1)"
    export LOCPATH="${glibc-locales}/lib/locale"
    export LC_ALL=C.UTF-8 LANG=C.UTF-8
  '';
in
  assert (!stdenv.isCross && stdenv.hostPlatform.system == "x86_64-linux") || isArmCross;
    mkBazelPackage {
      pname = "workerd-modern-source";
      inherit version;
      src = fetchurl {
        urls = ["https://github.com/cloudflare/workerd/archive/refs/tags/v${version}.tar.gz"];
        hash = "0w6dy0k7bxr8ar54hw82makqbpp66nj1c6s5q2rfn0r6jx5zxiws";
      };

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
        if isArmCross
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
        ++ lib.optionals isArmCross ["+local_repository+aos_arm64_toolchain"];
      # Native and ARM64 analysis produce the same pinned dependency snapshot;
      # local toolchain repositories are regenerated for the selected target.
      depsHash = "sha256-7vU7V20b8HnQHqpzW+2SuwkZihPmZMoUIpbfWZt+8TQ=";
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
        ++ lib.optionals isArmCross [
          "--platforms=@aos_arm64_toolchain//:target-platform"
          "--extra_toolchains=@aos_arm64_toolchain//:registered-toolchain"
          "--@v8//bazel/config:v8_target_cpu=arm64"
        ];

      postPatch = prepareSource;
      fetchPostPatch = configureEnvironment;
      postFetch = ''
        ${python3}/bin/python3 ${./clean-bazel-tool-downloads.py} "$bazelOut/external"
      '';
      preBazelBuild =
        configureEnvironment
        + lib.optionalString isArmCross ''
          # Shared Bazel setup supplies native compatibility libraries for Rust
          # generators. Target links must resolve their ARM64 counterparts.
          sed -i "\\|^build --linkopt=-L$TMPDIR/rust-link-libs$|d" .bazelrc
          if grep -Fqx "build --linkopt=-L$TMPDIR/rust-link-libs" .bazelrc; then
            echo "Native compatibility libraries leaked into the ARM64 link" >&2
            exit 1
          fi

          # ARM64 memcopy uses CHAR_BIT; declare its defining header instead
          # of depending on transitive includes from the C++ standard library.
          patch -d "$TMPDIR/repo-overrides/+http_archive+v8" -p1 < ${./v8-memcopy-climits.patch}
          patch -d "$TMPDIR/repo-overrides/+http+ncrypto" -p1 < ${./ncrypto-climits.patch}
        ''
        + ''
          sed -i '1s|^#!/usr/bin/env bash$|#!${bash}/bin/bash|' tools/unix/workspace-status.sh
          # Patch the generator templates before Bazel creates executable launchers.
          sed -i '1s|^#!/usr/bin/env bash$|#!${bash}/bin/bash|' \
            "$TMPDIR/repo-overrides/aspect_rules_js+/js/private/js_binary.sh.tpl" \
            "$TMPDIR/repo-overrides/aspect_rules_js+/js/private/node_wrapper.sh"
          sed -i 's|^DEFAULT_STUB_SHEBANG = "#!/usr/bin/env python3"$|DEFAULT_STUB_SHEBANG = "#!${python3}/bin/python3"|' \
            "$TMPDIR/repo-overrides/rules_python+/python/private/py_runtime_info.bzl"


        '';
      bazelBuildFlags =
        [
          "-c opt"
          "--spawn_strategy=processwrapper-sandbox,standalone"
          "--java_runtime_version=local_jdk"
          "--tool_java_runtime_version=local_jdk"
        ]
        ++ lib.optionals (!isArmCross) [
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
          if isArmCross
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
