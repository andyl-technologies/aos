##! Envoy proxy — high-performance L7 proxy built from source
##!
##! Uses mkBazelPackage (two-phase FOD build adapted from nixpkgs):
##! (1) fetchBazelDeps fetches all Bazel external deps via `bazel build --nobuild`
##! (2) bazelPhases patchelfs downloaded ELFs and builds offline
{
  mkBazelPackage,
  fetchBazelDeps,
  stdenv,
  buildPackages,
  fetchurl,
  lib,
  bazel-7,
  bash,
  coreutils,
  which,
  zip,
  unzip,
  gawk,
  python3,
  openjdk,
  gcc,
  binutils,
  llvm,
  rust,
  cmake,
  ninja,
  grep,
  gzip,
  patch,
  diffutils,
  findutils,
  sed,
  tar,
  xz,
  file,
  ca-certificates,
  perl,
  gnumake,
  pkg-config,
  autoconf,
  automake,
  m4,
  patchelf,
  bootstrapTools,
}: let
  version = "1.37.0";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;

  # Repository rules, generators, and execution-platform actions run on the
  # Linux builder.  Keep those tools native while the explicit Bazel target
  # toolchains below select the AOS Darwin compiler and Rust standard library
  # for the final Envoy binary.
  buildBazel =
    if isDarwinCross
    then buildPackages.bazel-7
    else bazel-7;
  buildJdk =
    if isDarwinCross
    then buildPackages.openjdk
    else openjdk;
  buildBash =
    if isDarwinCross
    then buildPackages.bash
    else bash;
  buildCoreutils =
    if isDarwinCross
    then buildPackages.coreutils
    else coreutils;
  buildWhich =
    if isDarwinCross
    then buildPackages.which
    else which;
  buildZip =
    if isDarwinCross
    then buildPackages.zip
    else zip;
  buildUnzip =
    if isDarwinCross
    then buildPackages.unzip
    else unzip;
  buildGawk =
    if isDarwinCross
    then buildPackages.gawk
    else gawk;
  buildPython =
    if isDarwinCross
    then buildPackages.python3
    else python3;
  buildGcc =
    if isDarwinCross
    then buildPackages.gcc
    else gcc;
  buildBinutils =
    if isDarwinCross
    then buildPackages.binutils
    else binutils;
  buildLlvm =
    if isDarwinCross
    then buildPackages.llvm
    else llvm;
  buildRust =
    if isDarwinCross
    then rust.passthru.buildTool
    else rust;
  nativeRust =
    if isDarwinCross
    then buildPackages.rust
    else rust;
  buildCmake =
    if isDarwinCross
    then buildPackages.cmake
    else cmake;
  buildNinja =
    if isDarwinCross
    then buildPackages.ninja
    else ninja;
  buildGrep =
    if isDarwinCross
    then buildPackages.grep
    else grep;
  buildGzip =
    if isDarwinCross
    then buildPackages.gzip
    else gzip;
  buildPatch =
    if isDarwinCross
    then buildPackages.patch
    else patch;
  buildDiffutils =
    if isDarwinCross
    then buildPackages.diffutils
    else diffutils;
  buildFindutils =
    if isDarwinCross
    then buildPackages.findutils
    else findutils;
  buildSed =
    if isDarwinCross
    then buildPackages.sed
    else sed;
  buildTar =
    if isDarwinCross
    then buildPackages.tar
    else tar;
  buildXz =
    if isDarwinCross
    then buildPackages.xz
    else xz;
  buildFile =
    if isDarwinCross
    then buildPackages.file
    else file;
  buildPerl =
    if isDarwinCross
    then buildPackages.perl
    else perl;
  buildGnumake =
    if isDarwinCross
    then buildPackages.gnumake
    else gnumake;
  buildPkgConfig =
    if isDarwinCross
    then buildPackages.pkg-config
    else pkg-config;
  buildAutoconf =
    if isDarwinCross
    then buildPackages.autoconf
    else autoconf;
  buildAutomake =
    if isDarwinCross
    then buildPackages.automake
    else automake;
  buildM4 =
    if isDarwinCross
    then buildPackages.m4
    else m4;
  buildCaCertificates =
    if isDarwinCross
    then buildPackages.ca-certificates
    else ca-certificates;
  buildPatchelf =
    if isDarwinCross
    then buildPackages.patchelf
    else patchelf;
  buildBootstrapTools =
    if isDarwinCross
    then buildPackages.bootstrapTools
    else bootstrapTools;
  darwinBazelCpu =
    if stdenv.hostPlatform.isAarch64
    then "darwin_arm64"
    else "darwin_x86_64";
  darwinBazelCpuConstraint =
    if stdenv.hostPlatform.isAarch64
    then "aarch64"
    else "x86_64";
  darwinTargetTriple = stdenv.hostPlatform.config;
  llvmMajor = builtins.head (lib.splitString "." buildLlvm.version);

  envoyCredentialNames = [
    "tls-certificate"
    "tls-private-key"
    "validation-ca"
  ];

  envoyCredentialSource = name: "/run/credstore/envoy/${name}";

  tools = [
    buildBash
    buildCoreutils
    buildWhich
    buildZip
    buildUnzip
    buildGawk
    buildPython
    buildGcc
    buildBinutils
    buildLlvm
    buildRust
    buildCmake
    buildNinja
    buildGrep
    buildGzip
    buildPatch
    buildDiffutils
    buildFindutils
    buildSed
    buildTar
    buildXz
    buildFile
    buildPerl
    buildGnumake
    buildPkgConfig
    buildAutoconf
    buildAutomake
    buildM4
  ];

  src = fetchurl {
    urls = [
      "https://github.com/envoyproxy/envoy/archive/v${version}.tar.gz"
    ];
    hash = "sha256-XPOlNCvf/owcwowK+mGiRlTR94FIDT3MImyB/kGh5xM=";
  };
  darwinMdnsResponderSrc =
    if isDarwinCross
    then
      fetchurl {
        urls = [
          "https://github.com/darlinghq/darling-mDNSResponder/archive/7e38ef562b4f3d41bffabb3e30d844d8042d3bbd.tar.gz"
        ];
        hash = "sha256-hPVgEJgzqCQA0xNHfdnwSIhKHaVFMHONnKY72L2Rk5c=";
      }
    else null;

  # Script to clean up python toolchain references that the patch may miss
  fixPythonBzl = builtins.toFile "fix_python_bzl.py" ''
    import re, sys
    with open(sys.argv[1], 'r') as f:
        content = f.read()
    # Remove python_register_toolchains(...) call block (handles nested parens)
    content = re.sub(r'\n\s*#[^\n]*[Rr]egisters[^\n]*\n', '\n', content)
    content = re.sub(r'\n\s*python_register_toolchains\(.*?\n\s*\)\n', '\n', content, flags=re.DOTALL)
    # Remove _python_minor_version function if still present
    content = re.sub(r'\ndef _python_minor_version\([^)]*\):\n[^\n]*\n', '\n', content)
    # Remove PYTHON_VERSION/PYTHON_MINOR_VERSION if still present
    content = re.sub(r'\n# Python version[^\n]*\n', '\n', content)
    content = re.sub(r'\nPYTHON_VERSION = [^\n]*\n', '\n', content)
    content = re.sub(r'\nPYTHON_MINOR_VERSION = [^\n]*\n', '\n', content)
    # Remove python_version parameter from function signature and calls
    content = re.sub(r',\s*\n\s*python_version\s*=\s*PYTHON_VERSION', "", content)
    content = re.sub(r'\s*python_version\s*=\s*python_version,', "", content)
    with open(sys.argv[1], 'w') as f:
        f.write(content)
  '';

  # Script to replace yq usage in repo.bzl with dummy data.
  # The envoy_repo repository rule uses yq (a pre-built Go binary) to parse
  # .github/config.yml. The yq binary can't execute in the Nix sandbox.
  fixRepoBzl = builtins.toFile "fix_repo_bzl.py" ''
    import re, sys
    with open(sys.argv[1], "r") as f:
        content = f.read()

    old_block = """    json_result = repository_ctx.execute([
            repository_ctx.path(repository_ctx.attr.yq),
            repository_ctx.path(repository_ctx.attr.envoy_ci_config),
            "-ojson",
        ])
        if json_result.return_code != 0:
            fail("yq failed: {}".format(json_result.stderr))
        repository_ctx.file("ci-config.json", json_result.stdout)
        config_data = json.decode(repository_ctx.read("ci-config.json"))"""

    # Provide dummy container data — not needed for building from source
    new_block = """    # AOS: skip yq (pre-built binary incompatible with Nix sandbox).
        # Provide dummy CI container config — not needed for source builds.
        config_data = {"build-image": {"repo": "envoyproxy/envoy-build-ubuntu", "repo-gcr": "envoyproxy/envoy-build-ubuntu", "sha": "dummy", "sha-gcc": "dummy", "sha-mobile": "dummy", "sha-worker": "dummy", "tag": "dummy"}}"""

    content = content.replace(old_block, new_block)

    # Also remove the yq attr from _envoy_repo since it's no longer needed
    content = content.replace('"yq": attr.label(default = "@yq"),', "")

    with open(sys.argv[1], "w") as f:
        f.write(content)
  '';

  # Store path scrubbing map — shared between fetch and build phases
  # Use unsafeDiscardStringContext because Nix disallows store path refs as dynamic attr keys
  scrub = builtins.unsafeDiscardStringContext;
  scrubMap = {
    "${scrub buildPython}" = "__AOS_PYTHON__";
    "${scrub buildBash}" = "__AOS_BASH__";
    "${scrub buildCoreutils}" = "__AOS_COREUTILS__";
    "${scrub buildRust}" = "__AOS_RUST__";
    "${scrub buildJdk}" = "__AOS_JDK__";
    "${scrub buildGcc}" = "__AOS_GCC__";
    "${scrub buildBinutils}" = "__AOS_BINUTILS__";
    "${scrub buildLlvm}" = "__AOS_LLVM__";
  };

  # Bazel's repository and execution platforms remain native Linux.  This
  # crosstool is selected only for target C, C++, and link actions, so no
  # Mach-O helper is ever executed by the builder.
  darwinToolchainSetup = lib.optionalString isDarwinCross ''
    mkdir -p aos-darwin-toolchain
    ${buildUnzip}/bin/unzip -jo "${buildBazel.src}" \
      tools/cpp/unix_cc_toolchain_config.bzl \
      -d aos-darwin-toolchain
    mkdir -p aos-darwin-toolchain/include
    ${buildTar}/bin/tar -xOf ${darwinMdnsResponderSrc} \
      --wildcards '*/mDNSShared/dns_sd.h' \
      > aos-darwin-toolchain/include/dns_sd.h

    # Envoy registers the upstream download-only LLVM toolchain even when an
    # explicit target crosstool is selected.  Its only remaining consumers are
    # two compiler-rt/libunwind build settings in .bazelrc; AOS supplies both
    # from the Darwin runtimes instead.  Remove the registration and settings
    # together so offline repository resolution remains fail closed.
    test "$(grep -Fc '    _toolchains_llvm()' bazel/repositories.bzl)" = 1
    test "$(grep -Fc -- '@toolchains_llvm//toolchain/config:' .bazelrc)" = 4
    sed -i '/^    _toolchains_llvm()$/d' bazel/repositories.bzl
    sed -i '\|@toolchains_llvm//toolchain/config:|d' .bazelrc

    # The generated macOS feature assumes `ar` is Apple's libtool and emits
    # `-static -o`. AOS uses LLVM ar, whose archive operation is `rcs`.
    if ! grep -q 'enabled = not is_linux,' \
      aos-darwin-toolchain/unix_cc_toolchain_config.bzl; then
      echo "Envoy ${version}: macOS libtool feature anchor is missing" >&2
      exit 1
    fi
    sed -i 's/enabled = not is_linux,/enabled = False,/' \
      aos-darwin-toolchain/unix_cc_toolchain_config.bzl

    {
      printf '%s\n' '#!${buildBash}/bin/bash'
      printf '%s\n' 'set -eu'
      printf '%s\n' 'compiling=false'
      printf '%s\n' 'c_source=false'
      printf '%s\n' 'cxx_source=false'
      printf '%s\n' 'for arg in "$@"; do'
      printf '%s\n' '  case "$arg" in'
      printf '%s\n' '    -c|-S|-E|-M|-MM|-fsyntax-only) compiling=true ;;'
      printf '%s\n' '    *.c|*.m|*.s|*.S) c_source=true ;;'
      printf '%s\n' '    *.cc|*.cp|*.cpp|*.cxx|*.C|*.mm) cxx_source=true ;;'
      printf '%s\n' '  esac'
      printf '%s\n' 'done'
      printf '%s\n' 'if [ "$compiling" = true ] && [ "$c_source" = true ] && [ "$cxx_source" = false ]; then'
      printf '%s\n' '  exec ${stdenv.cc}/bin/cc "$@"'
      printf '%s\n' 'fi'
      printf '%s\n' 'exec ${stdenv.cc}/bin/c++ "$@"'
    } > aos-darwin-toolchain/compiler
    chmod +x aos-darwin-toolchain/compiler

    cat > aos-darwin-toolchain/BUILD.bazel <<'DARWIN_TOOLCHAIN_EOF'
    load(":unix_cc_toolchain_config.bzl", "cc_toolchain_config")
    load("@rules_cc//cc:defs.bzl", "cc_toolchain", "cc_toolchain_suite")

    package(default_visibility = ["//visibility:public"])

    platform(
        name = "target-platform",
        constraint_values = [
            "@platforms//cpu:${darwinBazelCpuConstraint}",
            "@platforms//os:osx",
        ],
    )

    filegroup(name = "empty")
    filegroup(
        name = "compiler-files",
        srcs = ["compiler", "unix_cc_toolchain_config.bzl"] + glob(["include/**"]),
    )

    cc_toolchain_suite(
        name = "toolchain",
        toolchains = {
            "${darwinBazelCpu}": ":cc-compiler",
            "${darwinBazelCpu}|clang": ":cc-compiler",
        },
    )

    cc_toolchain(
        name = "cc-compiler",
        toolchain_identifier = "aos-${darwinBazelCpu}",
        toolchain_config = ":config",
        all_files = ":compiler-files",
        ar_files = ":compiler-files",
        as_files = ":compiler-files",
        compiler_files = ":compiler-files",
        dwp_files = ":empty",
        linker_files = ":compiler-files",
        objcopy_files = ":compiler-files",
        strip_files = ":compiler-files",
        supports_header_parsing = 1,
        supports_param_files = 1,
    )

    toolchain(
        name = "registered-toolchain",
        exec_compatible_with = [
            "@platforms//cpu:x86_64",
            "@platforms//os:linux",
        ],
        target_compatible_with = [
            "@platforms//cpu:${darwinBazelCpuConstraint}",
            "@platforms//os:osx",
        ],
        toolchain = ":cc-compiler",
        toolchain_type = "@bazel_tools//tools/cpp:toolchain_type",
    )

    cc_toolchain_config(
        name = "config",
        cpu = "${darwinBazelCpu}",
        compiler = "clang",
        toolchain_identifier = "aos-${darwinBazelCpu}",
        host_system_name = "x86_64-unknown-linux-gnu",
        target_system_name = "${darwinTargetTriple}",
        target_libc = "macosx",
        abi_version = "darwin",
        abi_libc_version = "darwin",
        builtin_sysroot = "${stdenv.sdk}",
        cxx_builtin_include_directories = [
            "${stdenv.darwinRuntimes}/include/c++/v1",
            "${stdenv.cc}/lib/clang/aos-darwin/include",
            "${buildLlvm}/lib/clang/${llvmMajor}/include",
            "${stdenv.sdk}/usr/include",
            "${stdenv.sdk}/System/Library/Frameworks",
        ],
        tool_paths = {
            "ar": "${stdenv.cc}/bin/ar",
            "c++filt": "${buildLlvm}/bin/llvm-cxxfilt",
            "cpp": "${stdenv.cc}/bin/cc",
            "dwp": "${buildLlvm}/bin/llvm-dwp",
            "gcc": "compiler",
            "gcov": "${buildLlvm}/bin/llvm-cov",
            "ld": "compiler",
            "llvm-cov": "${buildLlvm}/bin/llvm-cov",
            "llvm-profdata": "${buildLlvm}/bin/llvm-profdata",
            "nm": "${stdenv.cc}/bin/nm",
            "objcopy": "${stdenv.cc}/bin/objcopy",
            "objdump": "${stdenv.cc}/bin/objdump",
            "strip": "${stdenv.cc}/bin/strip",
        },
        compile_flags = ["-Iaos-darwin-toolchain/include", "-D__HAS_DISPATCH__=1"],
        dbg_compile_flags = ["-g"],
        opt_compile_flags = ["-O2", "-DNDEBUG"],
        conly_flags = [],
        cxx_flags = ["-stdlib=libc++", "-faligned-allocation"],
        link_flags = [],
        archive_flags = [],
        link_libs = [],
        opt_link_flags = [],
        unfiltered_compile_flags = [],
        coverage_compile_flags = [],
        coverage_link_flags = [],
        supports_start_end_lib = False,
        extra_flags_per_feature = {},
    )
    DARWIN_TOOLCHAIN_EOF
  '';

  # Source patching — shared between fetch and build phases
  postPatchScript =
    darwinToolchainSetup
    + ''
          # Apply patches
          patch -p1 < ${./envoy-patches/0001-use-system-python.patch}
          patch -p1 < ${./envoy-patches/0003-use-system-cc-toolchains.patch}
          patch -p1 < ${./envoy-patches/0004-bump-rules-rust.patch}
          ${lib.optionalString (!isDarwinCross) ''
        # Keep the committed Cargo graph while advancing rules_rust's
        # exact repository-rule checksum. Darwin retains its separately
        # proven cross-platform fixed-output graph.
        sed -i \
          's/"checksum": "b864c94e442ea41673dcae0f7039f7afb9ef5c4287962b4464b406f670a8e6d7"/"checksum": "1a3594db8f7293ad95cc02e807d844330cdf741cbb8edcbbbc42b36ee953adba"/' \
          source/extensions/dynamic_modules/sdk/rust/Cargo.Bazel.lock
        grep -q \
          '"checksum": "1a3594db8f7293ad95cc02e807d844330cdf741cbb8edcbbbc42b36ee953adba"' \
          source/extensions/dynamic_modules/sdk/rust/Cargo.Bazel.lock
      ''}
          cat >> bazel/rules_rust.patch << 'RULES_RUST_SHEBANG_EOF'

      --- crate_universe/src/metadata/cargo_tree_rustc_wrapper.sh
      +++ crate_universe/src/metadata/cargo_tree_rustc_wrapper.sh
      @@ -1,4 +1,4 @@
      -#!/usr/bin/env bash
      +#!${buildBash}/bin/bash
       #
       # For details, see:
       # `@rules_rust//crate_universe/src/metadata/cargo_tree_resolver.rs - TreeResolver::create_rustc_wrapper`
      RULES_RUST_SHEBANG_EOF

          # Remove .bazelversion so AOS Bazel is used directly
          rm -f .bazelversion

          # Ensure python toolchain registration is fully removed
          python3 ${fixPythonBzl} bazel/repositories_extra.bzl

          # Replace yq-based YAML parsing with dummy data
          python3 ${fixRepoBzl} bazel/repo.bzl

          # Remove yq/jq toolchain registrations (pre-built Go binaries)
          sed -i '/register_yq_toolchains/d' bazel/dependency_imports.bzl
          sed -i '/register_jq_toolchains/d' bazel/dependency_imports.bzl

          # Disable toolchains_llvm setup — we use AOS-built GCC
          sed -i '/bazel_toolchain_dependencies/d' bazel/repositories_extra.bzl
          sed -i '/toolchain_llvm/d' bazel/repositories_extra.bzl 2>/dev/null || true

          # Remove envoy_toolchains() from WORKSPACE — it loads @toolchains_llvm rules
          # which transitively need @helly25_bzl (defined by bazel_toolchain_dependencies, now removed)
          sed -i '/envoy_toolchains/d' WORKSPACE
          cat > bazel/toolchains.bzl << 'TOOLCHAINS_EOF'
      # AOS: toolchains_llvm disabled — using AOS-built GCC directly
      def envoy_toolchains():
          pass
      TOOLCHAINS_EOF

          # Remove llvm_toolchain references from dependency_imports_extra.bzl
          sed -i '/llvm_toolchain/d' bazel/dependency_imports_extra.bzl
          sed -i '/llvm_register_toolchains/d' bazel/dependency_imports_extra.bzl

          # Remove emsdk/emscripten (wasm toolchain — not needed)
          sed -i '/emsdk/d' bazel/dependency_imports.bzl
          sed -i '/emscripten/d' bazel/dependency_imports.bzl
          sed -i '/emsdk/d' bazel/repositories_extra.bzl
          sed -i '/_emsdk/d' bazel/repositories.bzl

          # Remove Envoy's upstream bazel_toolchains repository. Execution
          # policy remains external and can still be supplied by Bazel's rc.
          sed -i '/bazel_toolchains/d' bazel/repositories.bzl

          # Stub out RBE BUILD files that use @bazel_toolchains
          # Provide stub platform targets so references from other BUILD files work
          cat > bazel/rbe/toolchains/BUILD << 'RBE_EOF'
      # AOS: upstream RBE platform disabled — provide stub platform target
      platform(
          name = "rbe_linux_gcc_platform",
          visibility = ["//visibility:public"],
      )
      RBE_EOF
          cat > bazel/platforms/rbe/BUILD << 'RBE_EOF'
      # AOS: upstream RBE platform disabled
      RBE_EOF
          if [ -f mobile/bazel/platforms/rbe/BUILD ]; then
            echo '# AOS: upstream RBE platform disabled' > mobile/bazel/platforms/rbe/BUILD
          fi

          # Remove -Werror (GCC may produce warnings Clang doesn't)
          sed -i '/"-Werror"/d' bazel/envoy_internal.bzl

          # Remove host_platform from --config=gcc (our stub platform has no CC toolchain)
          # We'll set flags directly instead
          sed -i '/host_platform.*rbe_linux_gcc/d' .bazelrc
          # Use lld linker (envoy's auto-configured CC toolchain uses lld-specific flags
          # like --start-lib that bfd doesn't support)
          sed -i 's/-fuse-ld=gold/-fuse-ld=lld/g' .bazelrc

          # Remove javabase from .bazelrc (set via --server_javabase)
          sed -i '/javabase=/d' .bazelrc

          # Set up Rust toolchain symlinks for Bazel
          mkdir -p bazel/nix
          ln -sf ${
        if isDarwinCross
        then "${nativeRust}/bin/rustc.unwrapped"
        else "${buildRust}/bin/rustc"
      } bazel/nix/rustc
          ln -sf ${
        if isDarwinCross
        then "${nativeRust}/bin/cargo"
        else "${buildRust}/bin/cargo"
      } bazel/nix/cargo
          ln -sf ${
        if isDarwinCross
        then "${nativeRust}/bin/rustdoc.unwrapped"
        else "${buildRust}/bin/rustdoc"
      } bazel/nix/rustdoc
          ln -sf ${buildRust} bazel/nix/rustcroot
          ${
        if isDarwinCross
        then ''
          cat > bazel/nix/BUILD.bazel <<'DARWIN_RUST_TOOLCHAIN_EOF'
          load("@bazel_tools//tools/sh:sh_toolchain.bzl", "sh_toolchain")
          load("@rules_rust//rust:toolchain.bzl", "rust_toolchain")
          load("@rules_rust//rust:defs.bzl", "rust_stdlib_filegroup")

          exports_files(["cargo", "rustdoc", "rustc"])

          rust_stdlib_filegroup(
              name = "rust_nix_target_stdlib",
              srcs = glob([
                  "rustcroot/lib/rustlib/${darwinTargetTriple}/lib/**",
              ]),
          )

          rust_toolchain(
              name = "rust_nix_target_impl",
              binary_ext = "",
              dylib_ext = ".dylib",
              exec_triple = "x86_64-unknown-linux-gnu",
              cargo = ":cargo",
              rust_doc = ":rustdoc",
              rust_std = ":rust_nix_target_stdlib",
              rustc = ":rustc",
              stdlib_linkflags = [],
              staticlib_ext = ".a",
              target_triple = "${darwinTargetTriple}",
              extra_rustc_flags = ["-Clinker=${stdenv.cc}/bin/cc"],
          )

          toolchain(
              name = "rust_nix_target",
              exec_compatible_with = [
                  "@platforms//cpu:x86_64",
                  "@platforms//os:linux",
              ],
              target_compatible_with = [
                  "@platforms//cpu:${darwinBazelCpuConstraint}",
                  "@platforms//os:osx",
              ],
              toolchain = ":rust_nix_target_impl",
              toolchain_type = "@rules_rust//rust:toolchain_type",
          )

          sh_toolchain(
              name = "local_sh_impl",
              path = "${buildBash}/bin/bash",
          )

          toolchain(
              name = "local_sh",
              toolchain = ":local_sh_impl",
              toolchain_type = "@bazel_tools//tools/sh:toolchain_type",
          )
          DARWIN_RUST_TOOLCHAIN_EOF
        ''
        else ''sed "s|@bash@|${buildBash}/bin/bash|g" ${./envoy-patches/nix-build.BUILD.bazel} > bazel/nix/BUILD.bazel''
      }

          # Inject Rust toolchain templates and bootstrap settings into crate_universe
          sed -i \
            -e 's|crate_universe_dependencies()|crate_universe_dependencies(bootstrap=True, rust_toolchain_cargo_template="@@//bazel/nix:cargo", rust_toolchain_rustc_template="@@//bazel/nix:rustc")|' \
            -e 's|crates_repository(|crates_repository(generator="@@cargo_bazel_bootstrap//:cargo-bazel", supported_platform_triples=["x86_64-unknown-linux-gnu"${
        lib.optionalString isDarwinCross '', "x86_64-apple-darwin", "aarch64-apple-darwin"''
      }], rust_toolchain_cargo_template="@@//bazel/nix:cargo", rust_toolchain_rustc_template="@@//bazel/nix:rustc",|' \
            bazel/dependency_imports.bzl

          # Fix luajit build script shebang
          sed -i 's|#!/usr/bin/env python3|#!${buildPython}/bin/python3|' \
            bazel/foreign_cc/luajit.patch 2>/dev/null || true

          # Replace shebangs throughout the source tree
          find . -type f \( -name '*.sh' -o -name '*.bzl' -o -name 'BUILD' \
               -o -name 'BUILD.*' -o -name 'WORKSPACE' -o -name '*.py' \
               -o -name '*.tpl' \) | \
            while read f; do
              sed -i \
                -e "s|/usr/local/bin/bash|${buildBash}/bin/bash|g" \
                -e "s|/usr/bin/bash|${buildBash}/bin/bash|g" \
                -e "s|/bin/bash|${buildBash}/bin/bash|g" \
                -e "s|/usr/bin/env python3|${buildPython}/bin/python3|g" \
                -e "s|/usr/bin/env python|${buildPython}/bin/python3|g" \
                -e "s|/usr/bin/env bash|${buildBash}/bin/bash|g" \
                -e "s|/usr/bin/env|${buildCoreutils}/bin/env|g" \
                -e "s|/bin/true|${buildCoreutils}/bin/true|g" \
                "$f" 2>/dev/null || true
            done
    '';
in
  mkBazelPackage {
    pname = "envoy";
    inherit version src;

    bazel = buildBazel;
    jdk = buildJdk;
    configModule = {
      src = ./_envoy-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [
        "envoy.admin"
        "envoy.clusters"
        "envoy.dynamicResources"
        "envoy.enable"
        "envoy.listeners"
        "envoy.node"
        "envoy.renderedBootstrap"
        "envoy.runtimeLayers"
        "envoy.telemetry"
      ];
      ownsRoots = [
        {
          root = "envoy";
          interfaceAbi = 1;
          contributable = [
            "clusters"
            "listeners"
            "runtimeLayers"
          ];
        }
      ];
    };

    expose = {
      units."envoy.service" = {
        description = "Envoy proxy";
        after = ["network-online.target"];
        wants = ["network-online.target"];
        serviceConfig = {
          Type = "simple";
          EnvironmentFile = "/etc/aos/packages/envoy/service.env";
          ExecCondition = "${bash}/bin/bash -c 'test \"$ENVOY_ENABLED\" = 1'";
          ExecStartPre = "/bin/envoy --mode validate --config-path /etc/aos/packages/envoy/bootstrap.json";
          ExecStart = "/bin/envoy --disable-hot-restart --config-path /etc/aos/packages/envoy/bootstrap.json";
          Restart = "on-failure";
          RestartSec = "2s";
          StateDirectory = "aos-pkg-envoy";
          LogsDirectory = "aos-pkg-envoy";
          LogsDirectoryMode = "0750";
          LimitNOFILE = "1048576";
        };
      };

      config = {
        artifacts = [
          {
            name = "service";
            path = "/etc/aos/packages/envoy/service.env";
            format = "env";
            required = ["ENVOY_ENABLED"];
            optional = [];
            units = ["envoy.service"];
            reload = "restart";
          }
          {
            name = "bootstrap";
            path = "/etc/aos/packages/envoy/bootstrap.json";
            format = "json";
            required = ["node" "static_resources"];
            optional = [
              "admin"
              "dynamic_resources"
              "layered_runtime"
              "stats_config"
              "stats_sinks"
            ];
            units = ["envoy.service"];
            reload = "restart";
          }
        ];
        credentials =
          builtins.map (name: {
            inherit name;
            source = envoyCredentialSource name;
            units = ["envoy.service"];
            encrypted = false;
            optional = true;
          })
          envoyCredentialNames;
      };

      permissions = {
        network = "host";
        capabilities = ["CAP_NET_BIND_SERVICE"];
        host-paths = [];
        devices = [];
        syscalls = "restricted";
        security-label = "aos-pkg-envoy";
      };
    };

    inherit tools;
    caCertificates = buildCaCertificates;

    # The Bazel build already passes --linkopt=-no-pie and
    # --host_linkopt=-no-pie; make the policy explicit.
    hardeningDisable = ["pie"];

    postPatch = postPatchScript;
    bazelTarget = "//source/exe:envoy-static";
    bazelFlags =
      [
        "--noenable_bzlmod"
        "--define=wasm=disabled"
      ]
      ++ lib.optionals isDarwinCross [
        "--noenable_platform_specific_config"
        "--platforms=//aos-darwin-toolchain:target-platform"
        "--cpu=${darwinBazelCpu}"
        "--host_cpu=k8"
        "--crosstool_top=//aos-darwin-toolchain:toolchain"
        "--host_crosstool_top=@local_config_cc//:toolchain"
        "--extra_toolchains=//aos-darwin-toolchain:registered-toolchain"
        "--repo_env=CC=${buildGcc}/bin/gcc"
        "--repo_env=CXX=${buildGcc}/bin/g++"
      ];
    inherit scrubMap;

    # --- Fetch-specific ---
    depsHash =
      if isDarwinCross
      then "sha256-OFSJQxEQ+LWGa8ZnTBZ6R16IauY5EL7Kh80T+m17emU="
      else "sha256-NpOZJqaq2eKswg/ZMIsvxAPMD2r61qfqgpYsam4fR/Y=";
    fetchPostPatch = "";
    bazelFetchFlags = [
      "--extra_toolchains=//bazel/nix:${
        if isDarwinCross
        then "rust_nix_target"
        else "rust_nix_x86_64"
      }"
    ];
    fetchEnv = lib.optionalAttrs isDarwinCross {
      CARGO_BAZEL_REPIN = "true";
    };
    postFetch = ''
      # Fix tcmalloc GCC warning
      find "$bazelOut/external" -path "*/com_github_google_tcmalloc/tcmalloc/copts.bzl" | \
        while read f; do
          sed -i '/TCMALLOC_GCC_FLAGS = \[/a\    "-Wno-changes-meaning",' "$f" 2>/dev/null || true
        done

      # CMake 3.1 → 3.5 compat fix for libevent
      find "$bazelOut/external" -path "*/com_github_libevent_libevent/CMakeLists.txt" | \
        while read f; do
          sed -i 's/cmake_minimum_required(VERSION 3\.1/cmake_minimum_required(VERSION 3.5/' "$f" 2>/dev/null || true
        done

      # Save Cargo.Bazel.lock
      if [ -f source/extensions/dynamic_modules/sdk/rust/Cargo.Bazel.lock ]; then
        cp source/extensions/dynamic_modules/sdk/rust/Cargo.Bazel.lock "$bazelOut/external/Cargo.Bazel.lock"
      fi

      # Remove cargo_bazel_bootstrap (compiled binary references store paths)
      rm -rf "$bazelOut/external/cargo_bazel_bootstrap"
      # Clean up crate index build artifacts (keep generated BUILD files)
      find "$bazelOut/external" -path "*/dynamic_modules_rust_sdk_crate_index/.cargo_home" \
        -exec rm -rf {} + 2>/dev/null || true
      find "$bazelOut/external" -path "*/dynamic_modules_rust_sdk_crate_index/splicing-output" \
        -exec rm -rf {} + 2>/dev/null || true

      # Remove prebuilt JDK toolchains
      rm -rf "$bazelOut/external/remotejdk"*
      rm -rf "$bazelOut/external/local_jdk"
      rm -rf "$bazelOut/external/android_tools" "$bazelOut/external/android_gmaven_r8"
      find "$bazelOut/external/repository_cache" -maxdepth 1 -type f \
        \( -iname '*remotejdk*' -o -iname '*remote_java_tools*' -o -iname '*android*' \) \
        -delete 2>/dev/null || true

      # Remove Go caches
      rm -rf "$bazelOut/external/bazel_gazelle_go_repository_cache/gocache" 2>/dev/null || true
      rm -rf "$bazelOut/external/bazel_gazelle_go_repository_cache/pkg" 2>/dev/null || true
    '';

    # --- Build-specific ---
    bazelBuildFlags =
      if isDarwinCross
      then [
        "-c opt"
        "--config=macos"
        "--spawn_strategy=standalone"
        "--extra_toolchains=@local_jdk//:all"
        "--java_runtime_version=local_jdk"
        "--tool_java_runtime_version=local_jdk"
        "--extra_toolchains=//bazel/nix:rust_nix_target"
        "--strip=always"
        "--host_linkopt=-fuse-ld=lld"
        "--host_linkopt=-no-pie"
        "--cxxopt=-Wno-error"
      ]
      else [
        "-c opt"
        "--config=gcc"
        "--spawn_strategy=remote,standalone"
        "--extra_toolchains=@local_jdk//:all"
        "--java_runtime_version=local_jdk"
        "--tool_java_runtime_version=local_jdk"
        "--extra_toolchains=//bazel/nix:rust_nix_x86_64"
        "--strip=always"
        "--linkopt=-fuse-ld=lld"
        "--host_linkopt=-fuse-ld=lld"
        "--action_env=BAZEL_LINKOPTS=-lm:-fuse-ld=lld"
        "--linkopt=-no-pie"
        "--host_linkopt=-no-pie"
        "--linkopt=-Wl,-z,noexecstack"
        "--linkopt=-Wl,--unresolved-symbols=ignore-in-object-files"
        "--cxxopt=-Wno-changes-meaning"
        "--cxxopt=-Wno-error"
      ];
    preBazelBuild = ''
                # Restore Cargo.Bazel.lock if saved in FOD
                if [ -f "$TMPDIR/output/external/Cargo.Bazel.lock" ]; then
                  cp "$TMPDIR/output/external/Cargo.Bazel.lock" \
                    source/extensions/dynamic_modules/sdk/rust/Cargo.Bazel.lock 2>/dev/null || true
                fi

                # Let the cc-wrapper provide glibc headers with -idirafter. Adding
                # glibc as -isystem breaks libstdc++'s #include_next <stdlib.h>.
                GLIBC=$(cat ${buildBootstrapTools}/nix-support/orig-libc)
                INTERP=$(cat ${buildBootstrapTools}/nix-support/dynamic-linker)
                # Fix library path and dynamic linker for linking
                echo "build --linkopt=-L$GLIBC/lib" >> .bazelrc
                echo "build --host_linkopt=-L$GLIBC/lib" >> .bazelrc
                echo "build --linkopt=-Wl,-dynamic-linker,$INTERP" >> .bazelrc
                echo "build --host_linkopt=-Wl,-dynamic-linker,$INTERP" >> .bazelrc
                # Also set RPATH so linked binaries find glibc at runtime
                echo "build --linkopt=-Wl,-rpath,$GLIBC/lib" >> .bazelrc
                echo "build --host_linkopt=-Wl,-rpath,$GLIBC/lib" >> .bazelrc

                # Patch shebangs in repo overrides (external deps have #!/bin/bash etc.)
                find "$TMPDIR/repo-overrides" -type f \( -name '*.sh' -o -name '*.py' -o -name '*.pl' \
                     -o -name 'configure' -o -name '*.bzl' -o -name 'BUILD' -o -name 'BUILD.*' \
                     -o -name '*.tpl' -o -name '*.txt' \) 2>/dev/null | \
                  while read f; do
                    sed -i \
                      -e "s|/usr/local/bin/bash|${buildBash}/bin/bash|g" \
                      -e "s|/usr/bin/bash|${buildBash}/bin/bash|g" \
                      -e "s|/bin/bash|${buildBash}/bin/bash|g" \
                      -e "s|/usr/bin/env python3|${buildPython}/bin/python3|g" \
                      -e "s|/usr/bin/env python|${buildPython}/bin/python3|g" \
                      -e "s|/usr/bin/env bash|${buildBash}/bin/bash|g" \
                      -e "s|/usr/bin/env perl|${buildPerl}/bin/perl|g" \
                      -e "s|/usr/bin/env|${buildCoreutils}/bin/env|g" \
                      -e "s|/usr/bin/perl|${buildPerl}/bin/perl|g" \
                      "$f" 2>/dev/null || true
                  done

                # Patch #!/bin/sh shebangs (first line only to avoid false matches)
                find "$TMPDIR/repo-overrides" -type f \( -name '*.sh' -o -name 'configure' \) 2>/dev/null | \
                  while read f; do
                    sed -i "1s|^#!/bin/sh|#!${buildBash}/bin/bash|" "$f" 2>/dev/null || true
                  done${lib.optionalString isDarwinCross ''

                # LuaJIT uses small generators while producing its target library.
                # Keep target flags captured by its configure wrapper, but build and
                # link those generators with native GCC so Linux can execute them.
                luajit_build="$TMPDIR/repo-overrides/com_github_luajit_luajit/luajit_build.sh"
                luajit_make="$TMPDIR/repo-overrides/com_github_luajit_luajit/src/Makefile"
                test -f "$luajit_build"
                test -f "$luajit_make"
                test "$(grep -Fc 'EXTRA_MAKE_ARGS=()' "$luajit_build")" = 1
                test "$(grep -Fc '    export CFLAGS=""' "$luajit_build")" = 2
                test "$(grep -Fc '  TARGET_XCFLAGS+= -DLUA_ROOT=\"$(PREFIX)\"' "$luajit_make")" = 1
                test "$(grep -Fc '  TARGET_XCFLAGS+= -DLUA_LJDIR=\"$(INSTALL_LJLIBD)\"' "$luajit_make")" = 1
                sed -i '/^EXTRA_MAKE_ARGS=()$/a\
        EXTRA_MAKE_ARGS+=("HOST_CC=${buildGcc}/bin/gcc" "TARGET_SYS=Darwin")' "$luajit_build"
                sed -i '0,/^    export CFLAGS=""$/s//    export CFLAGS=""\
            export LDFLAGS=""/' "$luajit_build"

                # foreign_cc's PREFIX is a disposable staging directory, not the
                # installed Envoy runtime prefix. Keep LuaJIT's ordinary /usr/local
                # module search defaults instead of compiling the staging paths into
                # Envoy's embedded Lua runtime.
                sed -i '/^  TARGET_XCFLAGS+= -DLUA_ROOT=\\"$(PREFIX)\\"$/d' "$luajit_make"
                sed -i '/^  TARGET_XCFLAGS+= -DLUA_LJDIR=\\"$(INSTALL_LJLIBD)\\"$/d' "$luajit_make"
      ''}

                # Afero's generated Gazelle BUILD file is missing strict deps for
                # util.go. Rehydrate the needed x/text packages from the cached Go
                # module sources so the offline Bazel build can resolve them.
                text_src=""
                for candidate in "$TMPDIR/repo-overrides/bazel_gazelle_go_repository_cache/pkg/mod/golang.org/x/text@"*; do
                  if [ -d "$candidate/transform" ] && [ -d "$candidate/runes" ] && [ -d "$candidate/unicode/norm" ]; then
                    text_src="$candidate"
                    break
                  fi
                done
                if [ -n "$text_src" ]; then
                  text_repo="$TMPDIR/repo-overrides/org_golang_x_text"
                  mkdir -p "$text_repo"
                  cp -a "$text_src/." "$text_repo/"
                  chmod -R u+rwx "$text_repo"
                  touch "$text_repo/WORKSPACE"
                  cat > "$text_repo/BUILD.bazel" <<'X_TEXT_ROOT_BUILD'
      package(default_visibility = ["//visibility:public"])
      X_TEXT_ROOT_BUILD
                  cat > "$text_repo/transform/BUILD.bazel" <<'X_TEXT_TRANSFORM_BUILD'
      load("@io_bazel_rules_go//go:def.bzl", "go_library")

      go_library(
          name = "go_default_library",
          srcs = glob(["*.go"], exclude = ["*_test.go"]),
          importpath = "golang.org/x/text/transform",
          visibility = ["//visibility:public"],
      )
      X_TEXT_TRANSFORM_BUILD
                  cat > "$text_repo/runes/BUILD.bazel" <<'X_TEXT_RUNES_BUILD'
      load("@io_bazel_rules_go//go:def.bzl", "go_library")

      go_library(
          name = "go_default_library",
          srcs = glob(["*.go"], exclude = ["*_test.go"]),
          importpath = "golang.org/x/text/runes",
          visibility = ["//visibility:public"],
          deps = ["@org_golang_x_text//transform:go_default_library"],
      )
      X_TEXT_RUNES_BUILD
                  cat > "$text_repo/unicode/norm/BUILD.bazel" <<'X_TEXT_NORM_BUILD'
      load("@io_bazel_rules_go//go:def.bzl", "go_library")

      go_library(
          name = "go_default_library",
          srcs = glob(["*.go"], exclude = ["*_test.go", "maketables.go"]),
          importpath = "golang.org/x/text/unicode/norm",
          visibility = ["//visibility:public"],
          deps = ["@org_golang_x_text//transform:go_default_library"],
      )
      X_TEXT_NORM_BUILD
                  echo "common --override_repository=org_golang_x_text=$text_repo" >> .bazelrc

                  afero_build="$TMPDIR/repo-overrides/com_github_spf13_afero/BUILD.bazel"
                  if [ -f "$afero_build" ] && ! grep -q '@org_golang_x_text//runes' "$afero_build"; then
                    ${buildGawk}/bin/awk '
                      { print }
                      $0 ~ /"\/\/mem",/ {
                        print "        \"@org_golang_x_text//runes:go_default_library\","
                        print "        \"@org_golang_x_text//transform:go_default_library\","
                        print "        \"@org_golang_x_text//unicode/norm:go_default_library\","
                      }
                    ' "$afero_build" > "$afero_build.tmp"
                    mv "$afero_build.tmp" "$afero_build"
                  fi
                fi

                # protoc-gen-star only uses golang.org/x/tools/imports for
                # imports.Process("", in, nil). Provide a small local implementation
                # rather than pulling in the full x/tools graph and its missing x/mod
                # repository during Envoy's offline build.
                tools_repo="$TMPDIR/repo-overrides/org_golang_x_tools"
                mkdir -p "$tools_repo/imports"
                touch "$tools_repo/WORKSPACE"
                cat > "$tools_repo/BUILD.bazel" <<'X_TOOLS_ROOT_BUILD'
      package(default_visibility = ["//visibility:public"])
      X_TOOLS_ROOT_BUILD
                cat > "$tools_repo/imports/BUILD.bazel" <<'X_TOOLS_IMPORTS_BUILD'
      load("@io_bazel_rules_go//go:def.bzl", "go_library")

      go_library(
          name = "imports",
          srcs = ["imports.go"],
          importpath = "golang.org/x/tools/imports",
          visibility = ["//visibility:public"],
      )

      alias(
          name = "go_default_library",
          actual = ":imports",
          visibility = ["//visibility:public"],
      )
      X_TOOLS_IMPORTS_BUILD
                cat > "$tools_repo/imports/imports.go" <<'X_TOOLS_IMPORTS_GO'
      package imports

      import (
      	"go/format"
      	"os"
      	"strings"
      )

      type Options struct {
      	Fragment   bool
      	AllErrors  bool
      	Comments   bool
      	TabIndent  bool
      	TabWidth   int
      	FormatOnly bool
      }

      var Debug bool
      var LocalPrefix string

      func Process(filename string, src []byte, opt *Options) ([]byte, error) {
      	if src == nil {
      		var err error
      		src, err = os.ReadFile(filename)
      		if err != nil {
      			return nil, err
      		}
      	}
      	return format.Source(src)
      }

      func VendorlessPath(ipath string) string {
      	const marker = "/vendor/"
      	if i := strings.LastIndex(ipath, marker); i >= 0 {
      		return ipath[i+len(marker):]
      	}
      	return strings.TrimPrefix(ipath, "vendor/")
      }
      X_TOOLS_IMPORTS_GO
                echo "common --override_repository=org_golang_x_tools=$tools_repo" >> .bazelrc

                pgs_go_build="$TMPDIR/repo-overrides/com_github_lyft_protoc_gen_star_v2/lang/go/BUILD.bazel"
                if [ -f "$pgs_go_build" ] && ! grep -q '@org_golang_x_tools//imports' "$pgs_go_build"; then
                  ${buildGawk}/bin/awk '
                    $0 ~ /deps = \["\/\/:protoc-gen-star"\],/ {
                      print "    deps = ["
                      print "        \"//:protoc-gen-star\","
                      print "        \"@org_golang_x_tools//imports:imports\","
                      print "    ],"
                      next
                    }
                    { print }
                    $0 ~ /"\/\/:protoc-gen-star",/ {
                      print "        \"@org_golang_x_tools//imports:imports\","
                    }
                  ' "$pgs_go_build" > "$pgs_go_build.tmp"
                  mv "$pgs_go_build.tmp" "$pgs_go_build"
                fi

                # Create fake-bin with tools that GCC/Go need to find
                mkdir -p "$TMPDIR/fake-bin"

                # GCC's collect2 needs to find the linker (ld.lld since we use -fuse-ld=lld).
                # Go's builder-cc wrapper restricts PATH, so collect2 can't find it normally.
                # Provide symlinks and tell GCC via -B and COMPILER_PATH.
                ln -sf ${buildLlvm}/bin/ld.lld "$TMPDIR/fake-bin/ld.lld"
                ln -sf ${buildLlvm}/bin/ld.lld "$TMPDIR/fake-bin/ld"
                echo "build --linkopt=-B$TMPDIR/fake-bin" >> .bazelrc
                echo "build --host_linkopt=-B$TMPDIR/fake-bin" >> .bazelrc
                echo "build --action_env=COMPILER_PATH=$TMPDIR/fake-bin" >> .bazelrc

                # Provide a fake git — bazel/get_workspace_status calls git for revision info
                {
                  printf '%s\n' '#!${buildBash}/bin/bash'
                  printf '%s\n' '# Fake git for workspace status — return empty/dummy values'
                  printf '%s\n' 'case "$*" in'
                  printf '%s\n' '  *rev-parse*HEAD*) echo "0000000000000000000000000000000000000000" ;;'
                  printf '%s\n' '  *rev-parse*) echo "unknown" ;;'
                  printf '%s\n' '  *describe*) echo "v1.37.0" ;;'
                  printf '%s\n' '  *status*) echo "" ;;'
                  printf '%s\n' '  *diff*) exit 0 ;;'
                  printf '%s\n' '  *log*) echo "" ;;'
                  printf '%s\n' '  *) echo "" ;;'
                  printf '%s\n' 'esac'
                  printf '%s\n' 'exit 0'
                } > "$TMPDIR/fake-bin/git"
                chmod +x "$TMPDIR/fake-bin/git"
                export PATH="$TMPDIR/fake-bin:$PATH"${lib.optionalString isDarwinCross ''

        # mkBazelPackage supplies Linux compatibility link paths for ordinary
        # native builds. Retain them for host actions, but keep every ELF-only
        # option out of the Darwin target link.
        sed -i \
          -e "\|^build --linkopt=-L$TMPDIR/rust-link-libs$|d" \
          -e "\|^build --linkopt=-L$GLIBC/lib$|d" \
          -e "\|^build --linkopt=-Wl,-dynamic-linker,$INTERP$|d" \
          -e "\|^build --linkopt=-Wl,-rpath,$GLIBC/lib$|d" \
          -e "\|^build --linkopt=-B$TMPDIR/fake-bin$|d" \
          -e "\|^build --action_env=COMPILER_PATH=$TMPDIR/fake-bin$|d" \
          .bazelrc

        # Bazel discovers @local_config_cc before selecting the explicit
        # Darwin target crosstool.  Run that discovery with the native GCC
        # toolchain and without target SDK identity; otherwise it records the
        # Darwin SDK as the only builtin include root for Linux host actions.
        unset AOS_CROSS_COMPILING AOS_TARGET_ARCH AOS_TARGET_PLATFORM
        unset MACOSX_DEPLOYMENT_TARGET SDKROOT
        export CC="${buildGcc}/bin/gcc"
        export CXX="${buildGcc}/bin/g++"
        export AR="${buildGcc}/bin/ar"
        export LD="${buildGcc}/bin/ld"
        export NM="${buildGcc}/bin/nm"
        export OBJCOPY="${buildGcc}/bin/objcopy"
        export OBJDUMP="${buildGcc}/bin/objdump"
        export RANLIB="${buildGcc}/bin/ranlib"
        export STRIP="${buildGcc}/bin/strip"
        echo "build --action_env=CC=$PWD/aos-darwin-toolchain/compiler" >> .bazelrc
        echo "build --action_env=CXX=$PWD/aos-darwin-toolchain/compiler" >> .bazelrc
        echo "build --host_action_env=CC=${buildGcc}/bin/gcc" >> .bazelrc
        echo "build --host_action_env=CXX=${buildGcc}/bin/g++" >> .bazelrc
        echo "build --host_action_env=COMPILER_PATH=$TMPDIR/fake-bin" >> .bazelrc

        for leaked_flag in dynamic-linker noexecstack unresolved-symbols; do
          if grep '^build --linkopt=' .bazelrc | grep -q -- "$leaked_flag"; then
            echo "ELF-only $leaked_flag flag leaked into the Darwin target" >&2
            exit 1
          fi
        done
      ''}
    '';
    installPhase =
      if isDarwinCross
      then ''
        # Repository and host-tool discovery run without Darwin target
        # identity. Restore it before the generic Darwin fixup validates and
        # records the installed output.
        export AOS_CROSS_COMPILING=1
        export AOS_TARGET_PLATFORM="${stdenv.hostPlatform.system}"
        export AOS_TARGET_ARCH="${stdenv.hostPlatform.darwinArch}"

        mkdir -p $out/bin

        ENVOY_BIN=$TMPDIR/output/execroot/envoy/bazel-out/${darwinBazelCpu}-opt/bin/source/exe/envoy-static
        if [ ! -f "$ENVOY_BIN" ]; then
          echo "ERROR: Bazel did not produce the ${darwinBazelCpu} Envoy binary" >&2
          find "$TMPDIR/output" -name envoy-static -type f -print >&2 || true
          exit 1
        fi

        cp "$ENVOY_BIN" $out/bin/envoy
        chmod +x $out/bin/envoy

        header=$(${stdenv.cc}/bin/objdump --macho --private-header $out/bin/envoy)
        case "${stdenv.hostPlatform.parsed.cpu.name}:$header" in
          x86_64:*X86_64*|aarch64:*ARM64*) ;;
          *)
            echo "Envoy output has the wrong Mach-O architecture" >&2
            echo "$header" >&2
            exit 1
            ;;
        esac
      ''
      else ''
        mkdir -p $out/bin

        ENVOY_BIN=$TMPDIR/output/execroot/envoy/bazel-out/k8-opt/bin/source/exe/envoy-static
        if [ ! -f "$ENVOY_BIN" ]; then
          # Try alternative path
          ENVOY_BIN=$(find $TMPDIR/output -name envoy-static -type f 2>/dev/null | head -1)
        fi
        if [ -z "$ENVOY_BIN" ] || [ ! -f "$ENVOY_BIN" ]; then
          echo "ERROR: bazel did not produce envoy-static binary" >&2
          find $TMPDIR/output -name 'envoy*' -type f 2>&1 || true
          exit 1
        fi

        cp "$ENVOY_BIN" $out/bin/envoy
        chmod +x $out/bin/envoy

        # Patch ELF interpreter and RPATH
        INTERP=$(cat "${buildBootstrapTools}/nix-support/dynamic-linker")
        BT_LIB=$(dirname "$INTERP")
        STDCXX_FILE=$(find "$BT_LIB" -name 'libstdc++.so.6' -not -name '*.py' 2>/dev/null | head -1)
        STDCXX_DIR=""
        if [ -n "$STDCXX_FILE" ]; then
          STDCXX_DIR=$(dirname "$STDCXX_FILE")
        fi
        RPATH="$BT_LIB"
        if [ -n "$STDCXX_DIR" ]; then
          RPATH="$RPATH:$STDCXX_DIR"
        fi
        ${buildPatchelf}/bin/patchelf --set-interpreter "$INTERP" --set-rpath "$RPATH" \
                 $out/bin/envoy 2>/dev/null || true
      '';

    buildDeps = [buildPatchelf];
    runtimeDeps = [];
    propagatedDeps = [];

    meta = {
      description = "Envoy proxy — high-performance L7 proxy and communication bus";
      homepage = "https://www.envoyproxy.io";
      license = "Apache-2.0";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: let
      evalConfig = envoyConfig:
        lib.evalModules {
          modules = [
            ({lib, ...}: {
              options = {
                assertions = lib.mkOption {
                  type = lib.types.listOf lib.types.attrs;
                  default = [];
                };
                envoy.config = lib.mkOption {
                  type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
                  default = {};
                };
                envoy.credentials = lib.mkOption {
                  type = lib.types.attrsOf lib.types.attrs;
                  default = {};
                };
              };
            })
            (import ./_envoy-config/module.nix)
            {envoy = envoyConfig;}
          ];
          inherit lib;
        };
      assertionsHoldFor = result:
        builtins.all (assertion: assertion.assertion) result.config.assertions;
      signedExpose = builtins.fromJSON self.expose.manifest;
      signedCredentials = signedExpose.expose.config.credentials;
      credentialDeclarationsHold =
        builtins.length signedCredentials
        == builtins.length envoyCredentialNames
        && builtins.all (
          credential:
            builtins.elem credential.name envoyCredentialNames
            && credential.source == envoyCredentialSource credential.name
            && !credential.encrypted
            && credential.optional
            && credential.units == ["envoy.service"]
        )
        signedCredentials;
      evaluatedConfig = evalConfig {
        enable = true;
        node = {
          id = "envoy-check";
          cluster = "aos-checks";
        };
        listeners.http = {
          address = "127.0.0.1";
          port = 10000;
          filterChains.http.virtualHosts.local = {
            domains = ["*"];
            routes.root = {
              cluster = "backend";
              retryCount = 2;
            };
          };
        };
        clusters.backend = {
          endpoints = [
            {
              address = "127.0.0.1";
              port = 10001;
            }
          ];
          healthChecks = [
            {
              type = "http";
              path = "/healthz";
            }
          ];
        };
        runtimeLayers.aos.values."envoy.reloadable_features.check" = true;
        telemetry.statsd = {
          address = "127.0.0.1";
          port = 8125;
        };
      };
      invalidRoute = evalConfig {
        listeners.http = {
          port = 10000;
          filterChains.http.virtualHosts.local.routes.root = {};
        };
      };
      invalidTls = evalConfig {
        clusters.backend = {
          endpoints = [
            {
              address = "127.0.0.1";
              port = 10001;
            }
          ];
          tls.certificateCredential = "tls-certificate";
        };
      };
      invalidAdmin = evalConfig {admin.address = "0.0.0.0";};
      invalidAdminLog = builtins.tryEval (builtins.deepSeq
        ((evalConfig {
            admin.accessLogPath = "/dev/stderr";
          })
          .config
          .envoy
          .renderedBootstrap)
        true);
      validSds = evalConfig {
        dynamicResources = {
          enableAds = true;
          adsCluster = "xds-control-plane";
        };
        clusters.xds-control-plane.endpoints = [
          {
            address = "127.0.0.1";
            port = 18000;
          }
        ];
        listeners.https = {
          port = 10443;
          filterChains.https = {
            tls = {
              sdsSecret = "downstream-certificate";
              validationSdsSecret = "client-ca";
              requireClientCertificate = true;
            };
            virtualHosts.local.routes.root.directResponse.status = 204;
          };
        };
      };
      validCredentialTls = evalConfig {
        credentials = {
          tls-certificate.ref = "system-credential";
          tls-private-key.ref = "system-credential";
        };
        listeners.https = {
          port = 10443;
          filterChains.https = {
            tls = {
              certificateCredential = "tls-certificate";
              privateKeyCredential = "tls-private-key";
            };
            virtualHosts.local.routes.root.directResponse.status = 204;
          };
        };
      };
      contractHolds =
        assertionsHoldFor evaluatedConfig
        && assertionsHoldFor validSds
        && assertionsHoldFor validCredentialTls
        && credentialDeclarationsHold
        && !assertionsHoldFor invalidRoute
        && !assertionsHoldFor invalidTls
        && !assertionsHoldFor invalidAdmin
        && !invalidAdminLog.success;
      renderedBootstrap =
        if assertionsHoldFor evaluatedConfig
        then builtins.toFile "envoy-config-module-check.json" (builtins.toJSON evaluatedConfig.config.envoy.renderedBootstrap)
        else throw "the Envoy config-module fixture has a failing assertion";
    in {
      version = testing.mkVMTest {
        name = "networking-envoy-version";
        rootfsDeps = [self];
        testScript = ''
          OUTPUT=$(envoy --version 2>&1)
          case "$OUTPUT" in
            *"1.37"*)
              echo "==> envoy version: PASS"
              ;;
            *)
              echo "==> ERROR: unexpected envoy version: $OUTPUT" >&2
              exit 1
              ;;
          esac
        '';
      };

      validate-config = testing.mkVMTest {
        name = "networking-envoy-validate-config";
        rootfsDeps = [self];
        testScript = ''
          # Write a minimal Envoy config
          mkdir -p /tmp/envoy
          cat > /tmp/envoy/config.yaml << 'YAML'
          static_resources:
            listeners:
            - name: test_listener
              address:
                socket_address:
                  address: 127.0.0.1
                  port_value: 10000
              filter_chains:
              - filters:
                - name: envoy.filters.network.http_connection_manager
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                    stat_prefix: ingress_http
                    route_config:
                      name: local_route
                      virtual_hosts:
                      - name: local_service
                        domains: ["*"]
                        routes:
                        - match:
                            prefix: "/"
                          direct_response:
                            status: 200
                            body:
                              inline_string: "hello"
                    http_filters:
                    - name: envoy.filters.http.router
                      typed_config:
                        "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          YAML

          envoy --mode validate -c /tmp/envoy/config.yaml 2>&1
          case "$?" in
            0)
              echo "==> envoy validate-config: PASS"
              ;;
            *)
              echo "==> ERROR: envoy config validation failed" >&2
              exit 1
              ;;
          esac
        '';
      };

      config-module = testing.mkVMTest {
        name = "networking-envoy-config-module";
        rootfsDeps = [self];
        testScript = ''
          envoy --mode validate --config-path ${renderedBootstrap}
          ${pkgs.grep}/bin/grep -q 'envoy-check' ${renderedBootstrap}
          ${pkgs.grep}/bin/grep -q 'envoy.reloadable_features.check' ${renderedBootstrap}
          echo "==> envoy config-module: PASS"
        '';
      };

      config-module-contract =
        if contractHolds
        then
          pkgs.runCommand "networking-envoy-config-module-contract" {} ''
            if ${pkgs.grep}/bin/grep -E 'LoadCredential(Encrypted)?=.*(tls-certificate|tls-private-key|validation-ca)' ${self.expose}/units/envoy.service; then
              echo "optional Envoy credentials must not create unconditional static unit bindings" >&2
              exit 1
            fi
            ${pkgs.grep}/bin/grep -F -- '-- /bin/envoy --mode validate' ${self.expose}/units/envoy.service
            ${pkgs.grep}/bin/grep -F -- '-- /bin/envoy --disable-hot-restart --config-path' ${self.expose}/units/envoy.service
            if ${pkgs.grep}/bin/grep -Fq -- '--log-format-prefix-with-location' ${self.expose}/units/envoy.service; then
              echo "Envoy service uses an unsupported log-format flag" >&2
              exit 1
            fi
            ${pkgs.grep}/bin/grep -qx 'LogsDirectory=aos-pkg-envoy' ${self.expose}/units/envoy.service
            ${pkgs.grep}/bin/grep -qx 'LogsDirectoryMode=0750' ${self.expose}/units/envoy.service
            ${pkgs.grep}/bin/grep -Fq -- '--fs-rw /var/log/aos-pkg-envoy' ${self.expose}/units/envoy.service
            ${pkgs.grep}/bin/grep -Fq '"/var/log/aos-pkg-envoy"' ${self.expose}/network-policy.json
            ${pkgs.grep}/bin/grep -Fq '"access_log_path":"/var/log/aos-pkg-envoy/admin-access.log"' ${renderedBootstrap}
            mkdir -p "$out"
            printf '%s\n' PASS > "$out/result"
          ''
        else throw "the Envoy config-module contract checks failed";
    };
  }
