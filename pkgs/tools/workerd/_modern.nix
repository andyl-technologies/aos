##! Source build of the Workers runtime used by current Wrangler.
{
  mkBazelPackage,
  fetchurl,
  callPackage,
  lib,
  stdenv,
  python3,
  rust,
  llvm,
  binutils,
  nodejs,
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
}: let
  version = "1.20260801.1";
  nativeClang = callPackage ./_native-clang.nix {};
  cargoBazel = callPackage ./_cargo-bazel.nix {};
  rustRepository = callPackage ./_rust-repository.nix {};
  nodeRepository = callPackage ./_node-repository.nix {};
  esbuildRepository = callPackage ./_esbuild-repository.nix {};
  pythonRepositories = callPackage ./_python-repositories.nix {};
  pyodide = callPackage ./_pyodide.nix {};

  repositories = {
    "rules_rust++rust+rust_linux_x86_64__x86_64-unknown-linux-gnu__stable_tools" = rustRepository;
    "rules_nodejs++node+nodejs_linux_amd64" = nodeRepository;
    "aspect_rules_esbuild++esbuild+esbuild_linux-x64" = esbuildRepository;
    "rules_python++pip+v8_python_deps_314_jinja2_py3_none_any_85ece445" = "${pythonRepositories}/jinja2";
    "rules_python++pip+v8_python_deps_314_markupsafe_sdist_594c6780" = "${pythonRepositories}/markupsafe";
    "+pyodide+pyodide-314.0.0" = pyodide;
  };

  prepareSource = ''
    ${python3}/bin/python3 ${./prepare-modern-toolchains.py} \
      --python ${python3}/bin/python3 --rust ${rust} --bash ${bash}/bin/bash
  '';

  configureEnvironment = ''
    export CARGO_BAZEL_GENERATOR_URL="file://${cargoBazel}/bin/cargo-bazel"
    export CARGO_BAZEL_GENERATOR_SHA256="$(sha256sum ${cargoBazel}/bin/cargo-bazel | cut -d ' ' -f 1)"
    export LOCPATH="${glibc-locales}/lib/locale"
    export LC_ALL=C.UTF-8 LANG=C.UTF-8
  '';
in
  # Cross-platform toolchain registration is added separately; never silently
  # emit a native executable for a requested cross target.
  assert !stdenv.isCross && stdenv.hostPlatform.system == "x86_64-linux";
    mkBazelPackage {
      pname = "workerd-modern-source";
      inherit version;
      src = fetchurl {
        urls = ["https://github.com/cloudflare/workerd/archive/refs/tags/v${version}.tar.gz"];
        hash = "0w6dy0k7bxr8ar54hw82makqbpp66nj1c6s5q2rfn0r6jx5zxiws";
      };

      tools = [
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
      populateBCR = false;
      depsHash = lib.fakeHash;
      bazelTarget = "//src/workerd/server:workerd";
      bazelFlags =
        [
          # The dependency snapshot owns repository contents. Bazel 9's shared
          # cache otherwise replaces them with temporary external symlinks.
          "--repo_contents_cache="
          "--@rules_python//python/config_settings:python_version=3.14"
          "--repo_env=CC=${nativeClang}/bin/clang"
        ]
        ++ lib.mapAttrsToList (name: path: "--override_repository=${name}=${path}") repositories;

      postPatch = prepareSource;
      fetchPostPatch = configureEnvironment;
      preBazelBuild = prepareSource + configureEnvironment;
      bazelBuildFlags = [
        "-c opt"
        "--spawn_strategy=processwrapper-sandbox,standalone"
        "--java_runtime_version=local_jdk"
        "--tool_java_runtime_version=local_jdk"
        "--linkopt=-lc++abi"
        "--linkopt=-lunwind"
        "--host_linkopt=-lc++abi"
        "--host_linkopt=-lunwind"
      ];

      installPhase = ''
        mkdir -p "$out/bin" "$out/share/licenses/workerd"
        cp bazel-bin/src/workerd/server/workerd "$out/bin/workerd"
        cp LICENSE "$out/share/licenses/workerd/LICENSE"
        "$out/bin/workerd" --version
      '';

      meta = {
        description = "Cloudflare Workers runtime built from source";
        license = "Apache-2.0";
      };
    }
