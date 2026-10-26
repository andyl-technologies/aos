##! Builds the original BPF sources and loaders before provider-package cutover.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/bpf-native-inventory.json,
}: let
  loaderName =
    if pkgs.stdenv.hostPlatform.isx86_64
    then "ld-linux-x86-64.so.2"
    else "ld-linux-aarch64.so.1";
  nativeCpu =
    if pkgs.stdenv.hostPlatform.isx86_64
    then "x86_64"
    else "aarch64";
  foreignCpu =
    if nativeCpu == "x86_64"
    then "aarch64"
    else "x86_64";
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-bpf-native-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  targets = [
    "//pkgs/security:aos-ebpf-lsm-loader"
    "//pkgs/security:aos-ebpf-net-policy-loader"
    "//pkgs/security:aos-ebpf-lsm-policy.bpf"
    "//pkgs/security:aos-ebpf-net-policy.bpf"
    "//pkgs/security:bpf_native_license_closure"
    "//pkgs/security:bpf_native_artifacts"
  ];
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories =
      if sourceInventory == null
      then ["tools/bazel" "pkgs/security"]
      else [];
    analysisTargets = targets;
    repositories =
      pkgs.aosBazelRepositories
      // {
        aos_bpf_tools = pkgs.aosBazelBpfTools;
        aos_bpf_native = pkgs.aosBazelBpfLibraries;
      };
  };
in rec {
  inherit workspace;
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-bpf-native";
    inherit workspace targets;
    retainActionGraph = true;
    sharedBuildCache = false;
  };
  inventory = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-bpf-native-inventory";
    inherit workspace targets;
    inventoryOnly = true;
    sharedBuildCache = false;
  };

  check =
    pkgs.runCommand "aos-bazel-bpf-native-checks" {
      buildDeps = [pkgs.python3];
      sharedBuildCache = false;
    } ''
      mkdir -p "$out"
      test "$(cat ${platform-rejection}/result)" = PASS
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
        ${scripts}/verify_bpf_native.py \
        --build ${build} --baseline ${baseline} --source ${workspace.source} \
        --tools ${pkgs.aosBazelBpfTools} --native ${pkgs.aosBazelBpfLibraries} \
        --compilers ${pkgs.aosBazelToolchains} \
        --readelf ${pkgs.binutils}/bin/readelf \
        --loader ${pkgs.glibc}/lib/${loaderName} \
        --output "$out/report.json"
      printf 'PASS\n' > "$out/result"
    '';

  platform-rejection =
    pkgs.runCommand "aos-bazel-bpf-native-platform-rejection" {
      buildDeps = [pkgs.python3];
      sharedBuildCache = false;
    } ''
      mkdir workspace
      cp -a ${workspace.source}/. workspace/
      chmod -R u+w workspace
      cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
      mkdir -p workspace/bpf-platform-probe "$out"
      cat > workspace/bpf-platform-probe/BUILD.bazel <<'BUILD'
      platform(
          name = "foreign_cpu",
          constraint_values = ["@platforms//cpu:${foreignCpu}", "@platforms//os:linux"],
      )
      platform(
          name = "foreign_os",
          constraint_values = ["@platforms//cpu:${nativeCpu}", "@platforms//os:none"],
      )
      BUILD
      for platform in foreign_cpu foreign_os; do
        if ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
          --config ${workspace.configuration} --workspace "$PWD/workspace" \
          --output-base "$TMPDIR/$platform/bazel" --nix-sandbox --batch \
          -- build //pkgs/security:aos-ebpf-lsm-policy.bpf --nobuild \
          --platforms="//bpf-platform-probe:$platform" > "$out/$platform.log" 2>&1; then
          echo "BPF binding accepted an incompatible target: $platform" >&2
          exit 1
        fi
        grep -F 'is incompatible' "$out/$platform.log"
      done
      printf 'PASS\n' > "$out/result"
    '';

  # This oracle retains the native commands from the unchanged Cargo package
  # recipes. It does not use Bazel rules or their tool repository.
  baseline =
    pkgs.runCommand "aos-bpf-native-original-recipe-oracle" {
      buildDeps = [pkgs.llvm pkgs.pkg-config pkgs.linux-headers];
      runtimeDeps = [pkgs.libbpf pkgs.json-c];
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
    } (''
        mkdir -p "$out"
      ''
      + pkgs.lib.concatMapStringsSep "\n" (policy: let
        source = ../../pkgs/security + "/aos-ebpf-${policy}-policy";
        architecture =
          if pkgs.stdenv.hostPlatform.isx86_64
          then "x86"
          else "arm64";
        loader =
          if policy == "lsm"
          then "aos-ebpf-lsm-loader"
          else "aos-ebpf-net-policy-loader";
      in ''
        cp ${source + ".bpf.c"} "$TMPDIR/aos-ebpf-${policy}-policy.bpf.c"
        ${pkgs.buildPackages.llvm}/bin/clang -target bpf -O2 -g \
          -D__TARGET_ARCH_${architecture} \
          -I${pkgs.linux-headers}/include -I${pkgs.libbpf}/include \
          -Wall -Wextra -Werror -Wno-unused-parameter \
          -c "$TMPDIR/aos-ebpf-${policy}-policy.bpf.c" \
          -o "$out/aos-ebpf-${policy}-policy.bpf.o"
        ${pkgs.buildPackages.llvm}/bin/llvm-strip -g "$out/aos-ebpf-${policy}-policy.bpf.o"
        $CC -O2 -Wall -Wextra -Werror -I${pkgs.linux-headers}/include \
          -o "$out/${loader}" ${source + ".c"} \
          $(pkg-config --cflags --libs libbpf json-c)
      '') ["lsm" "net"]);
}
