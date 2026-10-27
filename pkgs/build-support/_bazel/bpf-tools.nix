##! Binds the source-built BPF compiler, strip tool, and target headers.
{pkgs}: let
  platform = pkgs.stdenv.hostPlatform;
  architecture =
    if platform.isx86_64
    then "x86"
    else "arm64";
in
  assert !pkgs.stdenv.isCross && platform.isLinux && (platform.isx86_64 || platform.isAarch64);
    pkgs.mkDerivation {
      pname = "aos-bazel-bpf-tools";
      version = "1";
      src = null;
      sharedBuildCache = false;
      buildDeps = [pkgs.jq];
      outputChecks.out = {};
      exportReferencesGraph.bpf = [pkgs.buildPackages.llvm pkgs.linux-headers pkgs.libbpf];
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin" "$out/kernel" "$out/libbpf"
            ln -s ${pkgs.buildPackages.llvm}/bin/clang "$out/bin/clang"
            ln -s ${pkgs.buildPackages.llvm}/bin/llvm-strip "$out/bin/llvm-strip"
            ln -s ${pkgs.linux-headers}/include "$out/kernel/include"
            ln -s ${pkgs.libbpf}/include "$out/libbpf/include"
            jq -cS '{schema: 1, closure: [.bpf[] | {path, narHash}] | sort_by(.path)}' \
              "$NIX_ATTRS_JSON_FILE" > "$out/closure.json"
            cat > "$out/paths.bzl" <<'PATHS'
            BPF_TOOLS = struct(
                architecture = "${architecture}",
                kernel_headers = "${pkgs.linux-headers}/include",
                libbpf_headers = "${pkgs.libbpf}/include",
            )
            PATHS
            cat > "$out/BUILD.bazel" <<'BUILD'
            load("@rules_cc//cc:defs.bzl", "cc_library")

            package(default_visibility = ["//visibility:public"])

            exports_files(["bin/clang", "bin/llvm-strip", "closure.json", "paths.bzl"])

            filegroup(
                name = "headers",
                srcs = glob(["kernel/include/**", "libbpf/include/**"]),
            )

            cc_library(
                name = "kernel_headers",
                hdrs = glob(["kernel/include/**"]),
                includes = ["kernel/include"],
                additional_linker_inputs = ["closure.json"],
                tags = ["aos-license:permissive-protocol"],
            )
            BUILD
            touch "$out/REPO.bazel"
          '';
        }
      ];
    }
