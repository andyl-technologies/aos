##! Bazel utility toolchains backed by AOS source-built programs.
{
  mkDerivation,
  callPackage,
  coreutils,
  libarchive,
  bash,
}: let
  yq = callPackage ./_yq.nix {};
  copyDirectory = callPackage ./_bazel-copy-directory.nix {};
in
  mkDerivation {
    pname = "workerd-utility-repositories";
    version = "1";
    runtimeDeps = [coreutils libarchive bash yq copyDirectory];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/coreutils" "$out/tar" "$out/yq" "$out/copy_directory"
          ln -s ${libarchive}/bin/bsdtar "$out/tar/tar"
          ln -s ${yq}/bin/yq "$out/yq/yq"
          ln -s ${copyDirectory}/bin/copy_directory "$out/copy_directory/copy_directory"

          # Bazel's uutils interface selects an applet with its first argument;
          # GNU's source-built multicall implementation uses an explicit option.
          cat > "$out/coreutils/coreutils" <<'SH'
          #!${bash}/bin/bash
          set -eu
          applet="$1"
          shift
          exec ${coreutils}/bin/coreutils --coreutils-prog="$applet" "$@"
          SH
          chmod +x "$out/coreutils/coreutils"

          cat > "$out/coreutils/BUILD.bazel" <<'BUILD'
          load("@bazel_lib//lib/private:coreutils_toolchain.bzl", "coreutils_toolchain")
          exports_files(["coreutils"])
          coreutils_toolchain(name = "coreutils_toolchain", binary = "coreutils", visibility = ["//visibility:public"])
          BUILD
          cat > "$out/tar/BUILD.bazel" <<'BUILD'
          load("@tar.bzl//tar/toolchain:toolchain.bzl", "tar_toolchain")
          tar_toolchain(name = "bsdtar_toolchain", binary = "tar", visibility = ["//visibility:public"])
          BUILD
          cat > "$out/yq/BUILD.bazel" <<'BUILD'
          load("@yq.bzl//yq/toolchain:toolchain.bzl", "yq_toolchain")
          exports_files(["yq"])
          yq_toolchain(name = "yq_toolchain", bin = "yq", visibility = ["//visibility:public"])
          BUILD
          cat > "$out/copy_directory/BUILD.bazel" <<'BUILD'
          load("@bazel_lib//lib/private:copy_directory_toolchain.bzl", "copy_directory_toolchain")
          exports_files(["copy_directory"])
          copy_directory_toolchain(name = "copy_directory_toolchain", bin = "copy_directory", visibility = ["//visibility:public"])
          BUILD
          for repository in coreutils tar yq copy_directory; do
            touch "$out/$repository/REPO.bazel"
          done
        '';
      }
      {
        name = "check";
        script = ''
          test "$("$out/coreutils/coreutils" printf '%s' dispatch-ok)" = dispatch-ok
          mkdir sample
          printf 'answer: 42\n' > sample/data.yaml
          "$out/coreutils/coreutils" cp sample/data.yaml copied.yaml
          cmp sample/data.yaml copied.yaml
          test "$("$out/yq/yq" '.answer' copied.yaml)" = 42
          "$out/tar/tar" -cf sample.tar sample
          mkdir restored
          "$out/tar/tar" -xf sample.tar -C restored
          cmp sample/data.yaml restored/sample/data.yaml
        '';
      }
    ];
  }
