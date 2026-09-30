##! Source-built async-profiler repositories for Bazel 8's module extension.
{
  mkDerivation,
  fetchgit,
  buildPackages,
  stdenv,
}: let
  version = "3.0-f0ceda6";
  buildJdk = buildPackages.openjdk-17;

  source = fetchgit {
    url = "https://github.com/async-profiler/async-profiler.git";
    rev = "f0ceda6356f05b7ad0a6593670c8c113113bf0b3";
    fetchCommit = true;
    hash = "sha256-2nfMK8LlenG3WzppoQJSMsRm8DqtGJx1DbRl+Si/pmw=";
    name = "bazel-async-profiler-${version}-source-only";

    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;

    # The pinned commit includes compiled helper classes; javac rebuilds them.
    sparsePatterns = [
      "/src/"
      "/LICENSE"
      "/Makefile"
      "!*.jar"
      "!*.class"
      "!*.so"
      "!*.a"
      "!*.ar"
      "!*.aar"
      "!*.o"
      "!*.wasm"
      "!*.dll"
      "!*.dylib"
      "!*.exe"
      "!*.bin"
      "!*.zip"
      "!*.tar"
      "!*.gz"
      "!*.xz"
    ];
  };

  apiJar = mkDerivation {
    pname = "bazel-async-profiler-api";
    inherit version;
    src = source;

    buildDeps = [buildJdk];
    runtimeDeps = [];

    phases = [
      {
        name = "build";
        script = ''
          mkdir -p classes
          ${buildJdk}/bin/javac --release 8 -proc:none -encoding UTF-8 \
            -d classes "$src"/src/api/one/profiler/*.java
          ${buildJdk}/bin/jar --create --file async-profiler.jar \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java"
          cp async-profiler.jar "$out/share/java/"
        '';
      }
    ];
  };

  linuxArmPackages = import ../../default.nix {crossSystem = "aarch64-linux";};
  darwinX64Packages = import ../../default.nix {crossSystem = "x86_64-darwin";};
  darwinArmPackages = import ../../default.nix {crossSystem = "aarch64-darwin";};

  nativeLibrary = {
    targetStdenv,
    targetSystem,
    gccLibs ? null,
  }: let
    isDarwin = gccLibs == null;
    extension =
      if isDarwin
      then "dylib"
      else "so";
    platformFlags =
      if isDarwin
      then "-D_XOPEN_SOURCE -D_DARWIN_C_SOURCE"
      else "-Wl,-z,defs";
    sharedFlag =
      if isDarwin
      then "-dynamiclib"
      else "-shared";
    platformLibraries =
      if isDarwin
      then "-ldl -lpthread"
      else "-ldl -lpthread -lrt";
    runtimeRpath =
      if isDarwin
      then ""
      else ''patchelf --set-rpath ${gccLibs}/lib libasyncProfiler.so'';
  in
    targetStdenv.mkDerivation {
      pname = "bazel-async-profiler-native-${targetSystem}";
      inherit version;
      src = source;

      buildDeps =
        [buildJdk buildPackages.nuke-references]
        ++ (
          if isDarwin
          then []
          else [buildPackages.patchelf]
        );
      runtimeDeps =
        if isDarwin
        then []
        else [gccLibs];

      phases = [
        {
          name = "build";
          script = ''
            cp -R "$src"/. .
            chmod -R u+w src

            ${buildJdk}/bin/javac -source 8 -target 8 -Xlint:-options \
              -proc:none -g:none -encoding UTF-8 \
              -d src/helper src/helper/one/profiler/*.java

            # The JDK's JNI declarations work for the cross-compiled native
            # library; the AOS target compiler supplies the platform ABI.
            c++ -O2 -fno-exceptions -fno-omit-frame-pointer \
              -fvisibility=hidden -std=c++11 ${platformFlags} \
              -DPROFILER_VERSION='"3.0"' \
              -I${buildJdk}/include -I${buildJdk}/include/linux \
              -Isrc/helper -fPIC ${sharedFlag} \
              -o libasyncProfiler.${extension} src/*.cpp \
              ${platformLibraries}

            ${runtimeRpath}
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/lib"
            cp libasyncProfiler.${extension} "$out/lib/"
            cp "$src/LICENSE" "$out/"
          '';
        }
      ];
    };

  linuxX64 = nativeLibrary {
    targetStdenv = stdenv;
    targetSystem = "x86_64-linux";
    gccLibs = buildPackages.gcc-libs;
  };
  linuxArm = nativeLibrary {
    targetStdenv = linuxArmPackages.stdenv;
    targetSystem = "aarch64-linux";
    gccLibs = linuxArmPackages.pkgs.gcc-libs;
  };
  darwinX64 = nativeLibrary {
    targetStdenv = darwinX64Packages.stdenv;
    targetSystem = "x86_64-darwin";
  };
  darwinArm = nativeLibrary {
    targetStdenv = darwinArmPackages.stdenv;
    targetSystem = "aarch64-darwin";
  };

  darwinUniversal = mkDerivation {
    pname = "bazel-async-profiler-darwin-universal";
    inherit version;

    buildDeps = [buildPackages.llvm];
    runtimeDeps = [darwinX64 darwinArm];
    # The Mach-O slices retain their AOS Darwin runtime load paths.
    dontNukeRefs = true;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib"
          llvm-lipo -create -output "$out/lib/libasyncProfiler.dylib" \
            ${darwinX64}/lib/libasyncProfiler.dylib \
            ${darwinArm}/lib/libasyncProfiler.dylib
          test "$(llvm-lipo -archs "$out/lib/libasyncProfiler.dylib")" = "x86_64 arm64 "
        '';
      }
    ];
  };

  jarRepository = mkDerivation {
    pname = "bazel-async-profiler-jar-repository";
    inherit version;
    src = apiJar;

    buildDeps = [];
    runtimeDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/file"
          cp "$src/share/java/async-profiler.jar" \
            "$out/file/async-profiler.jar"
          touch "$out/REPO.bazel"
          cat > "$out/file/BUILD.bazel" <<'BUILD'
          filegroup(
              name = "file",
              srcs = ["async-profiler.jar"],
              visibility = ["//visibility:public"],
          )
          BUILD
        '';
      }
    ];
  };

  nativeRepository = {
    name,
    library,
    tag,
    extension,
  }:
    mkDerivation {
      pname = "bazel-${name}-repository";
      inherit version;
      src = library;

      buildDeps = [];
      runtimeDeps = [library];
      # Keep the cross-built library's runtime references intact.
      dontNukeRefs = true;

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out"
            cp "$src/lib/libasyncProfiler.${extension}" \
              "$out/libasyncProfiler.${extension}"
            touch "$out/REPO.bazel"
            cat > "$out/BUILD.bazel" <<'BUILD'
            load("@bazel_skylib//rules:copy_file.bzl", "copy_file")

            copy_file(
                name = "libasyncProfiler",
                src = "libasyncProfiler.${extension}",
                out = "${tag}/libasyncProfiler.so",
                visibility = ["//visibility:public"],
            )
            BUILD
          '';
        }
      ];
    };
in {
  "+async_profiler_repos+async_profiler" = jarRepository;
  "+async_profiler_repos+async_profiler_linux_x64" = nativeRepository {
    name = "async-profiler-linux-x64";
    library = linuxX64;
    tag = "linux-x64";
    extension = "so";
  };
  "+async_profiler_repos+async_profiler_linux_arm64" = nativeRepository {
    name = "async-profiler-linux-arm64";
    library = linuxArm;
    tag = "linux-arm64";
    extension = "so";
  };
  "+async_profiler_repos+async_profiler_macos" = nativeRepository {
    name = "async-profiler-macos";
    library = darwinUniversal;
    tag = "macos";
    extension = "dylib";
  };
}
