##! Bazel 7 bootstrap Java runner compiled from the pinned source checkout.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  lib,
  stdenv,
  buildPackages,
  protobuf,
  abseil-cpp,
  zlib,
  bash,
  coreutils,
  which,
  findutils,
  gawk,
  grep,
  sed,
  unzip,
  zip,
  python3,
}: let
  helperFiles = builtins.filter (
    file: lib.hasPrefix "_bazel-" file && lib.hasSuffix ".nix" file
  ) (builtins.attrNames (builtins.readDir ./.));
  capitalize = part:
    lib.toUpper (builtins.substring 0 1 part)
    + builtins.substring 1 (builtins.stringLength part - 1) part;
  helperName = file: let
    suffix = builtins.substring 7 (builtins.stringLength file - 11) file;
  in
    "bazel" + lib.concatStringsSep "" (builtins.map capitalize (lib.splitString "-" suffix));
  helperScope = builtins.listToAttrs (builtins.map (file: {
      name = helperName file;
      value = callHelper (./. + "/${file}") {};
    })
    helperFiles);
  aliases = {
    bazelAvalonApi = helperScope.bazelAvalonFrameworkApi;
    bazelBlockHound = helperScope.bazelBlockhound;
    bazelByteBuddy = helperScope.bazelByteBuddyBootstrap;
    bazelByteBuddy114 = helperScope.bazelByteBuddy1_14;
    bazelJeroMq = helperScope.bazelJeromq;
    bazelZstdJni155 = callHelper ./_bazel-zstd-jni.nix {version = "1.5.5-11";};
    protobufJava = helperScope.bazelProtobufJava;
    xmlResolver = helperScope.bazelXmlResolver;
  };
  callHelper = path: overrides: let
    expression = import path;
    scope =
      buildPackages
      // {
        inherit mkDerivation fetchgit fetchurl lib stdenv buildPackages protobuf abseil-cpp zlib;
      }
      // helperScope
      // aliases;
  in
    expression ((builtins.intersectAttrs (builtins.functionArgs expression) scope) // overrides);

  source = helperScope.bazelSource;
  mavenJars = helperScope.bazelMavenBootstrap;
  protobufJava = helperScope.bazelProtobufJava;
  protobufJavaUtil = helperScope.bazelProtobufJavaUtil;
  grpcJavaPlugin = helperScope.bazelGrpcJavaPlugin;
  unixJni = helperScope.bazelUnixJni;
  nettyLibraries = [
    helperScope.bazelNettyCommon
    helperScope.bazelNettyBase
    helperScope.bazelNettyCodec
    helperScope.bazelNettyCodecHttp
    helperScope.bazelNettyTransportExtras
    helperScope.bazelNettyHandler
    helperScope.bazelNettyDns
    helperScope.bazelGrpcNetty
    helperScope.bazelGoogleHttp
    helperScope.bazelAsyncProfilerJar
  ];
  jdk = buildPackages.openjdk-21;
in
  mkDerivation {
    pname = "bazel-bootstrap";
    version = "7.7.1";
    src = source;

    buildDeps =
      [
        jdk
        mavenJars
        protobufJava
        protobufJavaUtil
        aliases.bazelZstdJni155
        grpcJavaPlugin
        unixJni
      ]
      ++ nettyLibraries
      ++ [
        protobuf
        bash
        coreutils
        which
        findutils
        gawk
        grep
        sed
        unzip
        zip
        python3
      ];
    runtimeDeps = [jdk bash];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -r "$src" bazel-source
          chmod -R u+w bazel-source
          cd bazel-source
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${jdk}
          export PATH="${jdk}/bin:${bash}/bin:${coreutils}/bin:${which}/bin:${findutils}/bin:${gawk}/bin:${grep}/bin:${sed}/bin:${unzip}/bin:${zip}/bin:${python3}/bin:$PATH"
          export PROTOC=${protobuf}/bin/protoc
          export GRPC_JAVA_PLUGIN=${grpcJavaPlugin}/bin/protoc-gen-grpc-java
          export BAZEL_JAVAC_OPTS="-processor com.google.auto.value.processor.AutoValueProcessor,com.google.auto.value.processor.AutoOneOfProcessor,com.google.auto.value.processor.AutoBuilderProcessor,com.google.auto.service.processor.AutoServiceProcessor"

          mkdir -p derived/jars derived/maven
          cp -r ${mavenJars}/maven/. derived/maven/
          ln -s ${protobufJava}/share/java/protobuf-java-${protobufJava.version}.jar \
            derived/jars/protobuf-java.jar
          ln -s ${protobufJavaUtil}/share/java/protobuf-java-util-${protobufJavaUtil.version}.jar \
            derived/jars/protobuf-java-util.jar
          ln -s ${aliases.bazelZstdJni155}/maven/com/github/luben/zstd-jni/1.5.5-11/zstd-jni-1.5.5-11.jar \
            derived/jars/zstd-jni.jar
          index=0
          for package in ${builtins.concatStringsSep " " (builtins.map builtins.toString nettyLibraries)}; do
            j=0
            find "$package" -type f -name '*.jar' -print | while IFS= read -r jar; do
              ln -s "$jar" "derived/jars/netty-$index-$j.jar"
              j=$((j + 1))
            done
            index=$((index + 1))
          done
          printf '%s\n' 'filegroup(name = "srcs", srcs = glob(["**/*.jar"]))' \
            > derived/maven/BUILD.vendor
          printf '%s\n' 'rules_jvm_external~maven~maven' \
            > derived/maven/MAVEN_CANONICAL_REPO_NAME

          python3 ${./generate-bazel-bootstrap-resources.py} --source-root .
          sed -i "1s|^#!/bin/bash$|#!${bash}/bin/bash|" \
            compile.sh scripts/bootstrap/*.sh
          # The checkout needs two proto sources that the dist bootstrap
          # carries only as generated Java classes.
          sed -i \
            's|src/main/java/com/google/devtools/build/lib/packages/metrics/package_load_metrics.proto|src/main/java/com/google/devtools/build/lib/packages/metrics/package_metrics.proto src/main/java/com/google/devtools/build/lib/packages/metrics/package_load_metrics.proto src/main/java/com/google/devtools/build/skydoc/rendering/proto/stardoc_output.proto|' \
            scripts/bootstrap/compile.sh

          # Upstream's bootstrap scripts use unset variables as empty strings.
          set +u
          source scripts/bootstrap/buildenv.sh
          source scripts/bootstrap/compile.sh
          test -s "$OUTPUT_DIR/archive/libblaze.jar"

          # Bazel loads its native process support from inside the runner JAR.
          mkdir -p main/native
          cp ${unixJni}/lib/libunix_jni.so main/native/libunix_jni.so
          ${jdk}/bin/jar --update --file "$OUTPUT_DIR/archive/libblaze.jar" \
            main/native/libunix_jni.so

          sed -i '1s|^#!/bin/sh$|#!${bash}/bin/bash|' \
            "$OUTPUT_DIR/archive/build-runfiles"
          install -Dm644 "$OUTPUT_DIR/archive/libblaze.jar" \
            "$out/share/java/libblaze.jar"
          cp -rL "$OUTPUT_DIR/archive" "$out/share/bazel-bootstrap-archive"

          # The copied archive is materialized: follow no source-tree
          # directory symlinks when restoring these public package targets.
          for directory in allowlists whitelists; do
            find "$out/share/bazel-bootstrap-archive/embedded_tools/tools/$directory" \
              -name BUILD.tools -type f -print |
              while IFS= read -r build_file; do
                destination="''${build_file%.tools}"
                rm -f "$destination"
                cp "$build_file" "$destination"
              done
          done

          mkdir -p "$out/bin"
          cat > "$out/bin/bazel" <<BAZEL_WRAPPER
          #!${bash}/bin/bash
          set -eu
          : "\''${TMPDIR:=/tmp}"
          # The unstamped Java runner needs its pinned version for BCR feature checks.
          export BAZEL_DEV_VERSION_OVERRIDE=7.7.1
          exec ${jdk}/bin/java \
            --add-opens java.base/java.lang=ALL-UNNAMED \
            -jar "$out/share/java/libblaze.jar" \
            --batch \
            --install_base="$out/share/bazel-bootstrap-archive" \
            --output_base="\$TMPDIR/bazel-bootstrap-output" \
            --output_user_root="\$TMPDIR/bazel-bootstrap-user-root" \
            --failure_detail_out="\$TMPDIR/bazel-bootstrap-failure.rawproto" \
            --install_md5= \
            --default_system_javabase=${jdk} \
            --workspace_directory="\$PWD" \
            "\$@"
          BAZEL_WRAPPER
          chmod +x "$out/bin/bazel"
        '';
      }
    ];
  }
