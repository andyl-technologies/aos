##! Bazel bootstrap Java runner compiled from pinned source checkouts.
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
  bootstrapVersion ? "7.7.1",
  bootstrapSource ? null,
  bootstrapGrpcJavaPlugin ? null,
  bootstrapChicory ? null,
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

  source =
    if bootstrapSource == null
    then
      if bootstrapVersion == "8.6.0"
      then helperScope.bazelSource8Prepared
      else if bootstrapVersion == "9.2.0"
      then helperScope.bazelSource9
      else helperScope.bazelSource
    else bootstrapSource;
  mavenJars =
    # Bazel 8+ must deserialize its lockfile with the source-built newer Gson.
    if builtins.compareVersions bootstrapVersion "8.0.0" >= 0
    then callHelper ./_bazel-maven-bootstrap.nix {includeModernLibraries = true;}
    else helperScope.bazelMavenBootstrap;
  protobufJava = helperScope.bazelProtobufJava;
  protobufJavaUtil = helperScope.bazelProtobufJavaUtil;
  grpcJavaPlugin =
    if bootstrapGrpcJavaPlugin == null
    then
      if builtins.elem bootstrapVersion ["8.6.0" "9.2.0"]
      then
        callHelper ./_bazel-grpc-java-plugin.nix {
          pluginVersion = "1.66.0";
          pluginRev = "cf784069508fc5767a85c915e43bb43ccfc84c76";
          pluginHash = "sha256-p6VPwRD2wkErW5smvS3mtYwlE+yCUukmSEOtGEf1Ggg=";
        }
      else helperScope.bazelGrpcJavaPlugin
    else bootstrapGrpcJavaPlugin;
  chicory =
    if bootstrapChicory != null
    then bootstrapChicory
    else if bootstrapVersion == "8.6.0"
    then helperScope.bazelChicory
    else if bootstrapVersion == "9.2.0"
    then
      callHelper ./_bazel-chicory.nix {
        chicoryVersion = "1.5.2";
        chicoryRev = "4f6e73d69b76c221c200ea16a95e8699236b5bc9";
        chicoryHash = "sha256-R1BAQP0neK4rgCzAMWBPoG/BER9t43dchdjfm05VoLg=";
      }
    else null;
  unixJni =
    if bootstrapVersion == "7.7.1"
    then helperScope.bazelUnixJni
    else
      callHelper ./_bazel-unix-jni.nix {
        bazelSource = source;
        sourceVersion = bootstrapVersion;
      };
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
  platformsSource =
    if builtins.compareVersions bootstrapVersion "8.0.0" >= 0
    then helperScope.bazelPlatformsSource
    else null;
in
  mkDerivation {
    pname = "bazel-bootstrap";
    version = bootstrapVersion;
    src = source;

    # Release tooling can pass these verified Bazel 8 checkouts as module
    # overrides while fetching the remaining graph with downloads disabled.
    passthru.offlineModules = helperScope.bazelOfflineModules;
    passthru.offlineSource = source;
    passthru.offlineNettyModules = helperScope.bazelNetty119;
    passthru.offlineRepositories =
      {platforms = helperScope.bazelPlatformsSource;}
      // helperScope.bazelAsyncProfilerRepositories
      // helperScope.bazelNetty119.repositories
      // {"grpc++grpc_repo_deps_ext+com_github_cncf_xds" = helperScope.bazelGrpcXdsSource;};

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
      ++ lib.optional (chicory != null) chicory
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
          ${lib.optionalString (builtins.compareVersions bootstrapVersion "8.0.0" >= 0) ''
            # The older Gson wins classpath assembly and cannot read Bazel 8's lockfile.
            chmod u+w derived/maven/com/google/code/gson/gson/2.9.0
            rm derived/maven/com/google/code/gson/gson/2.9.0/gson-2.9.0.jar
          ''}
          ln -s ${protobufJava}/share/java/protobuf-java-${protobufJava.version}.jar \
            derived/jars/protobuf-java.jar
          ln -s ${protobufJavaUtil}/share/java/protobuf-java-util-${protobufJavaUtil.version}.jar \
            derived/jars/protobuf-java-util.jar
          ${lib.optionalString (chicory != null) ''
            ln -s ${chicory}/share/java/chicory-${chicory.version}.jar \
              derived/jars/chicory.jar
          ''}
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
          ${lib.optionalString (bootstrapVersion == "9.2.0") ''
            # This Bazel source tag omits the Protolark option definition.
            # Removing only its annotations preserves the project message
            # fields and their wire numbers.
            for proto in src/main/protobuf/project/buildable_unit.proto \
              src/main/protobuf/project/project.proto; do
              test "$(grep -c 'import "devtools/starlark/protolark/proto/protolark.proto";' "$proto")" = 1
              sed -i \
                -e '/import "devtools\/starlark\/protolark\/proto\/protolark.proto";/d' \
                -e 's/ \[(.protolark.used_in_blaze) = true\]//' \
                "$proto"
            done
            if grep -q 'used_in_blaze' src/main/protobuf/project/*.proto; then
              exit 1
            fi
          ''}
          if ! test -f third_party/googleapis/google/api/annotations.proto; then
            # Newer source tags move these proto schemas into a BCR module.
            # The source-built bootstrap uses the pinned Bazel 7 schemas.
            cp -r ${helperScope.bazelSource}/third_party/googleapis/google \
              third_party/googleapis/google
            GOOGLE_API_PROTOS="$(grep -o '".*\.proto"' \
              ${helperScope.bazelSource}/third_party/googleapis/BUILD.bazel |
              sed 's/"//g; s|^|third_party/googleapis/|g')"
            sed -i \
              's|find third_party/remoteapis |find third_party/remoteapis ''${GOOGLE_API_PROTOS} |' \
              scripts/bootstrap/compile.sh
            cat > protoc-with-googleapis <<PROTOC_WRAPPER
          #!${bash}/bin/bash
          exec ${protobuf}/bin/protoc -I${helperScope.bazelSource}/third_party/googleapis "\$@"
          PROTOC_WRAPPER
            chmod +x protoc-with-googleapis
          fi
          sed -i "1s|^#!/bin/bash$|#!${bash}/bin/bash|" \
            compile.sh scripts/bootstrap/*.sh
          # Source checkouts need proto inputs that dist bootstrap archives
          # carry only as generated Java classes.
          extra_protos=src/main/java/com/google/devtools/build/lib/packages/metrics/package_metrics.proto
          stardoc_proto=src/main/java/com/google/devtools/build/skydoc/rendering/proto/stardoc_output.proto
          if test -f "$stardoc_proto"; then
            extra_protos="$extra_protos $stardoc_proto"
          fi
          sed -i \
            "s|src/main/java/com/google/devtools/build/lib/packages/metrics/package_load_metrics.proto|$extra_protos src/main/java/com/google/devtools/build/lib/packages/metrics/package_load_metrics.proto|" \
            scripts/bootstrap/compile.sh
          ${lib.optionalString (bootstrapVersion == "9.2.0") ''
            # Dist archives carry this generated class. Source bootstrap
            # must compile its checked-in protobuf schema instead.
            sed -i \
              's|src/main/java/com/google/devtools/build/lib/packages/metrics/package_load_metrics.proto|src/main/java/com/google/devtools/build/lib/sandbox/cgroups/proto/cgroups_info.proto src/main/java/com/google/devtools/build/lib/packages/metrics/package_load_metrics.proto|' \
              scripts/bootstrap/compile.sh
          ''}

          # Upstream's bootstrap scripts use unset variables as empty strings.
          set +u
          source scripts/bootstrap/buildenv.sh
          if test -x protoc-with-googleapis; then
            export PROTOC="$PWD/protoc-with-googleapis"
          fi
          source scripts/bootstrap/compile.sh
          test -s "$OUTPUT_DIR/archive/libblaze.jar"

          # Bazel loads its native process support from inside the runner JAR.
          mkdir -p main/native
          cp ${unixJni}/lib/libunix_jni.so main/native/libunix_jni.so
          ${jdk}/bin/jar --update --file "$OUTPUT_DIR/archive/libblaze.jar" \
            main/native/libunix_jni.so

          if test -f "$OUTPUT_DIR/archive/build-runfiles"; then
            sed -i '1s|^#!/bin/sh$|#!${bash}/bin/bash|' \
              "$OUTPUT_DIR/archive/build-runfiles"
          fi
          install -Dm644 "$OUTPUT_DIR/archive/libblaze.jar" \
            "$out/share/java/libblaze.jar"
          cp -rL "$OUTPUT_DIR/archive" "$out/share/bazel-bootstrap-archive"
          ${lib.optionalString (platformsSource != null) ''
            cp -rL ${platformsSource} "$out/share/bazel-bootstrap-archive/platforms"
          ''}

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
          export BAZEL_DEV_VERSION_OVERRIDE=${bootstrapVersion}
          exec ${jdk}/bin/java \
            --add-opens java.base/java.lang=ALL-UNNAMED \
            --add-exports java.base/jdk.internal.misc=ALL-UNNAMED \
            --add-exports java.base/jdk.internal.vm=ALL-UNNAMED \
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
