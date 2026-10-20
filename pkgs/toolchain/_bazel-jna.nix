##! JNA's Java and JNI libraries built from a source-only Git checkout.
{
  mkDerivation,
  fetchgit,
  buildPackages,
}: let
  version = "5.3.1";
  buildJdk = buildPackages.openjdk-17;
  buildStdenv = buildPackages.stdenv;
  libffi = buildPackages.libffi;
  javaArchitecture =
    if buildStdenv.hostPlatform.isAarch64
    then "aarch64"
    else "x86-64";
  source = fetchgit {
    url = "https://github.com/java-native-access/jna.git";
    ref = version;
    rev = "f270bcff64d88e9b9ac7819c11adfa9d453836dc";
    name = "jna-${version}-source-only";
    hash = "sha256-pjsobO1Ks4/bVwr6MxIT0F/JKODQKdcoslsDBru87/4=";

    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;

    # The Git tag contains release archives, native binaries, test documents,
    # and a signing keystore. Exclude their blobs before checkout.
    sparsePatterns = [
      "/*"
      "!*.class"
      "!*.jar"
      "!*.aar"
      "!*.keystore"
      "!*.signature"
      "!*.jpg"
      "!*.png"
      "!*.xls"
      "!*.doc"
      "!*.evtx"
      "!*.ico"
      "!*.p12"
      "!*.lnk"
      "!*.info"
      "!*.so"
      "!*.dylib"
      "!*.jnilib"
      "!*.dll"
      "!*.a"
      "!*.o"
      "!*.obj"
      "!*.lib"
      "!*.pdb"
      "!*.exe"
      "!*.bin"
      "!*.wasm"
      "!*.zip"
      "!*.tar"
      "!*.gz"
      "!*.xz"
    ];
  };
in
  assert buildStdenv.hostPlatform.isLinux;
  assert buildStdenv.hostPlatform.isAarch64 || buildStdenv.hostPlatform.isx86_64;
    mkDerivation {
      pname = "bazel-jna";
      inherit version;
      src = source;

      buildDeps = [
        buildJdk
        libffi
        buildPackages.xorg-stubs
        buildPackages.pkg-config
        buildPackages.findutils
        buildPackages.python3
      ];
      runtimeDeps = [libffi];

      phases = [
        {
          name = "audit-source";
          script = ''
            python3 - "$src" <<'PY'
            from pathlib import Path
            import sys

            compiled_suffixes = {
                ".class", ".jar", ".aar", ".so", ".dylib", ".jnilib",
                ".dll", ".a", ".o", ".obj", ".lib", ".exe", ".bin",
                ".wasm", ".zip", ".tar", ".gz", ".xz",
            }
            compiled_signatures = (
                bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
                bytes.fromhex("0061736d"), bytes.fromhex("213c617263683e0a"),
                bytes.fromhex("4d5a"), bytes.fromhex("504b0304"),
            )
            for path in Path(sys.argv[1]).rglob("*"):
                if not path.is_file():
                    continue
                data = path.read_bytes()
                if path.suffix.lower() in compiled_suffixes:
                    raise SystemExit(f"Compiled payload in JNA source: {path}")
                if data[:8].startswith(compiled_signatures) or b"\0" in data:
                    raise SystemExit(f"Opaque payload in JNA source: {path}")
            PY
          '';
        }
        {
          name = "build";
          script = ''
            export JAVA_HOME=${buildJdk}
            export PATH="$JAVA_HOME/bin:$PATH"

            mkdir -p classes platform-classes build/native
            find "$src/src" -type f -name '*.java' -print > core-sources
            javac --release 8 -proc:none -encoding UTF-8 \
              -h build/native -d classes @core-sources

            find "$src/contrib/platform/src" -type f -name '*.java' \
              -print > platform-sources
            javac --release 8 -proc:none -encoding UTF-8 \
              -cp classes -d platform-classes @platform-sources

            cp -a "$src/native" native
            chmod -R u+w native
            grep -F -q 'String VERSION_NATIVE = "6.0.0";' \
              "$src/src/com/sun/jna/Version.java"
            make -C native DYNAMIC_LIBFFI=true JNA_JNI_VERSION=6.0.0 \
              CC=cc LD=cc ../build/native/libjnidispatch.so
            test -s build/native/libjnidispatch.so

            mkdir -p classes/com/sun/jna/linux-${javaArchitecture}
            cp build/native/libjnidispatch.so \
              classes/com/sun/jna/linux-${javaArchitecture}/libjnidispatch.so
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/share/java" "$out/share/licenses/jna"
            jar --create --file "$out/share/java/jna-${version}.jar" \
              --no-manifest --date=1980-01-01T00:00:02Z -C classes .
            jar --create --file "$out/share/java/jna-platform-${version}.jar" \
              --no-manifest --date=1980-01-01T00:00:02Z -C platform-classes .
            cp "$src/LICENSE" "$src/AL2.0" "$src/LGPL2.1" "$src/OTHERS" \
              "$out/share/licenses/jna/"
          '';
        }
      ];
    }
