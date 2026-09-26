##! async-profiler native library built from source for Bazel's Linux bootstrap.
{
  mkDerivation,
  fetchgit,
  buildPackages,
  stdenv,
  gcc-libs,
}: let
  version = "3.0";
  buildJdk = buildPackages.openjdk-17;
  source = fetchgit {
    url = "https://github.com/async-profiler/async-profiler.git";
    ref = "v${version}";
    rev = "4e441b4024a5873a5764a1e8b9f0bb25ad997fbf";
    hash = "sha256-JI8PPD4/MpZYHrnoKZvMJ/vyYb+XAcvjI7iGDtTANpE=";
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;

    # The tag tracks compiled Java helpers. Rebuild them from their sources.
    sparsePatterns = [
      "/src/"
      "/LICENSE"
      "!/src/helper/one/profiler/*.class"
    ];
  };
in
  assert stdenv.hostPlatform.isLinux;
  assert stdenv.hostPlatform.isx86_64 || stdenv.hostPlatform.isAarch64;
    mkDerivation {
      pname = "bazel-async-profiler-native";
      inherit version;
      src = source;

      buildDeps = [
        buildJdk
        buildPackages.findutils
        buildPackages.python3
      ];
      runtimeDeps = [gcc-libs];

      phases = [
        {
          name = "audit-source";
          script = ''
            python3 - "$src" <<'PY'
            from pathlib import Path
            import sys

            compiled_suffixes = {
                ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
                ".exe", ".bin", ".wasm", ".zip", ".tar", ".gz", ".xz",
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
                    raise SystemExit(f"Compiled payload in async-profiler source: {path}")
                if data[:8].startswith(compiled_signatures) or b"\0" in data:
                    raise SystemExit(f"Opaque payload in async-profiler source: {path}")
            PY
          '';
        }
        {
          name = "build";
          script = ''
            export JAVA_HOME=${buildJdk}
            export PATH="$JAVA_HOME/bin:$PATH"

            cp -R "$src"/. .
            chmod -R u+w src

            # Upstream embeds these classes in the library via .incbin.
            # JfrSync targets Java 8 bytecode but references JFR APIs in JDK 17.
            javac -source 8 -target 8 -Xlint:-options -proc:none -g:none \
              -encoding UTF-8 \
              -d src/helper src/helper/one/profiler/*.java

            c++ -O3 -fno-exceptions -fno-omit-frame-pointer \
              -fvisibility=hidden -Wl,-z,defs \
              -DPROFILER_VERSION='"${version}"' \
              -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
              -Isrc/helper -fPIC -shared \
              -o libasyncProfiler.so src/*.cpp -ldl -lpthread -lrt
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/lib"
            cp libasyncProfiler.so "$out/lib/"
            cp "$src/LICENSE" "$out/"
          '';
        }
      ];
    }
