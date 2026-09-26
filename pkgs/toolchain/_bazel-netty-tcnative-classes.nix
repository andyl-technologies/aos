##! Netty TCNative Java API rebuilt from its release source tree.
{
  mkDerivation,
  fetchgit,
  buildPackages,
}: let
  version = "2.0.56.Final";
  buildJdk = buildPackages.openjdk-21;
in
  mkDerivation {
    pname = "bazel-netty-tcnative-classes";
    inherit version;

    src = fetchgit {
      url = "https://github.com/netty/netty-tcnative.git";
      rev = "fb50ea32f4bd2fada4a4cc576b34818eac60e01d";
      name = "netty-tcnative-${version}-java-source-only";
      hash = "sha256-No36p2JPDsbnF2Hxo5sEQ/Jjj0oRLxFUcl9AFVz65m8=";
      deepClone = true;
      git = buildPackages.git-minimal;
      caCertificates = buildPackages.ca-certificates;
      coreutils = buildPackages.coreutils;
      sparsePatterns = [
        "/openssl-classes/src/main/java/"
        "/LICENSE.txt"
        "/NOTICE.txt"
      ];
    };

    buildDeps = [buildJdk buildPackages.python3];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir source
          cp -R "$src"/. source/

          python3 - <<'PY'
          from pathlib import Path

          source = Path("source")
          files = [path for path in source.rglob("*") if path.is_file()]
          java = [path for path in files if path.suffix == ".java"]
          if len(files) != 26 or len(java) != 24:
              raise SystemExit(f"Unexpected Netty TCNative Java inventory: {len(files)} files, {len(java)} Java")
          for path in files:
              if path.suffix not in {".java", ".txt"}:
                  raise SystemExit(f"Unexpected Netty TCNative input: {path}")
              path.read_text(encoding="utf-8")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p classes
          find source/openssl-classes/src/main/java -name '*.java' \
            | sort > java-sources
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -d classes @java-sources
        '';
      }
      {
        name = "check";
        script = ''
          test -s classes/io/netty/internal/tcnative/Library.class
          test -s classes/io/netty/internal/tcnative/SSLContext.class
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/io/netty/netty-tcnative-classes/${version}"
          mkdir -p "$destination" "$out/share/java" \
            "$out/share/licenses/netty-tcnative" "$out/share/source"
          ${buildJdk}/bin/jar --create \
            --file "$destination/netty-tcnative-classes-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp "$destination/netty-tcnative-classes-${version}.jar" "$out/share/java/"
          cp source/LICENSE.txt source/NOTICE.txt \
            "$out/share/licenses/netty-tcnative/"
          cp -R source "$out/share/source/netty-tcnative"
        '';
      }
    ];
  }
