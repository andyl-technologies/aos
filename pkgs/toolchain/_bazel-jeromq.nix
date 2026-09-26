##! JeroMQ and JNaCl compiled from their tagged Java source trees.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "0.5.2";
  jnaclVersion = "1.0";
  buildJdk = buildPackages.openjdk-21;
  jnaclSource = fetchurl {
    urls = ["https://github.com/neilalexander/jnacl/archive/refs/tags/v${jnaclVersion}.tar.gz"];
    hash = "sha256-/bPvDn0SBqoF95hK9Mx5NT6fL1rGhmkH7E0q3KRA43w=";
  };
in
  mkDerivation {
    pname = "bazel-jeromq";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/zeromq/jeromq/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-ANPCjNQBiRyznDxVue2S9QKsOL5dl8apZfYQWgVCCME=";
    };

    buildDeps = [buildJdk buildPackages.python3 buildPackages.findutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          tar xf ${jnaclSource}

          python3 - <<'PY'
          from pathlib import Path

          roots = ((Path("jeromq-${version}"), 152), (Path("jnacl-${jnaclVersion}"), 9))
          compiled_suffixes = {
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          }
          compiled_signatures = tuple(bytes.fromhex(value) for value in (
              "cafebabe", "7f454c46", "0061736d", "213c617263683e0a",
              "feedface", "cefaedfe", "feedfacf", "cffaedfe",
              "4d5a", "504b0304", "504b0506",
          ))

          for root, expected_sources in roots:
              sources = sorted((root / "src/main/java").rglob("*.java"))
              if len(sources) != expected_sources:
                  raise SystemExit(f"Unexpected Java source count in {root}: {len(sources)}")

              for path in root.rglob("*"):
                  if path.is_symlink():
                      raise SystemExit(f"Symlink in Java source archive: {path}")
                  if not path.is_file():
                      continue
                  with path.open("rb") as input_file:
                      header = input_file.read(8)
                  if path.suffix.lower() in compiled_suffixes or header.startswith(compiled_signatures):
                      raise SystemExit(f"Compiled payload in Java source archive: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mkdir classes-jnacl classes-jeromq
          find jnacl-${jnaclVersion}/src/main/java -name '*.java' \
            -print | sort > jnacl-sources
          find jeromq-${version}/src/main/java -name '*.java' \
            -print | sort > jeromq-sources

          ${buildJdk}/bin/javac --release 8 -proc:none -encoding UTF-8 \
            -d classes-jnacl @jnacl-sources
          ${buildJdk}/bin/javac --release 8 -proc:none -encoding UTF-8 \
            -cp classes-jnacl -d classes-jeromq @jeromq-sources
        '';
      }
      {
        name = "check";
        script = ''
          cat > JeroMqSmoke.java <<'JAVA'
          import org.zeromq.ZMQ;

          final class JeroMqSmoke {
              public static void main(String[] args) {
                  ZMQ.Curve.KeyPair pair = ZMQ.Curve.generateKeyPair();
                  if (pair.publicKey.length() != ZMQ.Curve.KEY_SIZE_Z85 ||
                          pair.secretKey.length() != ZMQ.Curve.KEY_SIZE_Z85) {
                      throw new AssertionError("JNaCl CURVE key generation failed");
                  }

                  try (ZMQ.Context context = ZMQ.context(1)) {
                      if (context == null) {
                          throw new AssertionError("JeroMQ context creation failed");
                      }
                  }
              }
          }
          JAVA

          classpath=classes-jnacl:classes-jeromq
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -cp "$classpath" JeroMqSmoke.java
          ${buildJdk}/bin/java -cp "$classpath:." JeroMqSmoke
        '';
      }
      {
        name = "install";
        script = ''
          jeromqDestination="$out/maven/org/zeromq/jeromq/${version}"
          jnaclDestination="$out/maven/eu/neilalexander/jnacl/1.0.0"
          mkdir -p "$jeromqDestination" "$jnaclDestination" \
            "$out/share/licenses/jeromq" "$out/share/licenses/jnacl" \
            "$out/share/source"

          ${buildJdk}/bin/jar --create \
            --file "$jeromqDestination/jeromq-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z \
            -C classes-jeromq .
          ${buildJdk}/bin/jar --create \
            --file "$jnaclDestination/jnacl-1.0.0.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z \
            -C classes-jnacl .

          cp jeromq-${version}/LICENSE "$out/share/licenses/jeromq/LICENSE"
          cp jnacl-${jnaclVersion}/LICENSE "$out/share/licenses/jnacl/LICENSE"
          cp -R jeromq-${version}/src/main/java "$out/share/source/jeromq"
          cp -R jnacl-${jnaclVersion}/src/main/java "$out/share/source/jnacl"
        '';
      }
    ];
  }
