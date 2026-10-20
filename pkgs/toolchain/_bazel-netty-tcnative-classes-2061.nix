##! Pinned Netty TCNative Java APIs compiled from audited sources.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  version ? "2.0.61.Final",
}: let
  sourcePin =
    if version == "2.0.70.Final"
    then {
      revision = "431c098de23145edbd7112d96ad3fc30955a0e3b";
      hash = "sha256-XOP3q8N51dMZPgFlH33ctqVyr6OSyFoPWm4mJBrzMvE=";
      javaFiles = 25;
    }
    else
      assert version == "2.0.61.Final"; {
        revision = "ea87032e1dd058f7d3d5a8c5d1852e690a5142a3";
        hash = "sha256-tUI3C+atTXI+AVb8Qf/A2576MIMw5xrsGM3rDfw6RNA=";
        javaFiles = 24;
      };
  buildJdk = buildPackages.openjdk-21;
  source = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/io/netty/netty-tcnative-classes/${version}/netty-tcnative-classes-${version}-sources.jar"];
    inherit (sourcePin) hash;
  };
  license = fetchurl {
    urls = ["https://raw.githubusercontent.com/netty/netty-tcnative/${sourcePin.revision}/LICENSE.txt"];
    hash = "sha256-xx0jnfkXJvxRnG63LTGOxlggYnIysveWIZ6H3PNdCrQ=";
  };
  notice = fetchurl {
    urls = ["https://raw.githubusercontent.com/netty/netty-tcnative/${sourcePin.revision}/NOTICE.txt"];
    hash = "sha256-ewnB5LERiOiFLzc+5YTMN3WX+QdgoS+ZSPH5pEpynYo=";
  };
in
  mkDerivation {
    pname = "bazel-netty-tcnative-classes";
    inherit version;
    src = source;

    passthru.sourceTargets = ["io/netty/netty-tcnative-classes/${version}/netty-tcnative-classes-${version}.jar"];

    buildDeps = [buildJdk buildPackages.python3];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          python3 - "$src" <<'PY'
          from pathlib import Path, PurePosixPath
          from zipfile import ZipFile
          import stat
          import sys

          with ZipFile(sys.argv[1]) as archive:
              java_files = []
              for member in archive.infolist():
                  path = PurePosixPath(member.filename)
                  kind = stat.S_IFMT(member.external_attr >> 16)
                  if path.is_absolute() or ".." in path.parts or kind == stat.S_IFLNK:
                      raise SystemExit(f"Unsafe TCNative Java source: {path}")
                  if member.is_dir():
                      continue
                  if path.suffix not in {".java", ".xml", ".yml"} and str(path) != "META-INF/MANIFEST.MF":
                      raise SystemExit(f"Unexpected TCNative Java source: {path}")
                  data = archive.read(member)
                  if b"\0" in data:
                      raise SystemExit(f"Opaque TCNative Java source: {path}")
                  data.decode("utf-8")
                  if path.suffix != ".java":
                      continue
                  destination = Path("source") / str(path)
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)
                  java_files.append(destination)

          if len(java_files) != ${toString sourcePin.javaFiles}:
              raise SystemExit(f"Expected ${toString sourcePin.javaFiles} TCNative Java sources, found {len(java_files)}")
          Path("java-sources").write_text("".join(f"{path}\n" for path in sorted(java_files)))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mkdir classes
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
            "$out/share/source/netty-tcnative-classes" \
            "$out/share/licenses/netty-tcnative"
          ${buildJdk}/bin/jar --create \
            --file "$destination/netty-tcnative-classes-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp "$destination/netty-tcnative-classes-${version}.jar" "$out/share/java/"
          cp -R source/. "$out/share/source/netty-tcnative-classes/"
          cp ${license} "$out/share/licenses/netty-tcnative/LICENSE.txt"
          cp ${notice} "$out/share/licenses/netty-tcnative/NOTICE.txt"
        '';
      }
    ];
  }
