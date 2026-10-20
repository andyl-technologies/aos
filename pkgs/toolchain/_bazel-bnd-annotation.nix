##! bnd annotations and their OSGi API dependencies rebuilt from Java source.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  buildJdk = buildPackages.openjdk-21;
  version = "6.3.1";

  osgiAnnotation = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/osgi/osgi.annotation/8.1.0/osgi.annotation-8.1.0-sources.jar"];
    hash = "sha256-sfQYWXpQKXZJc3MdnmiDXxPrO/TnppiY5pDsUERaenY=";
  };
  osgiDto = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/osgi/org.osgi.dto/1.0.0/org.osgi.dto-1.0.0-sources.jar"];
    hash = "sha256-2R9h3gW3BMbAORtko0Nkflzn134FjqbN5BDYpr7Eizg=";
  };
  osgiResource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/osgi/org.osgi.resource/1.0.0/org.osgi.resource-1.0.0-sources.jar"];
    hash = "sha256-TeCjpfgbX5Y1v43KrBInugEf/t0z09OWEDilXZh2IEI=";
  };
  osgiExtender = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/osgi/org.osgi.namespace.extender/1.0.1/org.osgi.namespace.extender-1.0.1-sources.jar"];
    hash = "sha256-v/a493juKtDFNmfM3qkH7H8XFe1jtDek2biAKKaK+Ek=";
  };
  osgiService = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/osgi/org.osgi.namespace.service/1.0.0/org.osgi.namespace.service-1.0.0-sources.jar"];
    hash = "sha256-iCH64P9DPFncKq1GvYfyZn0Ff/r2h2ZKrdMmQoRFvGI=";
  };
  osgiServiceLoader = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/org/osgi/org.osgi.service.serviceloader/1.0.0/org.osgi.service.serviceloader-1.0.0-sources.jar"];
    hash = "sha256-fUeDtXDNEYJjvGqAfAp8GDsdtFFEL/y4o2MQrSSpF0M=";
  };
  bndSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/biz/aQute/bnd/biz.aQute.bnd.annotation/${version}/biz.aQute.bnd.annotation-${version}-sources.jar"];
    hash = "sha256-G/oTuncmTDPsziJe28xMz64AhXTYStFEugJbm0iNB24=";
  };
  bndPom = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/biz/aQute/bnd/biz.aQute.bnd.annotation/${version}/biz.aQute.bnd.annotation-${version}.pom"];
    hash = "sha256-EF3wZHYbgG50z2sKRBRkUKwjKbvsypeXrUnVjEOSdZQ=";
  };
in
  mkDerivation {
    pname = "bazel-bnd-annotation";
    inherit version;
    src = bndSource;

    buildDeps = [buildJdk buildPackages.python3];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          python3 - \
            "annotation:15:${osgiAnnotation}" \
            "dto:2:${osgiDto}" \
            "resource:15:${osgiResource}" \
            "extender:2:${osgiExtender}" \
            "service:2:${osgiService}" \
            "serviceloader:2:${osgiServiceLoader}" \
            "bnd:73:$src" <<'PY'
          from pathlib import Path, PurePosixPath
          from zipfile import ZipFile
          import stat
          import sys

          compiled_signatures = tuple(bytes.fromhex(value) for value in (
              "cafebabe", "7f454c46", "0061736d", "213c617263683e0a",
              "feedface", "cefaedfe", "feedfacf", "cffaedfe", "4d5a",
          ))
          for specification in sys.argv[1:]:
              name, count, archive_path = specification.split(":", 2)
              root = Path("source") / name

              with ZipFile(archive_path) as archive:
                  for member in archive.infolist():
                      path = PurePosixPath(member.filename)
                      kind = stat.S_IFMT(member.external_attr >> 16)
                      if path.is_absolute() or ".." in path.parts or kind == stat.S_IFLNK:
                          raise SystemExit(f"Unsafe {name} source: {path}")
                      if member.is_dir():
                          continue
                      if path.suffix not in {".java", ".html"} and path.name not in {"LICENSE", "packageinfo"} and str(path) != "META-INF/MANIFEST.MF":
                          raise SystemExit(f"Unexpected {name} source: {path}")

                      data = archive.read(member)
                      if data.startswith(compiled_signatures):
                          raise SystemExit(f"Compiled {name} source: {path}")
                      data.decode("utf-8")

                      destination = root / str(path)
                      destination.parent.mkdir(parents=True, exist_ok=True)
                      destination.write_bytes(data)

              sources = sorted(root.rglob("*.java"))
              if len(sources) != int(count):
                  raise SystemExit(f"Expected {count} {name} Java sources, found {len(sources)}")
              Path(f"{name}-sources").write_text(
                  "".join(f"{path}\n" for path in sources), encoding="utf-8")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p classes/annotation classes/dto classes/resource \
            classes/extender classes/service classes/serviceloader classes/bnd

          ${buildJdk}/bin/javac --release 8 -proc:none \
            -encoding UTF-8 -d classes/annotation @annotation-sources
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -cp classes/annotation -encoding UTF-8 -d classes/dto @dto-sources
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -cp classes/annotation:classes/dto \
            -encoding UTF-8 -d classes/resource @resource-sources

          osgi_classpath=classes/annotation:classes/dto:classes/resource
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -cp "$osgi_classpath" -encoding UTF-8 \
            -d classes/extender @extender-sources
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -cp "$osgi_classpath" -encoding UTF-8 \
            -d classes/service @service-sources
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -cp "$osgi_classpath" -encoding UTF-8 \
            -d classes/serviceloader @serviceloader-sources

          ${buildJdk}/bin/javac --release 8 -proc:none \
            -cp "$osgi_classpath:classes/extender:classes/service:classes/serviceloader" \
            -encoding UTF-8 -d classes/bnd @bnd-sources
        '';
      }
      {
        name = "check";
        script = ''
          ${
            if stdenv.hostPlatform.system == stdenv.buildPlatform.system
            then ''
              cat > BndAnnotationSmoke.java <<'JAVA'
              import aQute.bnd.annotation.Resolution;
              import aQute.bnd.annotation.spi.ServiceProvider;

              @ServiceProvider(value = Runnable.class, resolution = Resolution.OPTIONAL)
              final class BndAnnotationSmoke implements Runnable {
                  @Override
                  public void run() {}
              }
              JAVA

              classpath="classes/annotation:classes/dto:classes/resource:classes/extender:classes/service:classes/serviceloader:classes/bnd"
              ${buildJdk}/bin/javac --release 8 -proc:none \
                -cp "$classpath" BndAnnotationSmoke.java
              ${buildJdk}/bin/javap -v BndAnnotationSmoke | \
                ${buildPackages.grep}/bin/grep -q 'aQute.bnd.annotation.spi.ServiceProvider'
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          install_jar() {
            component="$1"
            coordinates="$2"
            filename="$3"
            destination="$out/maven/$coordinates"
            mkdir -p "$destination"
            ${buildJdk}/bin/jar --create \
              --file "$destination/$filename" \
              --no-manifest --date=1980-01-01T00:00:02Z \
              -C "classes/$component" .
          }

          install_jar annotation org/osgi/osgi.annotation/8.1.0 osgi.annotation-8.1.0.jar
          install_jar dto org/osgi/org.osgi.dto/1.0.0 org.osgi.dto-1.0.0.jar
          install_jar resource org/osgi/org.osgi.resource/1.0.0 org.osgi.resource-1.0.0.jar
          install_jar extender org/osgi/org.osgi.namespace.extender/1.0.1 org.osgi.namespace.extender-1.0.1.jar
          install_jar service org/osgi/org.osgi.namespace.service/1.0.0 org.osgi.namespace.service-1.0.0.jar
          install_jar serviceloader org/osgi/org.osgi.service.serviceloader/1.0.0 org.osgi.service.serviceloader-1.0.0.jar
          install_jar bnd biz/aQute/bnd/biz.aQute.bnd.annotation/${version} biz.aQute.bnd.annotation-${version}.jar

          mkdir -p "$out/share/source" "$out/share/licenses/osgi"
          cp -R source/. "$out/share/source/"
          cp "${bndPom}" "$out/share/source/bnd/pom.xml"
          cp source/resource/LICENSE "$out/share/licenses/osgi/LICENSE"
        '';
      }
    ];
  }
