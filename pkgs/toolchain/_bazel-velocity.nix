##! Velocity 1.7 built with source-only XML and XPath compile dependencies.
{
  mkDerivation,
  fetchurl,
  fetchgit,
  buildPackages,
  bazelMavenBootstrap,
  bazelLog4j,
  bazelAvalonApi,
  bazelLegacyJavaHttp,
}: let
  version = "1.7";
  buildJdk = buildPackages.openjdk-17;

  sources = [
    {
      name = "velocity";
      url = "https://repo.maven.apache.org/maven2/org/apache/velocity/velocity/1.7/velocity-1.7-sources.jar";
      hash = "sha256-+4B5B39++bTuQGuJPQ6Rn5f6Ros6pFeCs0FRnzzLwsI=";
    }
    {
      name = "jdom";
      url = "https://repo.maven.apache.org/maven2/jdom/jdom/1.0/jdom-1.0-sources.jar";
      hash = "sha256-pvJKSsvBU9QvXz3ZM7qjoxF+gC8uyjCLccwJ1HHMawU=";
    }
    {
      name = "jaxen";
      url = "https://repo.maven.apache.org/maven2/jaxen/jaxen/1.1.6/jaxen-1.1.6-sources.jar";
      hash = "sha256-fYZeZJ492iom2a7j9/Lp4QVpruaIRj/rV9C9oWdF6qI=";
    }
    {
      name = "saxpath";
      url = "https://repo.maven.apache.org/maven2/saxpath/saxpath/1.0-FCS/saxpath-1.0-FCS-sources.jar";
      hash = "sha256-IXe0PUWz3b67X5qU9lWLEhGUCeEvUV9xhMaHCSnW+lA=";
    }
    {
      name = "dom4j";
      url = "https://repo.maven.apache.org/maven2/dom4j/dom4j/1.6.1/dom4j-1.6.1-sources.jar";
      hash = "sha256-TTcnX4CZGje+Rg5zsBiQFy+C/VYSU7ohMLYqel0HIi0=";
    }
    {
      name = "xerces";
      url = "https://repo.maven.apache.org/maven2/xerces/xercesImpl/2.6.2/xercesImpl-2.6.2-sources.jar";
      hash = "sha256-Ab1tzDFAPzaondHI1+NLX1+Sz8QDUUiwBykHJII3ICY=";
    }
    {
      name = "antlr";
      url = "https://repo.maven.apache.org/maven2/antlr/antlr/2.7.6/antlr-2.7.6-sources.jar";
      hash = "sha256-HatGMr7yWF7OAMmXO9dCZv/S11JwzO1z5uC52tk6vzg=";
    }
  ];
  archives = builtins.map (source:
    source
    // {
      src = fetchurl {
        urls = [source.url];
        inherit (source) hash;
      };
    })
  sources;

  sourceFor = name: (builtins.head (builtins.filter (source: source.name == name) archives)).src;
  unpackSources = builtins.concatStringsSep "\n" (builtins.map (source: ''
      mkdir source-${source.name}
      unzip -q ${source.src} -d source-${source.name}
    '')
    archives);

  werkenSource = fetchurl {
    urls = ["https://deb.debian.org/debian/pool/main/w/werken.xpath/werken.xpath_0.9.4.orig.tar.gz"];
    hash = "sha256-CF/nDpy20iFgIR3ALIyujVli8C7Akx1nIg+EnIjNeqo=";
  };
  xomSource = fetchgit {
    url = "https://github.com/elharo/xom.git";
    ref = "master";
    rev = "8b55d083da2c13b37c9d5c519506d2a7d15081b5";
    hash = "sha256-KXnOwnbYH2j3WyR80B/3wJtZ2byo2nDsUyVKRzG+EIc=";
    name = "xom-1.1-java-source-only";

    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = ["/src/nu/xom/**/*.java"];
  };

  upstreamResources = [
    {
      path = "org/apache/velocity/runtime/defaults/directive.properties";
      hash = "sha256-XBo3e54VyTCXs6WvBDrvbLjf9+3xqyODFxZ6jY2kqeA=";
    }
    {
      path = "org/apache/velocity/runtime/defaults/velocity.properties";
      hash = "sha256-IFVU2+9OGMUi3+TIYOVFiMXF/izw7mJoG+2OCNjObJc=";
    }
    {
      path = "org/apache/velocity/texen/defaults/texen.properties";
      hash = "sha256-njNYpnEpfQ6YL+7XcFGnO6fESmWBEvxU0PAU98T5u7g=";
    }
  ];
  resources = builtins.map (resource:
    resource
    // {
      src = fetchurl {
        urls = ["https://raw.githubusercontent.com/apache/velocity-engine/e0383483e1b0ab37874e09f31e71bf01143f8238/src/java/${resource.path}"];
        inherit (resource) hash;
      };
    })
  upstreamResources;
  copyResources = builtins.concatStringsSep "\n" (builtins.map (resource: ''
      install -Dm644 ${resource.src} classes-velocity/${resource.path}
    '')
    resources);
in
  mkDerivation {
    pname = "bazel-velocity";
    inherit version;
    src = sourceFor "velocity";

    buildDeps = [
      buildJdk
      buildPackages.unzip
      buildPackages.tar
      buildPackages.patch
      buildPackages.findutils
      buildPackages.python3
      buildPackages.ant
      bazelMavenBootstrap
      bazelLog4j
      bazelAvalonApi
      bazelLegacyJavaHttp
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          ${unpackSources}
          tar xf ${werkenSource}
          mv werken.xpath-0.9.4.orig source-werken
          (cd source-werken && patch -p1 < ${./patches/bazel-velocity-werken-jdom1.patch})

          # XOM's Maven sources archive embeds compiled classes. Its Java
          # sources come from a sparse upstream checkout instead.
          python3 - ${xomSource} source-* <<'PY'
          from pathlib import Path
          import sys

          compiled_suffixes = {
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("213c617263683e0a"),
              bytes.fromhex("4d5a"), bytes.fromhex("504b0304"),
          )
          for argument in sys.argv[1:]:
              for path in Path(argument).rglob("*"):
                  if not path.is_file():
                      continue
                  if path.suffix.lower() in compiled_suffixes:
                      raise SystemExit(f"Compiled payload in Java source: {path}")
                  if path.read_bytes()[:8].startswith(compiled_signatures):
                      raise SystemExit(f"Compiled payload in Java source: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          maven_classpath=$(find ${bazelMavenBootstrap}/maven -type f -name '*.jar' -print | sort | paste -sd:)
          classpath="$maven_classpath:${buildPackages.ant}/lib/ant.jar"
          classpath="$classpath:${bazelLog4j}/maven/log4j/log4j/1.2.17/log4j-1.2.17.jar"
          classpath="$classpath:${bazelAvalonApi}/maven/logkit/logkit/1.0.1/logkit-1.0.1.jar"
          classpath="$classpath:${bazelLegacyJavaHttp}/maven/commons-logging/commons-logging/1.2/commons-logging-1.2.jar"
          printf '%s\n' "$classpath" > build-classpath.txt

          # Compile the complete Jaxen, JDOM, and SAXPath source sets. javac
          # builds their optional DOM4J, XOM, and Xerces adapter inputs from
          # the source path, without fetching any compiled artifacts.
          find source-jaxen source-jdom source-saxpath -type f -name '*.java' \
            ! -path '*/org/w3c/dom/UserDataHandler.java' -print > xml-sources.list
          mkdir classes-xml
          javac -J-Xss32m --release 8 -proc:none -encoding UTF-8 \
            -sourcepath "source-jaxen:source-jdom:source-saxpath:source-dom4j:source-xerces:${xomSource}/src" \
            -cp "$classpath" -d classes-xml @xml-sources.list

          find source-antlr -type f -name '*.java' -print > antlr-sources.list
          mkdir classes-antlr
          javac --release 8 -proc:none -encoding UTF-8 \
            -d classes-antlr @antlr-sources.list

          parser=source-werken/src/com/werken/xpath/parser
          java -cp classes-antlr antlr.Tool -o "$parser" "$parser/xpath.g"
          java -cp classes-antlr antlr.Tool -o "$parser" "$parser/xpath_lexer.g"
          find source-werken/src -type f -name '*.java' -print > werken-sources.list
          mkdir classes-werken
          javac --release 8 -proc:none -encoding UTF-8 \
            -cp "classes-xml:classes-antlr:$classpath" \
            -d classes-werken @werken-sources.list

          find source-velocity -type f -name '*.java' -print > velocity-sources.list
          mkdir classes-velocity
          javac --release 8 -proc:none -encoding UTF-8 \
            -cp "classes-xml:classes-werken:classes-antlr:$classpath" \
            -d classes-velocity @velocity-sources.list

          # Maven's source JAR omits these runtime defaults; pin their text
          # from the matching upstream Velocity 1.7 source revision.
          ${copyResources}
          jar --create --file velocity.jar --no-manifest \
            --date=1980-01-01T00:00:02Z -C classes-velocity .
        '';
      }
      {
        name = "check";
        script = ''
          cat > VelocitySourceSmoke.java <<'JAVA'
          import java.io.StringWriter;
          import org.apache.velocity.VelocityContext;
          import org.apache.velocity.app.VelocityEngine;

          final class VelocitySourceSmoke {
              public static void main(String[] args) throws Exception {
                  VelocityEngine engine = new VelocityEngine();
                  engine.setProperty("runtime.log.logsystem.class",
                      "org.apache.velocity.runtime.log.NullLogChute");
                  engine.init();

                  VelocityContext context = new VelocityContext();
                  context.put("name", "source");
                  StringWriter writer = new StringWriter();
                  engine.evaluate(context, writer, "source", "Hello $name");
                  if (!"Hello source".equals(writer.toString())) {
                      throw new AssertionError(writer.toString());
                  }
              }
          }
          JAVA

          classpath=$(cat build-classpath.txt)
          javac --release 8 -proc:none -cp "velocity.jar:$classpath" \
            VelocitySourceSmoke.java
          java -cp ".:velocity.jar:$classpath" VelocitySourceSmoke
        '';
      }
      {
        name = "install";
        script = ''
          install -Dm644 velocity.jar \
            "$out/maven/org/apache/velocity/velocity/${version}/velocity-${version}.jar"
        '';
      }
    ];
  }
