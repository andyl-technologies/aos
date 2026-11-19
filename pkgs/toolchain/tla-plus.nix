##! tla-plus — TLA+ tools: TLC model checker, SANY parser, PlusCal translator
{
  lib,
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
  openjdk-17,
  bash,
}: let
  # v1.8.0 is marked as a pre-release on GitHub. It is the first tagged
  # release of the 1.8 line that current TLA+ libraries such as the
  # CommunityModules target.
  version = "1.8.0";
  revision = "56d37a9b7bf529086fd961160e0b8975e224eafc";
  # TLC derives its CalVer version string from the manifest build timestamp
  # and otherwise reports the current time. Pin it to the tagged commit.
  releaseTimestamp = "2026-10-24T01:02:01.0Z";
  jdk = openjdk-17;
  buildJdk = buildPackages.openjdk-17;
  buildGit = buildPackages.git-minimal;
  buildCaCertificates = buildPackages.ca-certificates;
  buildCoreutils = buildPackages.coreutils;

  # The upstream repository carries compiled third-party JARs. Fetch only the
  # TLA+ sources and documentation so they never enter the build closure.
  tlaSource = fetchgit {
    url = "https://github.com/tlaplus/tlaplus.git";
    ref = "v${version}";
    rev = revision;
    hash = "sha256-xlHlQ4k5smXAnF3IlfrUhFi1cddMZPQoIW2w2ZQU54M=";
    git = buildGit;
    caCertificates = buildCaCertificates;
    coreutils = buildCoreutils;
    # Cone mode also checks out unrelated files at the repository root.
    sparsePatterns = [
      "/tlatools/org.lamport.tlatools/src/"
      "/tlatools/org.lamport.tlatools/doc/License.txt"
      "!/tlatools/org.lamport.tlatools/src/tla2sany/drivers/drivers - Shortcut.lnk"
    ];
  };

  sources = import ./_tla-plus/sources.nix {inherit fetchurl;};
  inherit (sources) activation mail jline juniversalchardet gson errorProneAnnotations lsp4j prettier4j apiguardian;
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      role = "public-package";
    };
    pname = "tla-plus";
    smokeTest = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "SANY completes parsing and semantic processing without errors.";
        "files" = {
          "Qualified.tla" = "---- MODULE Qualified ----\nEXTENDS Naturals\nAnswer == 40 + 2\n====\n";
        };
        "input" = "A syntactically valid TLA+ module defining a constant expression.";
        "operation" = "Parse and semantically analyze the module with the packaged SANY launcher.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/sany\", \"Qualified.tla\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"Semantic processing of module Qualified\" in result.stdout\nprint(\"tla-plus operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "tla-plus operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "SANY reports a parse error and returns failure.";
        "files" = {
          "Invalid.tla" = "---- MODULE Invalid ----\nBroken == (1 +\n====\n";
        };
        "input" = "A TLA+ module with an unterminated expression.";
        "operation" = "Parse the malformed module with SANY.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/sany\", \"Invalid.tla\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"Parse Error\" in result.stdout\n\nsys.stderr.write(\"tla-plus rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "tla-plus rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    version = "=${version}";
    src = tlaSource;

    buildDeps = [buildJdk buildPackages.python3];
    runtimeDeps = [jdk bash];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R ${tlaSource}/tlatools/org.lamport.tlatools/src tla-src

          # Extract only the module sources that are compiled. The archives
          # also carry build wrappers, test fixtures, and prebuilt native
          # libraries that the build must not see.
          tar xf ${activation.src} ${activation.dir}/activation/src/main \
            ${activation.dir}/LICENSE.md ${activation.dir}/NOTICE.md
          tar xf ${mail.src} ${mail.dir}/mail/src/main ${mail.dir}/smtp/src/main \
            ${mail.dir}/LICENSE.md ${mail.dir}/NOTICE.md
          tar xf ${jline.src} ${jline.dir}/LICENSE.txt \
            ${jline.dir}/terminal/src/main ${jline.dir}/reader/src/main \
            ${jline.dir}/console/src/main ${jline.dir}/builtins/src/main \
            ${jline.dir}/native/src/main/java
          tar xf ${juniversalchardet.src} ${juniversalchardet.dir}/src/main/java
          tar xf ${gson.src} ${gson.dir}/LICENSE ${gson.dir}/gson/src/main
          tar xf ${errorProneAnnotations.src} \
            ${errorProneAnnotations.dir}/annotations/src/main/java
          tar xf ${lsp4j.src} ${lsp4j.dir}/LICENSE ${lsp4j.dir}/NOTICE \
            ${lsp4j.dir}/org.eclipse.lsp4j.jsonrpc/src/main/java \
            ${lsp4j.dir}/org.eclipse.lsp4j.jsonrpc.debug/src/main/java
          mkdir lsp4j-debug
          (cd lsp4j-debug && ${buildJdk}/bin/jar xf ${sources.lsp4jDebugSources} org)
          tar xf ${prettier4j.src} ${prettier4j.dir}/LICENSE ${prettier4j.dir}/src/main/java
          tar xf ${apiguardian.src} ${apiguardian.dir}/src/main/java

          python3 ${./_tla-plus/payload-guard.py} "TLA+" tla-src \
            ${activation.dir} ${mail.dir} ${jline.dir} ${juniversalchardet.dir} \
            ${gson.dir} ${errorProneAnnotations.dir} ${lsp4j.dir} lsp4j-debug \
            ${prettier4j.dir} ${apiguardian.dir}
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME="${buildJdk}"
          export PATH="${buildJdk}/bin:$PATH"

          # Compile every Java file below the given source roots into one
          # class directory. Module descriptors are skipped because the
          # libraries are bundled onto a single classpath.
          compile_java() {
            output=$1
            classpath=$2
            shift 2
            mkdir -p "$output"
            find "$@" -name '*.java' ! -name module-info.java -print > "$output.sources"
            javac --release 11 -encoding UTF-8 -nowarn -cp "$classpath" \
              -d "$output" @"$output.sources"
          }

          # Maven and Gradle normally generate these version classes.
          mkdir -p mail-generated/javax/mail gson-generated/com/google/gson/internal
          sed 's|version = .*;|version = "${mail.version}";|' \
            ${mail.dir}/mail/src/main/resources/javax/mail/Version.java \
            > mail-generated/javax/mail/Version.java
          sed 's|''${project.version}|${gson.version}|' \
            ${gson.dir}/gson/src/main/java-templates/com/google/gson/internal/GsonBuildConfig.java \
            > gson-generated/com/google/gson/internal/GsonBuildConfig.java

          # Compile-only dependencies, which upstream also leaves out of
          # tla2tools.jar.
          compile_java apiguardian-classes "" ${apiguardian.dir}/src/main/java
          compile_java error-prone-classes "" \
            ${errorProneAnnotations.dir}/annotations/src/main/java
          compile_java chardet-classes "" ${juniversalchardet.dir}/src/main/java
          compile_java jline-native-classes "" ${jline.dir}/native/src/main/java

          # Bundled libraries.
          compile_java activation-classes "" ${activation.dir}/activation/src/main/java
          compile_java mail-classes activation-classes \
            ${mail.dir}/mail/src/main/java ${mail.dir}/smtp/src/main/java mail-generated
          compile_java gson-classes error-prone-classes \
            ${gson.dir}/gson/src/main/java gson-generated
          compile_java jsonrpc-classes gson-classes \
            ${lsp4j.dir}/org.eclipse.lsp4j.jsonrpc/src/main/java
          compile_java jsonrpc-debug-classes gson-classes:jsonrpc-classes \
            ${lsp4j.dir}/org.eclipse.lsp4j.jsonrpc.debug/src/main/java
          compile_java lsp4j-debug-classes \
            gson-classes:jsonrpc-classes:jsonrpc-debug-classes lsp4j-debug
          compile_java prettier4j-classes apiguardian-classes \
            ${prettier4j.dir}/src/main/java
          compile_java jline-terminal-classes jline-native-classes \
            ${jline.dir}/terminal/src/main/java
          compile_java jline-reader-classes jline-terminal-classes \
            ${jline.dir}/reader/src/main/java
          compile_java jline-builtins-classes \
            jline-terminal-classes:jline-reader-classes:chardet-classes \
            ${jline.dir}/builtins/src/main/java
          compile_java jline-console-classes \
            jline-terminal-classes:jline-reader-classes:jline-builtins-classes \
            ${jline.dir}/console/src/main/java

          bundled="activation-classes mail-classes gson-classes jsonrpc-classes"
          bundled="$bundled jsonrpc-debug-classes lsp4j-debug-classes prettier4j-classes"
          bundled="$bundled jline-terminal-classes jline-reader-classes"
          bundled="$bundled jline-builtins-classes jline-console-classes"
          classpath=$(printf '%s\n' $bundled | paste -sd: -)

          compile_java tla-classes "$classpath" tla-src

          # Library resources: JavaMail providers and mailcap, jline terminal
          # capabilities and provider registrations, and builtins help texts.
          cp -R ${mail.dir}/mail/src/main/resources/. tla-classes/
          cp -R ${mail.dir}/smtp/src/main/resources/. tla-classes/
          cp -R ${activation.dir}/activation/src/main/resources/. tla-classes/
          # JavaMail's own manifest would shadow the tla2tools.jar manifest.
          rm tla-classes/javax/mail/Version.java tla-classes/META-INF/MANIFEST.MF
          cp -R ${jline.dir}/terminal/src/main/resources/. tla-classes/
          cp -R ${jline.dir}/builtins/src/main/resources/. tla-classes/
          cp -R ${gson.dir}/gson/src/main/resources/. tla-classes/
          for classes in $bundled; do
            cp -R "$classes"/. tla-classes/
          done

          # Retain TLA+ non-Java resources alongside their compiled classes.
          find tla-src -type f ! -name '*.java' -print | while IFS= read -r source; do
            relative=''${source#tla-src/}
            mkdir -p "tla-classes/$(dirname "$relative")"
            cp "$source" "tla-classes/$relative"
          done
        '';
      }
      {
        name = "install";
        script = ''
          licenses="$out/share/licenses/tla-plus"
          mkdir -p "$out/bin" "$out/lib" "$licenses"
          cat > tla-manifest <<MANIFEST
          Main-Class: tlc2.TLC
          Implementation-Title: TLA+ Tools
          Implementation-Version: ${version}
          Build-TimeStamp: ${releaseTimestamp}
          X-Git-Tag: v${version}
          X-Git-Revision: ${revision}
          X-Git-ShortRevision: ${builtins.substring 0 7 revision}
          MANIFEST
          jar --create --file "$out/lib/tla2tools.jar" --manifest tla-manifest \
            --date=1980-01-01T00:00:02Z -C tla-classes .

          cp ${tlaSource}/tlatools/org.lamport.tlatools/doc/License.txt "$licenses/TLA-LICENSE.txt"
          cp tla-src/org/apache/commons/math3/CommonsMath-LICENSE.txt "$licenses/"
          cp tla-src/org/apache/commons/math3/CommonsMath-NOTICE.txt "$licenses/"
          cp ${mail.dir}/LICENSE.md "$licenses/JavaMail-LICENSE.md"
          cp ${mail.dir}/NOTICE.md "$licenses/JavaMail-NOTICE.md"
          cp ${activation.dir}/LICENSE.md "$licenses/Activation-LICENSE.md"
          cp ${activation.dir}/NOTICE.md "$licenses/Activation-NOTICE.md"
          cp ${jline.dir}/LICENSE.txt "$licenses/JLine-LICENSE.txt"
          cp ${gson.dir}/LICENSE "$licenses/Gson-LICENSE"
          cp ${lsp4j.dir}/LICENSE "$licenses/LSP4J-LICENSE"
          cp ${lsp4j.dir}/NOTICE "$licenses/LSP4J-NOTICE"
          cp ${prettier4j.dir}/LICENSE "$licenses/prettier4j-LICENSE"

          for entry in 'tlc tlc2.TLC' 'sany tla2sany.SANY' \
            'pcal pcal.trans' 'tlatex tla2tex.TLA'; do
            set -- $entry
            if test "$1" = tlc; then
              java_flags=-XX:+UseParallelGC
            else
              java_flags=
            fi
            cat > "$out/bin/$1" <<WRAPPER
          #!${bash}/bin/bash
          exec ${jdk}/bin/java $java_flags -cp $out/lib/tla2tools.jar $2 "\$@"
          WRAPPER
            chmod +x "$out/bin/$1"
          done
        '';
      }
    ];

    meta = {
      description = "TLA+ tools — TLC model checker, SANY parser, PlusCal translator";
      homepage = "https://github.com/tlaplus/tlaplus";
      license = ["MIT" "EPL-2.0" "BSD-3-Clause" "Apache-2.0"];
    };
  }
