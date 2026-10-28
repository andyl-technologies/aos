##! tla-community-modules — TLA+ CommunityModules with TLC Java overrides
{
  lib,
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
  openjdk-17,
  tla-plus,
  bash,
}: let
  # CommunityModules publishes date-stamped releases built against the TLA+
  # 1.8 line; this release compiles unchanged against tla-plus 1.8.0.
  version = "202610262215";
  jdk = openjdk-17;
  buildJdk = buildPackages.openjdk-17;
  buildGit = buildPackages.git-minimal;
  buildCaCertificates = buildPackages.ca-certificates;
  buildCoreutils = buildPackages.coreutils;

  # The repository checks prebuilt dependency JARs into lib/. Fetch only the
  # module sources and license so those JARs never enter the build closure.
  communitySource = fetchgit {
    url = "https://github.com/tlaplus/CommunityModules.git";
    ref = version;
    rev = "1805e9d5e1cef05d74806309fb87788e69b48f26";
    hash = "sha256-kwFCgNtRx1GyVIUEEbOL7Jhf9dOSc2ljNn2AsuXD59U=";
    git = buildGit;
    caCertificates = buildCaCertificates;
    coreutils = buildCoreutils;
    sparsePatterns = [
      "/modules/"
      "/LICENSE"
      "/README.md"
    ];
  };

  github = repository: ref: hash:
    fetchurl {
      urls = ["https://codeload.github.com/${repository}/tar.gz/refs/tags/${ref}"];
      inherit hash;
    };

  # The overrides' third-party dependencies, at the versions upstream vendors
  # as JARs in lib/. Gson comes from tla2tools.jar, which bundles it.
  commonsLang = rec {
    version = "3.12.0";
    dir = "commons-lang-rel-commons-lang-${version}";
    src = github "apache/commons-lang" "rel/commons-lang-${version}" "sha256-fDSCWdoAJlE1CZSbndfLIvutj9Y9hNo4AOWmNkZ94AU=";
  };

  commonsMath = {
    version = "3.6.1";
    dir = "commons-math-MATH_3_6_1";
    src = github "apache/commons-math" "MATH_3_6_1" "sha256-+9F0IoyoOhCJM8C1F3YgLITRxp44V4yFLnVZatzFgtg=";
  };

  # jgrapht-core's only runtime dependency.
  jheaps = rec {
    version = "0.13";
    dir = "jheaps-jheaps-${version}";
    src = github "d-michail/jheaps" "jheaps-${version}" "sha256-obcEunVhCbOWnOT+xYI7yf5RU6kpXRTiRiQWgYaCpAE=";
  };

  jgrapht = rec {
    version = "1.5.1";
    dir = "jgrapht-jgrapht-${version}";
    src = github "jgrapht/jgrapht" "jgrapht-${version}" "sha256-vHXGU1ASZeQJr6LxnbCJGI2il0g6NXWuOtV1jsqBMQU=";
  };

  # Upstream vendors a 1.4 snapshot of jungrapht-layout; use the 1.4 release.
  jungrapht = rec {
    version = "1.4";
    dir = "jungrapht-visualization-${version}";
    src = github "tomnelson/jungrapht-visualization" "v${version}" "sha256-6/WDyiuF73dffccMVa0DNmfR7Qp7/wqm6DMoVVXfVdA=";
  };

  slf4j = rec {
    version = "1.7.30";
    dir = "slf4j-v_${version}";
    src = github "qos-ch/slf4j" "v_${version}" "sha256-IXUZWI0N0fhc7iNXyjGv3XwKGoppY5U7O/RVz1F0Yz4=";
  };

  payloadGuard = ./_tla-plus/payload-guard.py;
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
    pname = "tla-community-modules";
    smokeTest = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "TLC evaluates the SequencesExt string override and checks the model without errors.";
        "files" = {
          "Qualified.tla" = "---- MODULE Qualified ----\nEXTENDS SequencesExt, Naturals\nVARIABLE x\nASSUME ReplaceAllSubSeqs(\"b\", \"a\", \"banana\") = \"bbnbnb\"\nInit == x = 0\nNext == x' = (x + 1) % 2\n====\n";
          "Qualified.cfg" = "INIT Init\nNEXT Next\n";
        };
        "input" = "A TLA+ specification whose assumption depends on the Java override of SequencesExt!ReplaceAllSubSeqs for strings.";
        "operation" = "Model check the specification with the packaged TLC launcher.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/tlc\", \"-workers\", \"1\", \"Qualified\"], capture_output=True, text=True)\nassert result.returncode == 0, result.stdout\nassert \"No error has been found\" in result.stdout\nprint(\"tla-community-modules operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "tla-community-modules operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "TLC reports the false assumption and returns failure.";
        "files" = {
          "Invalid.tla" = "---- MODULE Invalid ----\nEXTENDS SequencesExt, Naturals\nVARIABLE x\nASSUME ReplaceAllSubSeqs(\"b\", \"a\", \"banana\") = \"banana\"\nInit == x = 0\nNext == UNCHANGED x\n====\n";
          "Invalid.cfg" = "INIT Init\nNEXT Next\n";
        };
        "input" = "A TLA+ specification with an assumption that the string replacement contradicts.";
        "operation" = "Model check the specification with the packaged TLC launcher.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/tlc\", \"-workers\", \"1\", \"Invalid\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"Assumption line 4\" in result.stdout and \"is false\" in result.stdout\n\nsys.stderr.write(\"tla-community-modules rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "tla-community-modules rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;
    src = communitySource;

    buildDeps = [buildJdk buildPackages.python3];
    runtimeDeps = [jdk bash tla-plus];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R ${communitySource}/modules community-modules

          # Extract only the module sources that are compiled; the archives
          # also carry build wrappers and test fixtures.
          tar xf ${commonsLang.src} ${commonsLang.dir}/src/main/java \
            ${commonsLang.dir}/LICENSE.txt ${commonsLang.dir}/NOTICE.txt
          tar xf ${commonsMath.src} ${commonsMath.dir}/src/main/java \
            ${commonsMath.dir}/src/main/resources \
            ${commonsMath.dir}/LICENSE.txt ${commonsMath.dir}/NOTICE.txt
          tar xf ${jheaps.src} ${jheaps.dir}/src/main/java ${jheaps.dir}/LICENSE
          tar xf ${jgrapht.src} ${jgrapht.dir}/jgrapht-core/src/main/java \
            ${jgrapht.dir}/license-EPL.txt ${jgrapht.dir}/license-LGPL.txt
          tar xf ${jungrapht.src} ${jungrapht.dir}/jungrapht-layout/src/main/java \
            ${jungrapht.dir}/LICENSE
          tar xf ${slf4j.src} ${slf4j.dir}/slf4j-api/src/main/java \
            ${slf4j.dir}/slf4j-nop/src/main/java ${slf4j.dir}/LICENSE.txt

          python3 ${payloadGuard} CommunityModules community-modules \
            ${commonsLang.dir} ${commonsMath.dir} ${jheaps.dir} ${jgrapht.dir} \
            ${jungrapht.dir} ${slf4j.dir}
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME="${buildJdk}"
          export PATH="${buildJdk}/bin:$PATH"

          # Compile every Java file below the given source roots into one
          # class directory. Module descriptors are skipped because the
          # libraries are bundled onto a single classpath. jgrapht's
          # SørensenIndexLinkPrediction is skipped: its non-ASCII file name
          # breaks JAR tooling, and upstream omits it from its bundled JAR
          # for that reason (jgrapht issue 1112).
          compile_java() {
            output=$1
            classpath=$2
            shift 2
            mkdir -p "$output"
            find "$@" -name '*.java' ! -name module-info.java \
              ! -name '*rensenIndexLinkPrediction.java' -print > "$output.sources"
            javac --release 11 -encoding UTF-8 -nowarn -cp "$classpath" \
              -d "$output" @"$output.sources"
          }

          compile_java commons-lang-classes "" ${commonsLang.dir}/src/main/java
          compile_java commons-math-classes "" ${commonsMath.dir}/src/main/java
          compile_java jheaps-classes "" ${jheaps.dir}/src/main/java
          compile_java jgrapht-classes jheaps-classes ${jgrapht.dir}/jgrapht-core/src/main/java

          # slf4j-api compiles against placeholder org.slf4j.impl binders that
          # its release build deletes; slf4j-nop provides the real ones.
          compile_java slf4j-api-classes "" ${slf4j.dir}/slf4j-api/src/main/java
          rm -r slf4j-api-classes/org/slf4j/impl
          compile_java slf4j-nop-classes slf4j-api-classes ${slf4j.dir}/slf4j-nop/src/main/java

          compile_java jungrapht-classes jgrapht-classes:jheaps-classes:slf4j-api-classes \
            ${jungrapht.dir}/jungrapht-layout/src/main/java

          bundled="commons-lang-classes commons-math-classes jheaps-classes"
          bundled="$bundled jgrapht-classes jungrapht-classes slf4j-api-classes slf4j-nop-classes"
          classpath=$(printf '%s\n' ${tla-plus}/lib/tla2tools.jar $bundled | paste -sd: -)
          compile_java community-classes "$classpath" community-modules

          # Bundle the dependencies so the JAR alone enables every override.
          # TLC resolves the module definitions from the classpath root.
          for classes in $bundled; do
            cp -R "$classes"/. community-classes/
          done
          cp -R ${commonsMath.dir}/src/main/resources/. community-classes/
          cp community-modules/*.tla community-classes/
          cp ${communitySource}/LICENSE ${communitySource}/README.md community-classes/
        '';
      }
      {
        name = "install";
        script = ''
          licenses="$out/share/licenses/tla-community-modules"
          mkdir -p "$out/bin" "$out/lib" "$licenses"

          jar --create --file "$out/lib/CommunityModules.jar" --no-manifest \
            --date=1980-01-01T00:00:02Z -C community-classes .

          cp ${communitySource}/LICENSE "$licenses/CommunityModules-LICENSE"
          cp ${commonsLang.dir}/LICENSE.txt "$licenses/commons-lang-LICENSE.txt"
          cp ${commonsLang.dir}/NOTICE.txt "$licenses/commons-lang-NOTICE.txt"
          cp ${commonsMath.dir}/LICENSE.txt "$licenses/commons-math-LICENSE.txt"
          cp ${commonsMath.dir}/NOTICE.txt "$licenses/commons-math-NOTICE.txt"
          cp ${jheaps.dir}/LICENSE "$licenses/jheaps-LICENSE"
          cp ${jgrapht.dir}/license-EPL.txt "$licenses/jgrapht-license-EPL.txt"
          cp ${jgrapht.dir}/license-LGPL.txt "$licenses/jgrapht-license-LGPL.txt"
          cp ${jungrapht.dir}/LICENSE "$licenses/jungrapht-LICENSE"
          cp ${slf4j.dir}/LICENSE.txt "$licenses/slf4j-LICENSE.txt"

          # TLC loads tlc2.overrides.TLCOverrides and module files from its
          # classpath, so the launchers only need to append this JAR.
          classpath="${tla-plus}/lib/tla2tools.jar:$out/lib/CommunityModules.jar"
          for entry in 'tlc tlc2.TLC' 'sany tla2sany.SANY'; do
            set -- $entry
            if test "$1" = tlc; then
              java_flags=-XX:+UseParallelGC
            else
              java_flags=
            fi
            cat > "$out/bin/$1" <<WRAPPER
          #!${bash}/bin/bash
          exec ${jdk}/bin/java $java_flags -cp $classpath $2 "\$@"
          WRAPPER
            chmod +x "$out/bin/$1"
          done
        '';
      }
    ];

    checks = {
      self,
      pkgs,
      ...
    }: {
      trace-validation = pkgs.mkDerivation {
        pname = "tla-community-modules-trace-validation";
        version = "1";
        src = null;
        buildDeps = [self];
        phases = [
          {
            name = "check";
            script = ''
              export HOME="$PWD/home"
              mkdir -p "$HOME" "$out"
              fixtures=${./_tla-community-modules-tests}

              # Trace.tla reads the log named by TRACE_FILE through IOEnv.
              # TLC exits with 0 only when the logged events form a behavior
              # of the specification and the trace is consumed completely.
              mkdir valid
              cp "$fixtures"/Counter.tla "$fixtures"/Trace.tla "$fixtures"/Trace.cfg valid/
              cp "$fixtures"/valid.ndjson valid/
              (cd valid && TRACE_FILE=valid.ndjson \
                ${self}/bin/tlc -workers 1 -deadlock -noGenerateSpecTE -cleanup Trace) \
                > "$out/valid.log" 2>&1 || {
                cat "$out/valid.log"
                echo "TLC rejected the valid trace" >&2
                exit 1
              }
              grep -q 'Model checking completed. No error has been found.' "$out/valid.log"

              # The invalid trace skips a counter value, so TLC must report
              # that the end of the trace is unreachable (liveness, exit 13).
              mkdir invalid
              cp "$fixtures"/Counter.tla "$fixtures"/Trace.tla "$fixtures"/Trace.cfg invalid/
              cp "$fixtures"/invalid.ndjson invalid/
              status=0
              (cd invalid && TRACE_FILE=invalid.ndjson \
                ${self}/bin/tlc -workers 1 -deadlock -noGenerateSpecTE -cleanup Trace) \
                > "$out/invalid.log" 2>&1 || status=$?
              if test "$status" -ne 13 ||
                ! grep -q 'Temporal property TraceConsumed was violated' "$out/invalid.log"; then
                cat "$out/invalid.log"
                echo "TLC did not reject the invalid trace (exit $status)" >&2
                exit 1
              fi
            '';
          }
        ];
      };
    };

    meta = {
      description = "TLA+ CommunityModules — reusable TLA+ modules with TLC Java overrides";
      homepage = "https://github.com/tlaplus/CommunityModules";
      license = ["MIT" "Apache-2.0" "EPL-2.0" "LGPL-2.1-or-later" "BSD-3-Clause"];
    };
  }
