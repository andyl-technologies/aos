##! tla-plus — TLA+ tools: TLC model checker, SANY parser, PlusCal translator
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
  openjdk-17,
  bash,
}: let
  version = "1.7.4";
  jdk = openjdk-17;
  buildJdk = buildPackages.openjdk-17;
  buildGit = buildPackages.git-minimal;
  buildCaCertificates = buildPackages.ca-certificates;
  buildCoreutils = buildPackages.coreutils;

  # The upstream release archive carries compiled third-party JARs. Fetch only
  # the TLA+ sources and documentation so they never enter the build closure.
  tlaSource = fetchgit {
    url = "https://github.com/tlaplus/tlaplus.git";
    ref = "v${version}";
    rev = "5a47802b5c391f59ecdd44117981f4ff8c0656ba";
    hash = "sha256-mTvrKySvhGB8DQZOhGr6MIjRmBxfyK/GV+8ovn446iw=";
    git = buildGit;
    caCertificates = buildCaCertificates;
    coreutils = buildCoreutils;
    sparsePaths = [
      "tlatools/org.lamport.tlatools/src"
      "tlatools/org.lamport.tlatools/doc"
    ];
  };

  mailSource = fetchurl {
    urls = ["https://codeload.github.com/jakartaee/mail-api/tar.gz/refs/tags/1.6.3"];
    hash = "sha256-thWlwMj/HjUYKOri+mZDWKllP7o1EOCoYSr5+xG6lbU=";
  };

  activationSource = fetchurl {
    urls = ["https://codeload.github.com/jakartaee/jaf-api/tar.gz/refs/tags/1.2.1"];
    hash = "sha256-xZNoZNLLwob4HiEEH81iC9EDs2DbjWvaNvjeevjC/ys=";
  };
in
  mkDerivation {
    pname = "tla-plus";
    inherit version;
    src = tlaSource;

    buildDeps = [buildJdk];
    runtimeDeps = [jdk bash];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R ${tlaSource}/tlatools/org.lamport.tlatools/src tla-src
          tar xf ${mailSource}
          tar xf ${activationSource}
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME="${buildJdk}"
          export PATH="${buildJdk}/bin:$PATH"

          mkdir -p activation-classes mail-classes tla-classes

          find jaf-api-1.2.1/activation/src/main/java -name '*.java' -print > activation-sources
          javac -source 8 -target 8 -d activation-classes @activation-sources

          mkdir -p mail-generated/javax/mail
          cp mail-api-1.6.3/mail/src/main/resources/javax/mail/Version.java \
            mail-generated/javax/mail/Version.java
          sed -i 's|version = .*;|version = "1.6.3";|' mail-generated/javax/mail/Version.java

          find mail-api-1.6.3/mail/src/main/java mail-api-1.6.3/smtp/src/main/java \
            -name '*.java' ! -name module-info.java -print > mail-sources
          printf '%s\n' mail-generated/javax/mail/Version.java >> mail-sources
          javac -source 8 -target 8 -cp activation-classes -d mail-classes @mail-sources

          find tla-src -name '*.java' -print > tla-sources
          javac -source 8 -target 8 -cp activation-classes:mail-classes \
            -d tla-classes @tla-sources

          # JavaMail's service and mailcap resources are needed by MailSender.
          cp -R mail-api-1.6.3/mail/src/main/resources/. tla-classes/
          cp -R mail-api-1.6.3/smtp/src/main/resources/. tla-classes/
          cp -R jaf-api-1.2.1/activation/src/main/resources/. tla-classes/
          rm tla-classes/javax/mail/Version.java
          cp -R activation-classes/. mail-classes/. tla-classes/

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
          mkdir -p "$out/bin" "$out/lib" "$out/share/licenses/tla-plus"
          jar --create --file "$out/lib/tla2tools.jar" --no-manifest \
            --date=1980-01-01T00:00:02Z -C tla-classes .

          cp ${tlaSource}/tlatools/org.lamport.tlatools/doc/License.txt \
            "$out/share/licenses/tla-plus/TLA-LICENSE.txt"
          cp mail-api-1.6.3/LICENSE.md "$out/share/licenses/tla-plus/JavaMail-LICENSE.md"
          cp mail-api-1.6.3/NOTICE.md "$out/share/licenses/tla-plus/JavaMail-NOTICE.md"
          cp jaf-api-1.2.1/LICENSE.md "$out/share/licenses/tla-plus/Activation-LICENSE.md"
          cp jaf-api-1.2.1/NOTICE.md "$out/share/licenses/tla-plus/Activation-NOTICE.md"

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
      license = ["MIT" "EPL-2.0" "BSD-3-Clause"];
    };
  }
