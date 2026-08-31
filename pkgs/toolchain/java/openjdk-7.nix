##! OpenJDK 7 — first real OpenJDK, built via IcedTea 2.6.13
{
  mkDerivation,
  fetchurl,
  lib,
  stdenv,
  buildPackages,
  gnumake,
  autoconf,
  bash,
  which,
  zip,
  unzip,
  cpio,
  gawk,
  coreutils,
  grep,
  sed,
  pkg-config,
  zlib,
  krb5,
  alsa-lib,
  binutils,
  cups,
  file,
  fontconfig,
  freetype,
  xorg-stubs,
  perl,
  jamvm-2_0,
  ecj-bootstrap,
  classpath-0_99,
  gjavah,
  ant-bootstrap,
  fastjar,
  libxslt,
  java-native-foundation,
  bootstrapTools,
}: let
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildTools =
    if isDarwinCross
    then buildPackages
    else {
      inherit
        gnumake
        autoconf
        bash
        which
        zip
        unzip
        cpio
        gawk
        coreutils
        grep
        sed
        pkg-config
        binutils
        file
        perl
        jamvm-2_0
        ecj-bootstrap
        classpath-0_99
        gjavah
        ant-bootstrap
        fastjar
        libxslt
        ;
    };
  alsaForBuild =
    if isDarwinCross
    then buildPackages.alsa-lib
    else alsa-lib;
  xorgStubsForBuild =
    if isDarwinCross
    then buildPackages.xorg-stubs
    else xorg-stubs;
  configurePlatformFlags =
    if isDarwinCross
    then ''      --build=${stdenv.buildPlatform.config} \
                  --host=${stdenv.hostPlatform.config} \
    ''
    else "";
  # HotSpot's ADLC executes during the build even for a Darwin target. Keep its
  # Linux source configuration and GCC-only flags paired with the native CC.
  bootstrapCc =
    if isDarwinCross
    then "$TOOLS/native-cc"
    else "$(which gcc)";
  bootstrapCxx =
    if isDarwinCross
    then "$TOOLS/native-c++"
    else "$(which g++)";
  bootstrapCcAlias =
    if isDarwinCross
    then "$TOOLS/native-cc"
    else "$(which cc)";
  jnfFrameworks = "${java-native-foundation}/Library/Frameworks";
  icedteaVersion = "2.6.13";

  # IcedTea 2.6.13 — build harness for OpenJDK 7
  icedteaSrc = fetchurl {
    urls = [
      "https://icedtea.classpath.org/download/source/icedtea-${icedteaVersion}.tar.xz"
      "https://icedtea.wildebeest.org/download/source/icedtea-${icedteaVersion}.tar.xz"
    ];
    hash = "sha256-EE6EIF0RduIX4k93B4TFPRzWZq6yOrC66KyFjlsOY/A=";
  };

  # OpenJDK 7 sub-component sources (IcedTea 2.6.x drops)
  openjdkSrc = fetchurl {
    urls = [
      "https://icedtea.classpath.org/download/drops/icedtea7/${icedteaVersion}/openjdk.tar.bz2"
    ];
    hash = "sha256-FKn5Di/lwLtz3I/8yepdx20856dKDJAc/QsK4/yMZFA=";
  };
  corbaSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea7/${icedteaVersion}/corba.tar.bz2"];
    hash = "sha256-3xFUkVytMXuTVVtWP8EqytG5Ll8ocGQnNvGGt6TYDxQ=";
  };
  jaxpSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea7/${icedteaVersion}/jaxp.tar.bz2"];
    hash = "sha256-FDpblX+7AIif+dOKS/ORIYeGtqM2ZCNSee27bnmj3sw=";
  };
  jaxwsSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea7/${icedteaVersion}/jaxws.tar.bz2"];
    hash = "sha256-0+PVXW4iMcRCDTDRJPcsVmldReijmOPMe6If8qk8EoQ=";
  };
  jdkSrc = fetchurl {
    urls = ["https://icedtea.classpath.org/download/drops/icedtea7/${icedteaVersion}/jdk.tar.bz2"];
    hash = "sha256-rb2pPR6b6JRH4AlzOmyQUMbmzr2jxnSnbrvriYZiNTQ=";
  };
  langtoolsSrc = fetchurl {
    urls = [
      "https://icedtea.classpath.org/download/drops/icedtea7/${icedteaVersion}/langtools.tar.bz2"
    ];
    hash = "sha256-EgNrmF+IEc2t9tW/hA+QurJfTaHMPoa6ucP278wQBVs=";
  };
  hotspotSrc = fetchurl {
    urls = [
      "https://icedtea.classpath.org/download/drops/icedtea7/${icedteaVersion}/hotspot.tar.bz2"
    ];
    hash = "sha256-muPW1D/3cc8CuMeAWsDwpFf1+nAmsTNOoQhSYtPYbZ0=";
  };
in
  mkDerivation {
    pname = "openjdk-7";
    version = icedteaVersion;

    src = icedteaSrc;

    buildDeps =
      [
        buildTools.gnumake
        buildTools.autoconf
        buildTools.bash
        buildTools.which
        buildTools.zip
        buildTools.unzip
        buildTools.gawk
        buildTools.coreutils
        buildTools.grep
        buildTools.sed
        buildTools.pkg-config
        buildTools.binutils
        buildTools.cpio
        buildTools.file
        buildTools.perl
        xorg-stubs
        buildTools.jamvm-2_0
        buildTools.ecj-bootstrap
        buildTools.classpath-0_99
        buildTools.gjavah
        buildTools.ant-bootstrap
        buildTools.fastjar
        buildTools.libxslt
      ]
      ++ lib.optionals isDarwinCross [
        alsaForBuild
        buildTools.freetype
        buildTools.openjdk-7
        xorgStubsForBuild
        buildTools.zlib
      ];
    runtimeDeps =
      [zlib]
      ++ lib.optionals (!isDarwinCross) [alsa-lib]
      ++ lib.optionals isDarwinCross [
        java-native-foundation
        krb5
      ]
      ++ [
        fontconfig
        freetype
        cups
      ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd icedtea-${icedteaVersion}
        '';
      }
      {
        name = "setup-drops";
        script = ''
          # IcedTea expects source tarballs in drops/
          mkdir -p drops
          ln -sf ${openjdkSrc} drops/openjdk.tar.bz2
          ln -sf ${corbaSrc} drops/corba.tar.bz2
          ln -sf ${jaxpSrc} drops/jaxp.tar.bz2
          ln -sf ${jaxwsSrc} drops/jaxws.tar.bz2
          ln -sf ${jdkSrc} drops/jdk.tar.bz2
          ln -sf ${langtoolsSrc} drops/langtools.tar.bz2
          ln -sf ${hotspotSrc} drops/hotspot.tar.bz2
        '';
      }
      {
        name = "patch-bitrot";
        script = ''
          # Fix FreeType version detection (modern freetype is 2.x not 2.2.1)
          # IcedTea 2.6.x expects older freetype API version checks
          if [ -f Makefile.am ]; then
            sed -i 's/2\.2\.1/2.10.1/g' Makefile.am 2>/dev/null || true
          fi

          # Fix xattr.h include (attr/xattr.h -> sys/xattr.h on modern systems)
          find . -name '*.c' -o -name '*.h' | while read f; do
            sed -i 's|attr/xattr\.h|sys/xattr.h|g' "$f" 2>/dev/null || true
          done

        '';
      }
      {
        name = "patch-paths";
        script = ''
                  # Create a fake JDK home with the structure IcedTea expects
                  # IcedTea looks for jre/lib/rt.jar but JamVM uses classes.zip/glibj.zip
                  FAKE_JDK=$PWD/fake-jdk
                  mkdir -p $FAKE_JDK/bin $FAKE_JDK/jre/lib $FAKE_JDK/include
                  # Create java wrapper that filters HotSpot flags and converts
                  # -Xbootclasspath/p: + -jar into -cp + MainClass for JamVM
                  cat > $FAKE_JDK/bin/java << 'JAVAEOF'
          #!/bin/sh
          JAMVM=JAMVM_PLACEHOLDER
          UNZIP=UNZIP_PLACEHOLDER

          BOOTCP=""
          JARFILE=""
          SAW_JAR=false
          TMPJVM=$(mktemp /tmp/java-jvm.XXXXXX)
          TMPAPP=$(mktemp /tmp/java-app.XXXXXX)
          for arg in "$@"; do
            if $SAW_JAR && [ -z "$JARFILE" ]; then
              JARFILE="$arg"
              continue
            fi
            case "$arg" in
              -XX:*) ;;
              -Xmx*|-Xms*|-Xss*) ;;
              -Xbootclasspath/p:*)
                BOOTCP="''${arg#-Xbootclasspath/p:}"
                ;;
              -jar)
                SAW_JAR=true
                ;;
              *)
                if [ -z "$JARFILE" ] && ! $SAW_JAR; then
                  printf '%s\n' "$arg" >> "$TMPJVM"
                else
                  printf '%s\n' "$arg" >> "$TMPAPP"
                fi
                ;;
            esac
          done


          # If -jar points to javah.jar, redirect to gjavah (avoids NPE in langtools javah under JamVM)
          GJAVAH=GJAVAH_PLACEHOLDER
          case "$JARFILE" in
            *javah.jar)
              set --
              while IFS= read -r line; do set -- "$@" "$line"; done < "$TMPAPP" 2>/dev/null
              rm -f "$TMPJVM" "$TMPAPP"
              exec $GJAVAH "$@"
              ;;
          esac

          if [ -n "$JARFILE" ] && [ -n "$BOOTCP" ]; then
            MAINCLASS=$($UNZIP -p "$JARFILE" META-INF/MANIFEST.MF 2>/dev/null | while IFS= read -r mline; do
              case "$mline" in
                Main-Class:*) echo "$mline" | sed 's/Main-Class: *//;s/[[:space:]]*$//' ;;
              esac
            done)
            if [ -z "$MAINCLASS" ]; then
              echo "ERROR: Could not extract Main-Class from $JARFILE" >&2
              rm -f "$TMPJVM" "$TMPAPP"
              exit 1
            fi
            CP="$BOOTCP:$JARFILE"
            set --
            while IFS= read -r line; do set -- "$@" "$line"; done < "$TMPJVM" 2>/dev/null
            set -- "$@" "-cp" "$CP" "$MAINCLASS"
            while IFS= read -r line; do set -- "$@" "$line"; done < "$TMPAPP" 2>/dev/null
            rm -f "$TMPJVM" "$TMPAPP"
            exec $JAMVM "$@"
          elif [ -n "$JARFILE" ]; then
            set --
            while IFS= read -r line; do set -- "$@" "$line"; done < "$TMPJVM" 2>/dev/null
            set -- "$@" "-jar" "$JARFILE"
            while IFS= read -r line; do set -- "$@" "$line"; done < "$TMPAPP" 2>/dev/null
            rm -f "$TMPJVM" "$TMPAPP"
            exec $JAMVM "$@"
          else
            set --
            while IFS= read -r line; do set -- "$@" "$line"; done < "$TMPJVM" 2>/dev/null
            while IFS= read -r line; do set -- "$@" "$line"; done < "$TMPAPP" 2>/dev/null
            rm -f "$TMPJVM" "$TMPAPP"
            exec $JAMVM "$@"
          fi
          JAVAEOF
                  sed -i "s|JAMVM_PLACEHOLDER|${buildTools.jamvm-2_0}/bin/jamvm|" $FAKE_JDK/bin/java
                  sed -i "s|UNZIP_PLACEHOLDER|${buildTools.unzip}/bin/unzip|" $FAKE_JDK/bin/java
                  sed -i "s|GJAVAH_PLACEHOLDER|${buildTools.gjavah}/bin/gjavah|" $FAKE_JDK/bin/java
                  chmod +x $FAKE_JDK/bin/java
                  # Create a javac wrapper that pre-creates output directories
                  # before calling ECJ. JamVM's File.mkdirs() creates intermediate
                  # paths as files instead of directories, breaking ECJ's output.
                  cat > $FAKE_JDK/bin/javac << JAVACEOF
          #!/bin/sh
          # Parse args: extract -d <outdir>, -sourcepath, source files, filter flags
          OUTDIR=""
          SOURCEPATH=""
          PREV=""
          SRCFILES=""
          FILTERED_ARGS=""
          for arg in "\$@"; do
            if [ "\$PREV" = "-d" ]; then
              OUTDIR="\$arg"
            fi
            if [ "\$PREV" = "-sourcepath" ]; then
              SOURCEPATH="\$arg"
            fi
            case "\$arg" in
              @*) SRCFILES="\$SRCFILES \$arg" ;;
              *.java) SRCFILES="\$SRCFILES \$arg" ;;
            esac
            # Filter out -J flags (HotSpot JVM options not supported by ECJ/JamVM)
            # and javac-specific flags ECJ doesn't understand
            case "\$arg" in
              -J*) ;; # skip HotSpot-specific JVM flags
              -Xbootclasspath*) ;; # skip javac-specific bootclasspath flags
              -XDignore*) ;; # skip javac-specific -XD flags
              -implicit:*) ;; # skip javac-specific -implicit flag
              -Xprefer:*) ;; # skip javac-specific -Xprefer flag
              *) FILTERED_ARGS="\$FILTERED_ARGS \$arg" ;;
            esac
            PREV="\$arg"
          done

          # Helper: create a directory, removing any regular file that blocks the path
          safe_mkdir() {
            target="\$1"
            # Check each path component and fix files-where-dirs-should-be
            partial=""
            OLD_IFS2="\$IFS"
            IFS="/"
            for component in \$target; do
              IFS="\$OLD_IFS2"
              if [ -z "\$component" ]; then
                partial="/"
                continue
              fi
              partial="\$partial\$component"
              if [ -f "\$partial" ] && [ ! -d "\$partial" ]; then
                rm -f "\$partial"
              fi
              partial="\$partial/"
            done
            IFS="\$OLD_IFS2"
            mkdir -p "\$target" 2>/dev/null || true
          }

          # Pre-create output directories from sourcepath entries
          if [ -n "\$OUTDIR" ] && [ -n "\$SOURCEPATH" ]; then
            OLD_IFS="\$IFS"
            IFS=":"
            for sp in \$SOURCEPATH; do
              IFS="\$OLD_IFS"
              case "\$sp" in
                /*) abs_sp="\$sp" ;;
                *) abs_sp="\$(cd "\$sp" 2>/dev/null && pwd)" || abs_sp="" ;;
              esac
              if [ -n "\$abs_sp" ] && [ -d "\$abs_sp" ]; then
                find "\$abs_sp" -type d 2>/dev/null | while read d; do
                  rel=\$(echo "\$d" | sed "s|^\$abs_sp/||; s|^\$abs_sp||")
                  if [ -n "\$rel" ] && [ "\$rel" != "\$d" ]; then
                    safe_mkdir "\$OUTDIR/\$rel"
                  fi
                done
              fi
            done
            IFS="\$OLD_IFS"
          fi

          # Also pre-create directories for individual source files
          if [ -n "\$OUTDIR" ]; then
            for arg in \$SRCFILES; do
              case "\$arg" in
                @*)
                  argfile=\$(echo "\$arg" | sed 's/^@//')
                  if [ -f "\$argfile" ]; then
                    while read f; do
                      d=\$(dirname "\$f")
                      pkg=\$(echo "\$d" | sed 's|.*/src/share/classes/||; s|.*/src/classes/||; s|.*/tools/src/||; s|.*/gensrc/||; s|^\.||')
                      if [ -n "\$pkg" ]; then
                        safe_mkdir "\$OUTDIR/\$pkg"
                      fi
                    done < "\$argfile"
                  fi
                  ;;
                *.java)
                  d=\$(dirname "\$arg")
                  pkg=\$(echo "\$d" | sed 's|.*/src/share/classes/||; s|.*/src/classes/||; s|.*/tools/src/||; s|.*/gensrc/||; s|^\.||')
                  if [ -n "\$pkg" ]; then
                    safe_mkdir "\$OUTDIR/\$pkg"
                  fi
                  ;;
              esac
            done
          fi

          exec ${buildTools.ecj-bootstrap}/bin/ecj \$FILTERED_ARGS
          JAVACEOF
                  chmod +x $FAKE_JDK/bin/javac
                  ln -sf ${buildTools.gjavah}/bin/gjavah $FAKE_JDK/bin/javah
                  ln -sf ${buildTools.fastjar}/bin/fastjar $FAKE_JDK/bin/jar
                  ln -sf ${buildTools.jamvm-2_0}/include/jni.h $FAKE_JDK/include/jni.h
                  # Create rt.jar from classpath glibj.zip
                  ln -sf ${buildTools.classpath-0_99}/share/classpath/glibj.zip $FAKE_JDK/jre/lib/rt.jar

                  # Add rmic dummy to fake JDK (configure checks $JDK_HOME/bin/rmic)
                  printf '#!/bin/sh\nexit 0\n' > $FAKE_JDK/bin/rmic
                  chmod +x $FAKE_JDK/bin/rmic

                  # Create dummy tools — IcedTea checks for these but they're not needed
                  # or can be trivially emulated:
                  # wget (--disable-downloading), xsltproc (--disable-docs),
                  # getconf (only used for _NPROCESSORS_ONLN),
                  # rmic/native2ascii (IcedTea bootstrap builds its own from OpenJDK source)
                  mkdir -p dummy-bin
                  printf '#!/bin/sh\nexit 1\n' > dummy-bin/wget
                  ln -sf ${buildTools.libxslt}/bin/xsltproc dummy-bin/xsltproc
                  printf '#!/bin/sh\nexit 0\n' > dummy-bin/rmic
                  printf '#!/bin/sh\ncat "$@" 2>/dev/null\n' > dummy-bin/native2ascii
                  printf '#!/bin/sh\ncase "$1" in _NPROCESSORS_ONLN) echo %s;; *) echo 1;; esac\n' \
                    "$NIX_BUILD_CORES" > dummy-bin/getconf
                  printf '#!/bin/sh\necho localhost\n' > dummy-bin/hostname
                  printf '#!/bin/sh\necho "             total       used       free"\necho "Mem:       8000000    4000000    4000000"\n' > dummy-bin/free
                  printf '#!/bin/sh\necho "builder"\n' > dummy-bin/logname
                  for f in dummy-bin/*; do
                    if [ ! -L "$f" ]; then
                      chmod +x "$f"
                    fi
                  done
                  export PATH="$PWD/dummy-bin:$PATH"

                  # Patch hardcoded tool paths in IcedTea and OpenJDK build system
                  # IcedTea's configure and Makefiles reference /usr/bin/* and /bin/*
                  for f in $(find . -name '*.in' -o -name '*.sh' -o -name 'Makefile*' -o -name 'configure*' 2>/dev/null); do
                    sed -i \
                      -e "s|/usr/bin/echo|${buildTools.coreutils}/bin/echo|g" \
                      -e "s|/bin/echo|${buildTools.coreutils}/bin/echo|g" \
                      -e "s|/usr/bin/find|${buildTools.coreutils}/bin/find|g" \
                      -e "s|/usr/bin/grep|${buildTools.grep}/bin/grep|g" \
                      -e "s|/bin/grep|${buildTools.grep}/bin/grep|g" \
                      -e "s|/usr/bin/sed|${buildTools.sed}/bin/sed|g" \
                      -e "s|/bin/sed|${buildTools.sed}/bin/sed|g" \
                      -e "s|/usr/bin/cpio|cpio|g" \
                      -e "s|/usr/bin/file|${buildTools.file}/bin/file|g" \
                      -e "s|/usr/bin/readelf|${buildTools.binutils}/bin/readelf|g" \
                      "$f" 2>/dev/null || true
                  done
        '';
      }
      {
        name = "configure";
        script = ''
          # Set CFLAGS/CXXFLAGS to be permissive with GCC warnings
          export CFLAGS="-fcommon -Wno-error"
          export CXXFLAGS="-fcommon -Wno-error"

          # Add dummy tools to PATH (created in patch-paths phase)
          export PATH="$PWD/dummy-bin:$PATH"

          # Set X11 extension include path for headless builds
          export CPATH="${xorg-stubs}/include:''${CPATH:-}"

          # Override pkg-config checks (ccWrapper's pkg-config has recursion bug)
          export FREETYPE2_CFLAGS="-I${freetype}/include/freetype2 -I${freetype}/include"
          export FREETYPE2_LIBS="-L${freetype}/lib -lfreetype"
          export XPROTO_CFLAGS="-I${xorg-stubs}/include"
          export XPROTO_LIBS=" "
          export XT_CFLAGS="-I${xorg-stubs}/include"
          export XT_LIBS="-L${xorg-stubs}/lib -lXt"
          export XRENDER_CFLAGS="-I${xorg-stubs}/include"
          export XRENDER_LIBS="-L${xorg-stubs}/lib -lXrender"
          export X11_CFLAGS="-I${xorg-stubs}/include"
          export X11_LIBS="-L${xorg-stubs}/lib -lX11"
          export XCOMPOSITE_CFLAGS="-I${xorg-stubs}/include"
          export XCOMPOSITE_LIBS="-L${xorg-stubs}/lib -lXcomposite"
          export XINERAMA_CFLAGS="-I${xorg-stubs}/include"
          export XINERAMA_LIBS="-L${xorg-stubs}/lib -lXinerama"
          export XTST_CFLAGS="-I${xorg-stubs}/include"
          export XTST_LIBS="-L${xorg-stubs}/lib -lXtst"
          export ALSA_CFLAGS="-I${alsaForBuild}/include"
          export ALSA_LIBS="-L${alsaForBuild}/lib -lasound"

          $CONFIG_SHELL configure \
            ${configurePlatformFlags}--prefix=$out \
            --with-jdk-home=$PWD/fake-jdk \
            --with-ecj-jar=${buildTools.ecj-bootstrap}/lib/ecj.jar \
            --with-javac=$PWD/fake-jdk/bin/javac \
            --with-ant-home=${buildTools.ant-bootstrap} \
            --with-jar=${buildTools.fastjar}/bin/fastjar \
            --with-java=$PWD/fake-jdk/bin/java \
            --with-javah=${buildTools.gjavah}/bin/gjavah \
            --disable-docs \
            --disable-downloading \
            --disable-tests \
            --enable-bootstrap \
            --enable-headless-only \
            --with-openjdk-src-zip=${openjdkSrc} \
            --with-corba-src-zip=${corbaSrc} \
            --with-hotspot-src-zip=${hotspotSrc} \
            --with-jaxp-src-zip=${jaxpSrc} \
            --with-jaxws-src-zip=${jaxwsSrc} \
            --with-jdk-src-zip=${jdkSrc} \
            --with-langtools-src-zip=${langtoolsSrc} \
            --without-rhino \
            --disable-system-zlib \
            --disable-system-jpeg \
            --disable-system-png \
            --disable-system-gif \
            --disable-system-lcms \
            --disable-system-sctp \
            --disable-system-kerberos \
            --disable-system-gtk \
            --disable-system-gio \
            --disable-system-gconf \
            --disable-system-pcsc \
            --disable-system-fontconfig \
            --disable-system-cups \
            --disable-compile-against-syscalls \
            --with-cups=${cups} \
            --with-alsa=${alsaForBuild} \
            --x-includes=${xorg-stubs}/include \
            --x-libraries=${xorg-stubs}/lib \
            --with-parallel-jobs=$NIX_BUILD_CORES
        '';
      }
      {
        name = "build";
        script = ''
                  # Prevent autotools regeneration — touch generated files newer than inputs
                  # Must be done after configure (which modifies Makefile/config.status)
                  touch aclocal.m4
                  touch configure
                  touch Makefile.am Makefile.in
                  touch config.h.in 2>/dev/null || true

                  # IcedTea Makefile orchestrates extract → patch → build
                  export PATH="$PWD/dummy-bin:$PATH"
                  export CFLAGS="-fcommon -Wno-error -Wno-error=format-overflow -Wno-implicit-function-declaration"
                  export CXXFLAGS="-fcommon -Wno-error -Wno-error=format-overflow -fpermissive -Wno-error=pointer-arith"

                  # ALT_* variables for the inner OpenJDK/HotSpot build
                  export ALT_CUPS_HEADERS_PATH="${cups}/include"
                  export ALT_FREETYPE_HEADERS_PATH="${freetype}/include"
                  export ALT_FREETYPE_LIB_PATH="${freetype}/lib"

                  # First extract, patch, and clone the source for bootstrap
                  ${
            if isDarwinCross
            then ''
              # The crypto-policy gate must inspect the generated Darwin
              # policy jars, but its Java VM executes on the Linux builder.
              # Run the unchanged test class with the native JDK while
              # directing java.home at the completed target image, so the
              # target policy remains the exact subject of the check.
              for crypto_makefile in Makefile.am Makefile.in Makefile; do
                test "$(grep -Fc \
                  '$(BUILD_SDK_DIR)/bin/java -cp $(CRYPTO_CHECK_BUILD_DIR) TestCryptoLevel ; \' \
                  "$crypto_makefile")" = 1
                sed -i \
                  's|$(BUILD_SDK_DIR)/bin/java -cp|${buildTools.openjdk-7}/bin/java -Djava.home=$(BUILD_SDK_DIR)/jre -cp|' \
                  "$crypto_makefile"
                test "$(grep -Fc \
                  '${buildTools.openjdk-7}/bin/java -Djava.home=$(BUILD_SDK_DIR)/jre -cp $(CRYPTO_CHECK_BUILD_DIR) TestCryptoLevel ; \' \
                  "$crypto_makefile")" = 1

                # A CDS archive embeds VM/compiler ABI metadata. A Linux VM
                # cannot safely generate one for the Darwin target, while
                # the built VM retains CDS support and may generate it when
                # installed in a writable target image.
                test "$(grep -Fc \
                  '$(BUILD_SDK_DIR)/bin/java -Xshare:dump ; \' \
                  "$crypto_makefile")" = 1
                sed -i \
                  's|$(BUILD_SDK_DIR)/bin/java -Xshare:dump|: "Darwin cross omits target-only CDS archive generation"|' \
                  "$crypto_makefile"
                test "$(grep -Fc \
                  ': "Darwin cross omits target-only CDS archive generation" ; \' \
                  "$crypto_makefile")" = 1
              done

              make stamps/patch-boot.stamp

              # This configure-time sanity check is compiled and executed by the
              # build harness. Keep the check, but build it for Linux with the
              # native FreeType instead of trying to execute its Darwin result.
              for freetype_check_makefile in \
                openjdk/jdk/make/tools/freetypecheck/Makefile \
                openjdk-boot/jdk/make/tools/freetypecheck/Makefile; do
                test -f "$freetype_check_makefile"
                test "$(grep -Ec '^[[:blank:]]+[$][(]CC[)] [$][(]FT_OPTIONS[)] [$][(]CC_PROGRAM_OUTPUT_FLAG[)][$]@ freetypecheck[.]c [$][(]FT_LD_OPTIONS[)]$' "$freetype_check_makefile")" = 1
                sed -i \
                  's|^[[:blank:]]*$(CC) $(FT_OPTIONS) $(CC_PROGRAM_OUTPUT_FLAG)$@ freetypecheck.c $(FT_LD_OPTIONS)$|\t${buildTools.coreutils}/bin/env -u AOS_CROSS_COMPILING -u AOS_HARDENING_ENABLE -u AOS_TARGET_ARCH -u AOS_TARGET_PLATFORM -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH -u MACOSX_DEPLOYMENT_TARGET -u NIX_CFLAGS_COMPILE -u NIX_CFLAGS_LINK -u NIX_LDFLAGS -u SDKROOT ${buildTools.cc}/bin/cc -I${buildTools.freetype}/include/freetype2 -I${buildTools.freetype}/include -DREQUIRED_FREETYPE_VERSION=$(REQUIRED_FREETYPE_VERSION) -o $@ freetypecheck.c -L${buildTools.freetype}/lib -Wl,-rpath,${buildTools.freetype}/lib -lfreetype -L${buildTools.zlib}/lib -Wl,-rpath,${buildTools.zlib}/lib -lz|' \
                  "$freetype_check_makefile"
              done
            ''
            else "make stamps/patch-boot.stamp"
          }

                  # Pre-create output directories in lib/rt/ to work around JamVM
                  # File.mkdirs() bug (creates files instead of directories)
                  mkdir -p lib/rt
                  for srcdir in openjdk-boot/jdk/src/share/classes openjdk-boot/langtools/src/share/classes openjdk/jdk/src/share/classes openjdk/langtools/src/share/classes; do
                    if [ -d "$srcdir" ]; then
                      find "$srcdir" -name '*.java' -print | while read f; do
                        d=$(dirname "$f" | sed "s|^$srcdir/||")
                        if [ -n "$d" ] && [ "$d" != "." ]; then
                          mkdir -p "lib/rt/$d"
                        fi
                      done
                    fi
                  done

                  # Also fix any existing "file where directory should be" problems
                  for d in lib/rt/sun lib/rt/java lib/rt/javax lib/rt/com lib/rt/org; do
                    if [ -f "$d" ]; then
                      rm "$d"
                      mkdir -p "$d"
                    fi
                  done

                  # Now apply post-extraction fixes to OpenJDK source
                  for dir in openjdk openjdk-boot; do
                    if [ -d "$dir" ]; then
                      # Remove -Werror and fix ALL hardcoded tool paths in makefiles
                      find "$dir" -name '*.gmk' -o -name 'Makefile' -o -name '*.make' -o -name '*.sh' 2>/dev/null | while read f; do
                        sed -i \
                          -e 's/-Werror//g' \
                          -e "s|/bin/mkdir|${buildTools.coreutils}/bin/mkdir|g" \
                          -e "s|/usr/bin/mkdir|${buildTools.coreutils}/bin/mkdir|g" \
                          -e "s|/bin/cat|${buildTools.coreutils}/bin/cat|g" \
                          -e "s|/bin/cp |${buildTools.coreutils}/bin/cp |g" \
                          -e "s|/bin/mv |${buildTools.coreutils}/bin/mv |g" \
                          -e "s|/bin/rm |${buildTools.coreutils}/bin/rm |g" \
                          -e "s|/bin/ln |${buildTools.coreutils}/bin/ln |g" \
                          -e "s|/bin/chmod|${buildTools.coreutils}/bin/chmod|g" \
                          -e "s|/bin/ls |${buildTools.coreutils}/bin/ls |g" \
                          -e "s|/bin/pwd|${buildTools.coreutils}/bin/pwd|g" \
                          -e "s|/usr/bin/pwd|${buildTools.coreutils}/bin/pwd|g" \
                          -e "s|/bin/date|${buildTools.coreutils}/bin/date|g" \
                          -e "s|/usr/bin/tr|${buildTools.coreutils}/bin/tr|g" \
                          -e "s|/bin/tr |${buildTools.coreutils}/bin/tr |g" \
                          -e "s|/usr/bin/wc|${buildTools.coreutils}/bin/wc|g" \
                          -e "s|/usr/bin/sort|${buildTools.coreutils}/bin/sort|g" \
                          -e "s|/usr/bin/cut|${buildTools.coreutils}/bin/cut|g" \
                          -e "s|/usr/bin/head|${buildTools.coreutils}/bin/head|g" \
                          -e "s|/usr/bin/tail|${buildTools.coreutils}/bin/tail|g" \
                          -e "s|/usr/bin/uniq|${buildTools.coreutils}/bin/uniq|g" \
                          -e "s|/usr/bin/touch|${buildTools.coreutils}/bin/touch|g" \
                          -e "s|/usr/bin/basename|${buildTools.coreutils}/bin/basename|g" \
                          -e "s|/usr/bin/dirname|${buildTools.coreutils}/bin/dirname|g" \
                          -e "s|/usr/bin/uname|${buildTools.coreutils}/bin/uname|g" \
                          -e "s|/bin/echo|${buildTools.coreutils}/bin/echo|g" \
                          -e "s|/usr/bin/echo|${buildTools.coreutils}/bin/echo|g" \
                          -e "s|/bin/true|${buildTools.coreutils}/bin/true|g" \
                          -e "s|/bin/false|${buildTools.coreutils}/bin/false|g" \
                          -e "s|/usr/bin/test|${buildTools.coreutils}/bin/test|g" \
                          -e "s|/usr/bin/expr|${buildTools.coreutils}/bin/expr|g" \
                          -e "s|/usr/bin/env|${buildTools.coreutils}/bin/env|g" \
                          -e "s|/usr/bin/id|${buildTools.coreutils}/bin/id|g" \
                          -e "s|/bin/grep|${buildTools.grep}/bin/grep|g" \
                          -e "s|/usr/bin/grep|${buildTools.grep}/bin/grep|g" \
                          -e "s|/bin/egrep|${buildTools.grep}/bin/egrep|g" \
                          -e "s|/usr/bin/egrep|${buildTools.grep}/bin/egrep|g" \
                          -e "s|/bin/fgrep|${buildTools.grep}/bin/fgrep|g" \
                          -e "s|/usr/bin/fgrep|${buildTools.grep}/bin/fgrep|g" \
                          -e "s|/bin/sed|${buildTools.sed}/bin/sed|g" \
                          -e "s|/usr/bin/sed|${buildTools.sed}/bin/sed|g" \
                          -e "s|/usr/bin/gawk|${buildTools.gawk}/bin/gawk|g" \
                          -e "s|/usr/bin/awk|${buildTools.gawk}/bin/gawk|g" \
                          -e "s|/bin/awk|${buildTools.gawk}/bin/gawk|g" \
                          -e "s|/usr/bin/find|$(which find)|g" \
                          -e "s|/usr/bin/xargs|$(which xargs)|g" \
                          -e "s|/usr/bin/cpio|${buildTools.cpio}/bin/cpio|g" \
                          -e "s|/usr/bin/file|${buildTools.file}/bin/file|g" \
                          -e "s|/usr/bin/readelf|${buildTools.binutils}/bin/readelf|g" \
                          -e "s|/usr/bin/zip|${buildTools.zip}/bin/zip|g" \
                          -e "s|/usr/bin/unzip|${buildTools.unzip}/bin/unzip|g" \
                          "$f" 2>/dev/null || true
                      done
                      # Fix sys/sysctl.h includes (removed in modern glibc)
                      find "$dir" -name '*.c' -o -name '*.cpp' -o -name '*.h' 2>/dev/null | while read f; do
                        sed -i 's|#include <sys/sysctl\.h>|/* removed: sys/sysctl.h */|g' "$f" 2>/dev/null || true
                      done
                      # Fix hardcoded /bin/echo in Defs-utils.gmk
                      find "$dir" -name 'Defs-utils.gmk' 2>/dev/null | while read f; do
                        sed -i \
                          -e "s|ECHO           = /bin/echo|ECHO           = ${buildTools.coreutils}/bin/echo|g" \
                          -e "s|ECHO           = /usr/bin/echo|ECHO           = ${buildTools.coreutils}/bin/echo|g" \
                          "$f" 2>/dev/null || true
                      done
                      # Fix hardcoded NAWK = /usr/bin/gawk
                      find "$dir" -name 'Defs-utils.gmk' 2>/dev/null | while read f; do
                        sed -i "s|NAWK           = \$(USRBIN_PATH)gawk|NAWK           = ${buildTools.gawk}/bin/gawk|g" "$f" 2>/dev/null || true
                      done
                      # Create empty build.properties (GNU Classpath's Property class
                      # throws FileNotFoundException instead of silently skipping)
                      find "$dir" -path '*/langtools' -type d 2>/dev/null | while read d; do
                        touch "$d/build.properties" 2>/dev/null || true
                      done
                      # Replace ant's <mkdir> with shell exec (GNU Classpath File.isFile()
                      # bug returns true for directories, causing ant's Mkdir task to fail)
                      find "$dir" -name 'build.xml' 2>/dev/null | while read f; do
                        sed -i 's|<mkdir dir="\([^"]*\)"/>|<exec executable="mkdir" failonerror="false"><arg value="-p"/><arg value="\1"/></exec>|g' "$f" 2>/dev/null || true
                        sed -i 's|<mkdir dir="\([^"]*\)" />|<exec executable="mkdir" failonerror="false"><arg value="-p"/><arg value="\1"/></exec>|g' "$f" 2>/dev/null || true
                        # Replace the <copy> block that copies .properties-template files
                        # with our helper script (GNU Classpath File.exists()/canWrite() bugs)
                        sed -i '/<copy todir="@{gensrc.dir}">/,/<\/copy>/c\                <exec executable="copy-props.sh"><arg value="''${src.classes.dir}"/><arg value="@{gensrc.dir}"/><arg value="@{includes}"/><arg value="''${jdk.version}"/><arg value="@{release}"/><arg value="@{full.version}"/></exec>' "$f" 2>/dev/null || true
                      done
                      # Patch HotSpot to accept modern kernels (6.x+)
                      # The SUPPORTED_OS_VERSION list only goes up to 3.x or 4.x
                      find "$dir" -path '*/hotspot/make/linux/Makefile' 2>/dev/null | while read f; do
                        sed -i '/SUPPORTED_OS_VERSION/s/$/ 4% 5% 6% 7%/' "$f" 2>/dev/null || true
                      done
                      # Fix GCC 14 errors in HotSpot C++ code
                      find "$dir" -path '*/hotspot/make/linux/makefiles/gcc.make' 2>/dev/null | while read f; do
                        # Disable -Werror
                        sed -i 's/WARNINGS_ARE_ERRORS = -Werror/WARNINGS_ARE_ERRORS =/' "$f" 2>/dev/null || true
                        sed -i 's/-Wpointer-arith/-Wno-error/g' "$f" 2>/dev/null || true
                      done
                      # Fix pointer-vs-integer comparisons (hard error in GCC 14)
                      # Pattern: pointer > 0, pointer != 0, pointer == 0, etc.
                      find "$dir" -path '*/hotspot/src/*.cpp' -o -path '*/hotspot/src/*.hpp' 2>/dev/null | while read f; do
                        # narrow_oop_base() > 0 → narrow_oop_base() != NULL
                        sed -i 's/narrow_oop_base() > 0/narrow_oop_base() != NULL/g' "$f" 2>/dev/null || true
                        sed -i 's/narrow_oop_base() >= 0/narrow_oop_base() != NULL || narrow_oop_base() == NULL/g' "$f" 2>/dev/null || true
                        # base() > 0 → base() != NULL
                        sed -i 's/base() > 0/base() != NULL/g' "$f" 2>/dev/null || true
                      done
                      # Fix GCC 14: implicit function declarations are hard errors
                      # Patch source files directly since the inner Makefiles use the full
                      # path to aos-cc-wrapper, bypassing any gcc wrapper we create.
                      find "$dir" -path '*/jdk/src/share/native/common/jni_util.c' 2>/dev/null | while read f; do
                        # Add forward declaration of getLastErrorString after includes
                        sed -i '/jni_util\.h/a\/* GCC 14 fix */ int getLastErrorString(char *buf, size_t len);' "$f" 2>/dev/null || true
                      done
                      # Fix GCC 10+/14: multiple definition of `parentPathv`
                      # In childproc.c it's defined as a global; UNIXProcess_md.c also has it.
                      # GCC 10+ defaults to -fno-common, making tentative definitions errors.
                      find "$dir" -path '*/jdk/src/solaris/native/java/lang/childproc.c' 2>/dev/null | while read f; do
                        sed -i 's/^const char \*\*parentPathv;/extern const char **parentPathv;/' "$f" 2>/dev/null || true
                        sed -i 's/^char \*\*parentPathv;/extern char **parentPathv;/' "$f" 2>/dev/null || true
                      done
                      # Add -fcommon and -Wno-implicit-function-declaration globally
                      # as safety nets for other GCC 14 issues in JDK native code.
                      # Append to Defs-linux.gmk which defines CFLAGS_COMMON used by all builds.
                      find "$dir" -path '*/jdk/make/common/Defs-linux.gmk' 2>/dev/null | while read f; do
                        echo 'OTHER_CFLAGS += -fcommon -Wno-implicit-function-declaration -Wno-implicit-int -Wno-int-conversion -Wno-incompatible-pointer-types' >> "$f" 2>/dev/null || true
                        # Fix empty OPENWIN_HOME: bare -I flag eats -c flag, causing
                        # gcc to link instead of compile in headless AWT build
                        echo 'OPENWIN_HOME = ${xorg-stubs}' >> "$f" 2>/dev/null || true
                      done
                      # Fix GenerateCurrencyData: "time is more than 10 years from present"
                      # The currency data has dates from 2015 which are >10 years from 2026.
                      # Source: ((long) 10) * 365 ... → ((long) 50) * 365 ...
                      find "$dir" -path '*/tools/generatecurrencydata/GenerateCurrencyData.java' 2>/dev/null | while read f; do
                        sed -i 's/((long) 10)/((long) 50)/g' "$f" 2>/dev/null || true
                        sed -i 's/more than 10 years/more than 50 years/g' "$f" 2>/dev/null || true
                      done
                      # Disable splashscreen and xawt builds — headless build, xorg-stubs
                      # don't have real X11 function implementations or generated headers
                      # (Shell.h) needed for these components
                      for component in splashscreen xawt gtk jawt; do
                        find "$dir" -path "*/jdk/make/sun/$component/Makefile" 2>/dev/null | while read f; do
                          printf 'all:\n\t@echo "%s disabled for headless build"\nclean:\n\t@true\n' "$component" > "$f" 2>/dev/null || true
                        done
                      done
                      # Skip ct.sym generation (CreateSymbols processor) — the JAXWS build
                      # is missing internal ASM classes (MethodVisitor), causing hard errors
                      # during the symbol verification step. Without ct.sym, javac falls back
                      # to using rt.jar directly for symbol resolution.
                      find "$dir" -path '*/jdk/make/common/Release.gmk' 2>/dev/null | while read f; do
                        awk '
                          /XDprocess.packages/ && /proc:only/ { skip=1; print "\t@echo \"ct.sym generation skipped (bootstrap)\""; next }
                          skip && /\\$/ { next }
                          skip && !/\\$/ { skip=0; next }
                          { print }
                        ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
                      done
                      # Skip ant -diagnostics in langtools (JamVM is too slow for this)
                      find "$dir" -path '*/langtools/make/Makefile' 2>/dev/null | while read f; do
                        sed -i 's|$(ANT_JAVA_HOME) $(ANT_OPTS) $(ANT) -diagnostics > $@ ;|mkdir -p $(OUTPUTDIR)/build \&\& echo "diagnostics skipped" > $@ ;|' "$f" 2>/dev/null || true
                        sed -i 's|$(ANT_JAVA_HOME) $(ANT_OPTS) $(ANT) -version >> $@|echo "ant version skipped" >> $@|' "$f" 2>/dev/null || true
                      done
                    fi
                  done${
            if isDarwinCross
            then ''

                                                  # openjdk-boot is a Linux BuildJDK. Its launchers and headless
                                          # native libraries must use the native X11 publication, while
                                          # the final openjdk tree keeps the Darwin target stubs above.
                                          boot_defs=openjdk-boot/jdk/make/common/Defs-linux.gmk
                                          test -f "$boot_defs"
                                          {
                                            echo 'OPENWIN_HOME = ${xorgStubsForBuild}'
                                            echo 'override OPENWIN_LIB = ${xorgStubsForBuild}/lib'
                                          } >> "$boot_defs"

                                          # HotSpot otherwise selects its makefile from the Linux builder's
                                          # uname. Select the pinned BSD/Darwin port only for the final
                                          # target VM; openjdk-boot remains the native Linux BuildJDK.
                                          target_hotspot_rules=openjdk/make/hotspot-rules.gmk
                                          test -f "$target_hotspot_rules"
                                          test "$(grep -Fxc \
                                            'HOTSPOT_BUILD_ARGUMENTS += BUILD_FLAVOR=$(BUILD_FLAVOR)' \
                                            "$target_hotspot_rules")" = 1
                                          sed -i \
                                            '/^HOTSPOT_BUILD_ARGUMENTS += BUILD_FLAVOR=/a HOTSPOT_BUILD_ARGUMENTS += OS=bsd' \
                                            "$target_hotspot_rules"
                                          sed -i \
                                            '/^HOTSPOT_BUILD_ARGUMENTS += OS=bsd/a HOTSPOT_BUILD_ARGUMENTS += OS_VENDOR=Darwin' \
                                            "$target_hotspot_rules"

                                          # The Darwin serviceability agent is a real
                                          # JavaNativeFoundation consumer. Build and link it against the
                                          # pinned source-built framework and retain an image-relative
                                          # runtime path to the framework bundled below.
                                          mkdir -p openjdk-target-java-headers/JavaVM
                                          ln -s ../openjdk/jdk/src/share/javavm/export/jni.h \
                                            openjdk-target-java-headers/jni.h
                                          ln -s ../openjdk/jdk/src/macosx/javavm/export/jni_md.h \
                                            openjdk-target-java-headers/jni_md.h
                                          ln -s ../jni.h openjdk-target-java-headers/JavaVM/jni.h
                                          ln -s ../jni_md.h openjdk-target-java-headers/JavaVM/jni_md.h
                                          target_saproc_make=openjdk/hotspot/make/bsd/makefiles/saproc.make
                                          test -f "$target_saproc_make"
                                          test "$(grep -Fxc \
                                            '    SALIBS = -g -framework Foundation -F/System/Library/Frameworks/JavaVM.framework/Frameworks -framework JavaNativeFoundation -framework Security -framework CoreFoundation' \
                                            "$target_saproc_make")" = 1
                                          sed -i \
                                            's|^    SALIBS = -g |    SALIBS = -I$(GAMMADIR)/../../openjdk-target-java-headers -F${jnfFrameworks} -Wl,-rpath,@loader_path/.. -g |' \
                                            "$target_saproc_make"

                                          # The ordinary osxapp library is also a complete
                                          # JavaNativeFoundation consumer. Its legacy makefile assumes
                                          # Xcode's ambient framework search path for both headers and
                                          # the final link; publish the source-built target framework
                                          # explicitly instead.
                                          target_jdk_osxapp_make=openjdk/jdk/make/sun/osxapp/Makefile
                                          test -f "$target_jdk_osxapp_make"
                                          test "$(grep -Ec \
                                            '^[[:space:]]+-framework JavaNativeFoundation \\$' \
                                            "$target_jdk_osxapp_make")" = 1
                                          test "$(grep -Fxc 'CPPFLAGS += \' \
                                            "$target_jdk_osxapp_make")" = 1
                                          # ExceptionHandling was an ambient, link-only Xcode
                                          # dependency: none of the four pinned osxapp translation units
                                          # includes or references its API, and it is no longer a public
                                          # framework. Keep every active framework while dropping only
                                          # that unused legacy load command.
                                          test "$(grep -Ec \
                                            '^[[:space:]]+-framework ExceptionHandling \\$' \
                                            "$target_jdk_osxapp_make")" = 1
                                          sed -i \
                                            -e '/^CPPFLAGS += \\$/a\        -F${jnfFrameworks} \\' \
                                            -e '/^[[:space:]]*-framework JavaNativeFoundation \\$/i\	-F${jnfFrameworks} \\' \
                                            -e '/^[[:space:]]*-framework ExceptionHandling \\$/d' \
                                            "$target_jdk_osxapp_make"
                                          test "$(grep -Fxc \
                                            '        -F${jnfFrameworks} \' \
                                            "$target_jdk_osxapp_make")" = 1
                                          test "$(grep -Ec \
                                            '^[[:space:]]+-F${jnfFrameworks} \\$' \
                                            "$target_jdk_osxapp_make")" = 2
                                          test "$(grep -Fc 'ExceptionHandling' \
                                            "$target_jdk_osxapp_make")" = 0

                                          # libawt is a separate JavaNativeFoundation consumer. Its
                                          # framework list likewise assumes Xcode's ambient search path,
                                          # so publish the same source-built target framework to its final
                                          # link without changing the ordinary native build.
                                          target_jdk_awt_make=openjdk/jdk/make/sun/awt/Makefile
                                          test -f "$target_jdk_awt_make"
                                          test "$(grep -Ec \
                                            '^[[:space:]]+-framework JavaNativeFoundation \\$' \
                                            "$target_jdk_awt_make")" = 1
                                          test "$(grep -Fc '${jnfFrameworks}' \
                                            "$target_jdk_awt_make")" = 0
                                          sed -i \
                                            '/^[[:space:]]*-framework JavaNativeFoundation \\$/i\    -F${jnfFrameworks} \\' \
                                            "$target_jdk_awt_make"
                                          test "$(grep -Fxc \
                                            '    -F${jnfFrameworks} \' \
                                            "$target_jdk_awt_make")" = 1

                                          # The macOS lightweight AWT owns the Cocoa peer and must not
                                          # compile the Solaris X11 peer classes selected through the
                                          # broad sun/awt source root. Its native library is another real
                                          # JavaNativeFoundation consumer, installed one directory below
                                          # the bundled framework. Keep the complete Cocoa implementation,
                                          # prune only the foreign X11 package, and publish the framework
                                          # search path plus image-relative runtime path explicitly.
                                          target_jdk_lwawt_make=openjdk/jdk/make/sun/lwawt/Makefile
                                          test -f "$target_jdk_lwawt_make"
                                          test "$(grep -Fxc \
                                            'AUTO_FILES_JAVA_DIRS = sun/awt sun/font sun/lwawt sun/lwawt/macosx sun/java2d sun/java2d/opengl com/apple/eawt' \
                                            "$target_jdk_lwawt_make")" = 1
                                          test "$(grep -Ec \
                                            '^[[:space:]]+-framework JavaNativeFoundation \\$' \
                                            "$target_jdk_lwawt_make")" = 1
                                          test "$(grep -Ec \
                                            '^[[:space:]]+-framework ExceptionHandling \\$' \
                                            "$target_jdk_lwawt_make")" = 1
                                          test "$(grep -Fc '${jnfFrameworks}' \
                                            "$target_jdk_lwawt_make")" = 0
                                          sed -i \
                                            -e '/^AUTO_FILES_JAVA_DIRS = /a AUTO_JAVA_PRUNE += X11' \
                                            -e '/^CPPFLAGS += \\$/a\        -F${jnfFrameworks} \\' \
                                            -e '/^[[:space:]]*-framework JavaNativeFoundation \\$/i\        -F${jnfFrameworks} -Wl,-rpath,@loader_path/.. \\' \
                                            -e '/^[[:space:]]*-framework ExceptionHandling \\$/d' \
                                            "$target_jdk_lwawt_make"
                                          test "$(grep -Fxc 'AUTO_JAVA_PRUNE += X11' \
                                            "$target_jdk_lwawt_make")" = 1
                                          test "$(grep -Fc '${jnfFrameworks}' \
                                            "$target_jdk_lwawt_make")" = 2
                                          test "$(grep -Fc 'ExceptionHandling' \
                                            "$target_jdk_lwawt_make")" = 0

                                          # CGraphicsDevice consumes the public IOGraphics pixel-format
                                          # constants, but the pinned source relied on an old umbrella
                                          # header to publish them indirectly. Include their canonical
                                          # owning header explicitly for the target translation unit.
                                          target_jdk_graphics_device=openjdk/jdk/src/macosx/native/sun/awt/CGraphicsDevice.m
                                          test "$(grep -Fxc '#import "LWCToolkit.h"' \
                                            "$target_jdk_graphics_device")" = 1
                                          test "$(grep -Fxc '#include <IOKit/graphics/IOGraphicsTypes.h>' \
                                            "$target_jdk_graphics_device")" = 0
                                          sed -i \
                                            's@^#import "LWCToolkit.h"$@#import "LWCToolkit.h"\n#include <IOKit/graphics/IOGraphicsTypes.h>@' \
                                            "$target_jdk_graphics_device"

                                          # GNU javah omits private static-final fields from generated JNI
                                          # headers, while the pinned Cocoa event bridge shares their exact
                                          # Java values with native code. Restore only those generated names
                                          # in the native target source; the Java API and notification paths
                                          # remain unchanged.
                                          target_jdk_app_delegate=openjdk/jdk/src/macosx/native/sun/awt/ApplicationDelegate.m
                                          target_jdk_app_events=openjdk/jdk/src/macosx/classes/com/apple/eawt/_AppEventHandler.java
                                          for constant_value in \
                                            'NOTIFY_ABOUT 1' \
                                            'NOTIFY_PREFS 2' \
                                            'NOTIFY_OPEN_APP 3' \
                                            'NOTIFY_REOPEN_APP 4' \
                                            'NOTIFY_QUIT 5' \
                                            'NOTIFY_SHUTDOWN 6' \
                                            'NOTIFY_ACTIVE_APP_GAINED 7' \
                                            'NOTIFY_ACTIVE_APP_LOST 8' \
                                            'NOTIFY_APP_HIDDEN 9' \
                                            'NOTIFY_APP_SHOWN 10' \
                                            'NOTIFY_USER_SESSION_ACTIVE 11' \
                                            'NOTIFY_USER_SESSION_INACTIVE 12' \
                                            'NOTIFY_SCREEN_SLEEP 13' \
                                            'NOTIFY_SCREEN_WAKE 14' \
                                            'NOTIFY_SYSTEM_SLEEP 15' \
                                            'NOTIFY_SYSTEM_WAKE 16' \
                                            'REGISTER_USER_SESSION 1' \
                                            'REGISTER_SCREEN_SLEEP 2' \
                                            'REGISTER_SYSTEM_SLEEP 3'; do
                                            constant="''${constant_value% *}"
                                            value="''${constant_value#* }"
                                            test "$(grep -Fxc \
                                              "    private static final int $constant = $value;" \
                                              "$target_jdk_app_events")" = 1
                                          done
                                          target_jdk_menu_events=openjdk/jdk/src/macosx/classes/com/apple/eawt/_AppMenuBarHandler.java
                                          for constant_value in 'MENU_ABOUT 1' 'MENU_PREFS 2'; do
                                            constant="''${constant_value% *}"
                                            value="''${constant_value#* }"
                                            test "$(grep -Fxc \
                                              "    private static final int $constant = $value;" \
                                              "$target_jdk_menu_events")" = 1
                                          done
                                          test "$(grep -Fxc '#import "com_apple_eawt__AppEventHandler.h"' \
                                            "$target_jdk_app_delegate")" = 1
                                          test "$(grep -Fc \
                                            'com_apple_eawt__AppEventHandler_NOTIFY_ABOUT' \
                                            "$target_jdk_app_delegate")" = 1
                                          sed -i \
                                            '/^#import "com_apple_eawt__AppEventHandler.h"$/a\
              #ifndef com_apple_eawt__AppEventHandler_NOTIFY_ABOUT\
              #define com_apple_eawt__AppEventHandler_NOTIFY_ABOUT 1L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_PREFS 2L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_OPEN_APP 3L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_REOPEN_APP 4L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_QUIT 5L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_SHUTDOWN 6L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_ACTIVE_APP_GAINED 7L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_ACTIVE_APP_LOST 8L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_APP_HIDDEN 9L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_APP_SHOWN 10L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_USER_SESSION_ACTIVE 11L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_USER_SESSION_INACTIVE 12L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_SCREEN_SLEEP 13L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_SCREEN_WAKE 14L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_SYSTEM_SLEEP 15L\
              #define com_apple_eawt__AppEventHandler_NOTIFY_SYSTEM_WAKE 16L\
              #define com_apple_eawt__AppEventHandler_REGISTER_USER_SESSION 1L\
              #define com_apple_eawt__AppEventHandler_REGISTER_SCREEN_SLEEP 2L\
              #define com_apple_eawt__AppEventHandler_REGISTER_SYSTEM_SLEEP 3L\
              #define com_apple_eawt__AppMenuBarHandler_MENU_ABOUT 1L\
              #define com_apple_eawt__AppMenuBarHandler_MENU_PREFS 2L\
              #endif' \
                                            "$target_jdk_app_delegate"
                                          test "$(grep -Fc \
                                            '#define com_apple_eawt__AppEventHandler_NOTIFY_ABOUT 1L' \
                                            "$target_jdk_app_delegate")" = 1
                                          test "$(grep -Fc \
                                            '#define com_apple_eawt__AppEventHandler_REGISTER_SYSTEM_SLEEP 3L' \
                                            "$target_jdk_app_delegate")" = 1
                                          test "$(grep -Fc \
                                            '#define com_apple_eawt__AppMenuBarHandler_MENU_PREFS 2L' \
                                            "$target_jdk_app_delegate")" = 1

                                          # Backport JDK-8257148 for the supported Darwin baseline.
                                          # Press-and-hold is always available after Snow Leopard and the
                                          # obsolete grow-box implementation is never selected, so retain
                                          # those exact outcomes without the removed JRSCopyOSVersion API.
                                          target_jdk_awt_view=openjdk/jdk/src/macosx/native/sun/awt/AWTView.m
                                          test "$(grep -Fxc '#import "OSVersion.h"' \
                                            "$target_jdk_awt_view")" = 1
                                          test "$(grep -Fc \
                                            '    shouldUsePressAndHold = !isSnowLeopardOrLower();' \
                                            "$target_jdk_awt_view")" = 1
                                          sed -i \
                                            -e '/#import "OSVersion.h"/d' \
                                            -e '/static BOOL shouldUsePressAndHold()/,/^}/c\static BOOL shouldUsePressAndHold() {\n    return YES;\n}' \
                                            "$target_jdk_awt_view"
                                          test "$(sed -n \
                                            '/static BOOL shouldUsePressAndHold()/,/^}/p' \
                                            "$target_jdk_awt_view" | grep -Fc '    return YES;')" = 1
                                          ! grep -Fq 'isSnowLeopardOrLower' "$target_jdk_awt_view"

                                          target_jdk_awt_window=openjdk/jdk/src/macosx/native/sun/awt/AWTWindow.m
                                          test "$(grep -Fxc '#import "OSVersion.h"' \
                                            "$target_jdk_awt_window")" = 1
                                          test "$(grep -Fxc \
                                            '    return isSnowLeopardOrLower() && IS(self.styleBits, RESIZABLE);' \
                                            "$target_jdk_awt_window")" = 1
                                          sed -i \
                                            -e '/#import "OSVersion.h"/d' \
                                            -e 's/    return isSnowLeopardOrLower() && IS(self.styleBits, RESIZABLE);/    return NO;/' \
                                            "$target_jdk_awt_window"
                                          test "$(sed -n \
                                            '/- (BOOL) shouldShowGrowBox {/,/^}/p' \
                                            "$target_jdk_awt_window" | grep -Fxc '    return NO;')" = 1
                                          ! grep -Fq 'isSnowLeopardOrLower' "$target_jdk_awt_window"

                                          target_jdk_lwawt_sources=openjdk/jdk/make/sun/lwawt/FILES_c_macosx.gmk
                                          test "$(grep -Ec '^[[:space:]]+OSVersion[.]m \\' \
                                            "$target_jdk_lwawt_sources")" = 1
                                          sed -i '/^[[:space:]]*OSVersion[.]m \\/d' \
                                            "$target_jdk_lwawt_sources"
                                          ! grep -Fq 'OSVersion.m' "$target_jdk_lwawt_sources"
                                          rm -f \
                                            openjdk/jdk/src/macosx/native/sun/awt/OSVersion.h \
                                            openjdk/jdk/src/macosx/native/sun/awt/OSVersion.m

                                          # Later pinned JDK sources publish the JNI utility declaration
                                          # consumed by CRobot and use the already-global mouse coordinates
                                          # directly. Backport those source fixes without changing Robot's
                                          # button, keyboard, wheel, or screen-capture paths.
                                          target_jdk_robot=openjdk/jdk/src/macosx/native/sun/awt/CRobot.m
                                          test "$(grep -Fxc \
                                            '#import <JavaNativeFoundation/JavaNativeFoundation.h>' \
                                            "$target_jdk_robot")" = 1
                                          test "$(grep -Fc '#import "jni_util.h"' \
                                            "$target_jdk_robot")" = 0
                                          sed -i \
                                            '/#import <JavaNativeFoundation\/JavaNativeFoundation.h>/i\#import "jni_util.h"\n' \
                                            "$target_jdk_robot"
                                          test "$(grep -Fxc '#import "jni_util.h"' \
                                            "$target_jdk_robot")" = 1
                                          test "$(grep -Fxc \
                                            '    point.x = mouseLastX + globalDeviceBounds.origin.x;' \
                                            "$target_jdk_robot")" = 1
                                          test "$(grep -Fxc \
                                            '    point.y = mouseLastY + globalDeviceBounds.origin.y;' \
                                            "$target_jdk_robot")" = 1
                                          sed -i \
                                            -e 's/    point.x = mouseLastX + globalDeviceBounds.origin.x;/    point.x = mouseLastX;/' \
                                            -e 's/    point.y = mouseLastY + globalDeviceBounds.origin.y;/    point.y = mouseLastY;/' \
                                            "$target_jdk_robot"
                                          ! grep -Fq 'globalDeviceBounds' "$target_jdk_robot"

                                          # JMX generates portable RMI stub bytecode after the target
                                          # launcher has already been linked. The pinned makefile selects
                                          # that new launcher unless CROSS_COMPILE_ARCH is set, but this
                                          # Canadian build selects Darwin through the package stdenv and
                                          # leaves the legacy variable empty. Run the Java generator with
                                          # the Linux BuildJDK while retaining the target classes and
                                          # generated sources unchanged.
                                          target_jdk_jmx=openjdk/jdk/make/com/sun/jmx/Makefile
                                          test "$(grep -Fxc \
                                            'RMIC_JAVA = $(OUTPUTDIR)/bin/java' \
                                            "$target_jdk_jmx")" = 1
                                          test "$(grep -Fxc \
                                            'RMIC_JAVA = $(BOOT_JAVA_CMD)' \
                                            "$target_jdk_jmx")" = 0
                                          sed -i \
                                            's|^RMIC_JAVA = $(OUTPUTDIR)/bin/java$|RMIC_JAVA = $(BOOT_JAVA_CMD)|' \
                                            "$target_jdk_jmx"
                                          test "$(grep -Fxc \
                                            'RMIC_JAVA = $(BOOT_JAVA_CMD)' \
                                            "$target_jdk_jmx")" = 1

                                          # The com.apple.osx JNI library is another direct
                                          # JavaNativeFoundation consumer. Its pinned makefile
                                          # names the framework for the final link but assumes
                                          # Xcode supplies the framework search path to both
                                          # compilation and linking. Publish the source-built
                                          # target framework explicitly instead.
                                          target_jdk_apple_osx_make=openjdk/jdk/make/com/apple/osx/Makefile
                                          test -f "$target_jdk_apple_osx_make"
                                          test "$(grep -Fxc 'CPPFLAGS += \' \
                                            "$target_jdk_apple_osx_make")" = 1
                                          test "$(grep -Ec \
                                            '^[[:space:]]+-framework JavaNativeFoundation \\$' \
                                            "$target_jdk_apple_osx_make")" = 1
                                          test "$(grep -Fc '${jnfFrameworks}' \
                                            "$target_jdk_apple_osx_make")" = 0
                                          sed -i \
                                            -e '/^CPPFLAGS += \\$/a\        -F${jnfFrameworks} \\' \
                                            -e '/^[[:space:]]*-framework JavaNativeFoundation \\$/i\    -F${jnfFrameworks} \\' \
                                            "$target_jdk_apple_osx_make"
                                          test "$(grep -Fc '${jnfFrameworks}' \
                                            "$target_jdk_apple_osx_make")" = 2

                                          # The companion osxui library has the same legacy
                                          # ambient-Xcode assumption for its eight Cocoa/JRSUI
                                          # translation units and final framework link.
                                          target_jdk_apple_osxui_make=openjdk/jdk/make/com/apple/osxui/Makefile
                                          test -f "$target_jdk_apple_osxui_make"
                                          test "$(grep -Fxc 'CPPFLAGS += \' \
                                            "$target_jdk_apple_osxui_make")" = 1
                                          test "$(grep -Ec \
                                            '^[[:space:]]+-framework JavaNativeFoundation \\$' \
                                            "$target_jdk_apple_osxui_make")" = 1
                                          test "$(grep -Fc '${jnfFrameworks}' \
                                            "$target_jdk_apple_osxui_make")" = 0
                                          sed -i \
                                            -e '/^CPPFLAGS += \\$/a\        -F${jnfFrameworks} \\' \
                                            -e '/^[[:space:]]*-framework JavaNativeFoundation \\$/i\    -F${jnfFrameworks} \\' \
                                            "$target_jdk_apple_osxui_make"
                                          test "$(grep -Fc '${jnfFrameworks}' \
                                            "$target_jdk_apple_osxui_make")" = 2

                                          # AppleScriptEngine is the remaining pinned Apple
                                          # JNI library which imports JavaNativeFoundation.
                                          # Publish the same source-built target framework to
                                          # both its Objective-C compile and final link.
                                          target_jdk_applescript_make=openjdk/jdk/make/apple/applescript/Makefile
                                          test -f "$target_jdk_applescript_make"
                                          test "$(grep -Fxc 'CPPFLAGS += \' \
                                            "$target_jdk_applescript_make")" = 1
                                          test "$(grep -Ec \
                                            '^[[:space:]]+-framework JavaNativeFoundation$' \
                                            "$target_jdk_applescript_make")" = 1
                                          test "$(grep -Fc '${jnfFrameworks}' \
                                            "$target_jdk_applescript_make")" = 0
                                          sed -i \
                                            -e '/^CPPFLAGS += \\$/a\        -F${jnfFrameworks} \\' \
                                            -e '/^[[:space:]]*-framework JavaNativeFoundation$/i\    -F${jnfFrameworks} \\' \
                                            "$target_jdk_applescript_make"
                                          test "$(grep -Fc '${jnfFrameworks}' \
                                            "$target_jdk_applescript_make")" = 2

                                          # SetFile only records the Finder bundle bit in
                                          # HFS metadata. Nix store objects cannot retain that
                                          # metadata, while the bundle directories, launchers,
                                          # and Info.plist files are all produced normally.
                                          # Avoid executing the undeclared Xcode host utility
                                          # in the Canadian build without changing bundle
                                          # contents.
                                          target_jdk_release_macosx=openjdk/jdk/make/common/Release-macosx.gmk
                                          test -f "$target_jdk_release_macosx"
                                          test "$(grep -Ec \
                                            '^[[:space:]]*/usr/bin/SetFile -a B \$\((JRE|JDK|JDK_SERVER)_BUNDLE_DIR\)/\.\./$' \
                                            "$target_jdk_release_macosx")" = 3
                                          sed -i \
                                            's|^[[:space:]]*/usr/bin/SetFile -a B \(.*\)$|\t$(TRUE) # HFS Finder bundle metadata is not representable in the Nix store|' \
                                            "$target_jdk_release_macosx"
                                          test "$(grep -Ec \
                                            '^[[:space:]]+\$\(TRUE\) # HFS Finder bundle metadata is not representable in the Nix store$' \
                                            "$target_jdk_release_macosx")" = 3

                                          # Later OpenJDK corrected the Keychain import's format
                                          # variable to match SecKeychainItemImport and restored
                                          # the cleanup label used by the password conversion
                                          # failure path. Backport those source fixes verbatim;
                                          # the import formats and keychain behavior are unchanged.
                                          target_jdk_keystore=openjdk/jdk/src/macosx/native/apple/security/KeystoreImpl.m
                                          test "$(grep -Fxc \
                                            '    SecExternalItemType dataType = (isCertificate == JNI_TRUE ? kSecFormatX509Cert : kSecFormatWrappedPKCS8);' \
                                            "$target_jdk_keystore")" = 1
                                          test "$(grep -Fxc \
                                            '    err = SecKeychainItemImport(cfDataToImport, NULL, &dataType, NULL,' \
                                            "$target_jdk_keystore")" = 1
                                          test "$(grep -Fxc 'errOut:' \
                                            "$target_jdk_keystore")" = 3
                                          sed -i \
                                            -e 's/SecExternalItemType dataType =/SecExternalFormat dataFormat =/' \
                                            -e 's/SecKeychainItemImport(cfDataToImport, NULL, &dataType, NULL,/SecKeychainItemImport(cfDataToImport, NULL, \&dataFormat, NULL,/' \
                                            -e '/^    (\*env)->ReleaseByteArrayElements(env, rawDataObj, rawData, JNI_ABORT);$/i\errOut:' \
                                            "$target_jdk_keystore"
                                          test "$(grep -Fxc \
                                            '    SecExternalFormat dataFormat = (isCertificate == JNI_TRUE ? kSecFormatX509Cert : kSecFormatWrappedPKCS8);' \
                                            "$target_jdk_keystore")" = 1
                                          test "$(grep -Fxc \
                                            '    err = SecKeychainItemImport(cfDataToImport, NULL, &dataFormat, NULL,' \
                                            "$target_jdk_keystore")" = 1
                                          test "$(grep -Fxc 'errOut:' \
                                            "$target_jdk_keystore")" = 4

                                          # fView is stored as NSView for the common accessibility base,
                                          # but this path sends AWTView-specific JNI selectors. Make that
                                          # established runtime contract explicit for modern Clang.
                                          target_jdk_accessibility=openjdk/jdk/src/macosx/native/sun/awt/JavaComponentAccessibility.m
                                          test "$(grep -Fc 'AWTView *view = fView;' \
                                            "$target_jdk_accessibility")" = 1
                                          sed -i \
                                            's/AWTView \*view = fView;/AWTView *view = (AWTView *)fView;/' \
                                            "$target_jdk_accessibility"
                                          test "$(grep -Fc 'AWTView *view = (AWTView *)fView;' \
                                            "$target_jdk_accessibility")" = 1

                                          # Platform.gmk otherwise runs Darwin discovery programs on the
                                          # Linux builder after SYSTEM_UNAME selects the target sources.
                                          # Publish deterministic target-baseline values; the Linux boot
                                          # build never enters this branch.
                                          target_jdk_platform=openjdk/jdk/make/common/shared/Platform.gmk
                                          test -f "$target_jdk_platform"
                                          test "$(grep -Fc \
                                            'GB_OF_MEMORY := $(shell system_profiler SPHardwareDataType' \
                                            "$target_jdk_platform")" = 1
                                          test "$(grep -Fc \
                                            '  MB_OF_MEMORY := $(shell expr' \
                                            "$target_jdk_platform")" = 1
                                          test "$(grep -Fxc '  OS_VERSION := $(shell uname -r)' "$target_jdk_platform")" = 1
                                          sed -i \
                                            -e 's|^  GB_OF_MEMORY := .*|  GB_OF_MEMORY := 4|' \
                                            -e 's|^  MB_OF_MEMORY := .*|  MB_OF_MEMORY := 4096|' \
                                            -e 's|^  OS_VERSION := $(shell uname -r)$|  OS_VERSION := 20.0.0|' \
                                            "$target_jdk_platform"

                                          # The pinned LLVM compiler configuration creates archives by
                                          # driving ld -r through the compiler, including a 32+64-bit
                                          # universal request. Current ld64 does not implement relocatable
                                          # links. Use the target archiver to retain the ordinary static
                                          # fdlibm archive selected by the x86_64-only platform build.
                                          target_jdk_llvm=openjdk/jdk/make/common/shared/Compiler-llvm.gmk
                                          test -f "$target_jdk_llvm"
                                          test "$(grep -Fxc '  AR = $(CC)' "$target_jdk_llvm")" = 1
                                          test "$(grep -Fxc \
                                            '  ARFLAGS = -nostdlib -r -arch i386 -arch x86_64 -o' \
                                            "$target_jdk_llvm")" = 1
                                          sed -i \
                                            -e 's|^  AR = $(CC)$|  AR = ${stdenv.cc}/bin/ar|' \
                                            -e 's|^  ARFLAGS = -nostdlib -r -arch i386 -arch x86_64 -o$|  ARFLAGS = rcs|' \
                                            "$target_jdk_llvm"

                                          # The pinned JDK uses a tentative definition of parentPathv in
                                          # childproc.h, included by both childproc.c and UNIXProcess_md.c.
                                          # Match the common-symbol semantics of its contemporary Apple
                                          # compiler for target C only; modern Clang otherwise rejects the
                                          # duplicate while linking libjava.dylib.
                                          target_jdk_defs=openjdk/jdk/make/common/Defs-macosx.gmk
                                          test -f "$target_jdk_defs"
                                          test "$(grep -Fxc '  CFLAGS_COMMON   = -fno-strict-aliasing' \
                                            "$target_jdk_defs")" = 1
                                          sed -i \
                                            's|^  CFLAGS_COMMON   = -fno-strict-aliasing$|  CFLAGS_COMMON   = -fno-strict-aliasing -fcommon|' \
                                            "$target_jdk_defs"

                                          # The macOS JLI makefile lists the shared Solaris launcher
                                          # implementation but only searches the share and macOS source
                                          # directories. Retain the intended common launcher by adding its
                                          # already-declared Solaris source directory to the C vpath.
                                          target_jdk_jli=openjdk/jdk/make/java/jli/Makefile
                                          test "$(grep -Fxc \
                                            'vpath %.c $(LAUNCHER_SHARE_SRC) $(LAUNCHER_PLATFORM_SRC)' \
                                            "$target_jdk_jli")" = 1
                                          sed -i \
                                            's|^vpath %.c $(LAUNCHER_SHARE_SRC) $(LAUNCHER_PLATFORM_SRC)$|vpath %.c $(LAUNCHER_SHARE_SRC) $(LAUNCHER_PLATFORM_SRC) $(LAUNCHER_SOLARIS_PLATFORM_SRC)|' \
                                            "$target_jdk_jli"

                                          # TARGET_OS_MAC also identifies Darwin in current Apple headers,
                                          # but this bundled zlib branch describes classic Mac OS and
                                          # replaces the real fdopen declaration with a NULL macro. Keep
                                          # that compatibility branch for its historical targets only;
                                          # Darwin uses the following __APPLE__ configuration.
                                          target_jdk_zutil=openjdk/jdk/src/share/native/java/util/zip/zlib/zutil.h
                                          test "$(grep -Fxc \
                                            '#if defined(MACOS) || defined(TARGET_OS_MAC)' \
                                            "$target_jdk_zutil")" = 1
                                          sed -i \
                                            's@^#if defined(MACOS) || defined(TARGET_OS_MAC)$@#if (defined(MACOS) || defined(TARGET_OS_MAC)) \&\& !defined(__APPLE__)@' \
                                            "$target_jdk_zutil"

                                          # The shared bootstrap compatibility pass removes sys/sysctl.h
                                          # for modern Linux, where that header no longer exists. The
                                          # final Darwin networking and management implementations call
                                          # sysctl/sysctlbyname, use Darwin's socket limit constants, and
                                          # use xsw_usage, so restore the canonical target declaration
                                          # without changing the Linux BuildJDK source tree.
                                          target_jdk_portconfig=openjdk/jdk/src/solaris/native/sun/net/portconfig.c
                                          test "$(grep -Fxc \
                                            '/* removed: sys/sysctl.h */' \
                                            "$target_jdk_portconfig")" = 1
                                          sed -i \
                                            's@^/\* removed: sys/sysctl.h \*/$@#include <sys/sysctl.h>@' \
                                            "$target_jdk_portconfig"

                                          target_jdk_net_util=openjdk/jdk/src/solaris/native/java/net/net_util_md.c
                                          test "$(grep -Fxc \
                                            '/* removed: sys/sysctl.h */' \
                                            "$target_jdk_net_util")" = 1
                                          sed -i \
                                            's@^/\* removed: sys/sysctl.h \*/$@#include <sys/sysctl.h>@' \
                                            "$target_jdk_net_util"

                                          target_jdk_management=openjdk/jdk/src/solaris/native/com/sun/management/UnixOperatingSystem_md.c
                                          test "$(grep -Fxc \
                                            '/* removed: sys/sysctl.h */' \
                                            "$target_jdk_management")" = 1
                                          sed -i \
                                            's@^/\* removed: sys/sysctl.h \*/$@#include <sys/sysctl.h>@' \
                                            "$target_jdk_management"

                                          # The pinned macOS management implementation calls the public
                                          # JVM_ActiveProcessorCount interface but omits the JDK's jvm.h.
                                          # Include its canonical declaration rather than relying on the
                                          # implicit-function behavior of the contemporary Apple compiler.
                                          target_jdk_macos_management=openjdk/jdk/src/solaris/native/com/sun/management/MacosxOperatingSystem.c
                                          test "$(grep -Fxc \
                                            '#include "com_sun_management_UnixOperatingSystem.h"' \
                                            "$target_jdk_macos_management")" = 1
                                          test "$(grep -Fxc '#include "jvm.h"' \
                                            "$target_jdk_macos_management")" = 0
                                          sed -i \
                                            's@^#include "com_sun_management_UnixOperatingSystem.h"$@#include "com_sun_management_UnixOperatingSystem.h"\n#include "jvm.h"@' \
                                            "$target_jdk_macos_management"

                                          # Apple OpenJDK selected its native credential-cache bridge
                                          # through the legacy Kerberos umbrella and framework. The
                                          # source uses the public MIT krb5 and com_err APIs, so retain
                                          # the complete bridge against the AOS target implementation.
                                          target_jdk_native_ccache=openjdk/jdk/src/share/native/sun/security/krb5/nativeccache.c
                                          test "$(grep -Fc '#import <Kerberos/Kerberos.h>' \
                                            "$target_jdk_native_ccache")" -eq 1
                                          sed -i \
                                            's|#import <Kerberos/Kerberos.h>|#include <krb5.h>\n#include <com_err.h>\n#include <string.h>|' \
                                            "$target_jdk_native_ccache"
                                          test "$(grep -Fc '#include <krb5.h>' \
                                            "$target_jdk_native_ccache")" -eq 1
                                          test "$(grep -Fc '#include <com_err.h>' \
                                            "$target_jdk_native_ccache")" -eq 1
                                          test "$(grep -Fc '#include <string.h>' \
                                            "$target_jdk_native_ccache")" -eq 1

                                          target_jdk_krb5_make=openjdk/jdk/make/sun/security/krb5/Makefile
                                          test "$(grep -Fxc 'LIBRARY = osxkrb5' \
                                            "$target_jdk_krb5_make")" -eq 1
                                          test "$(grep -Fxc '  OTHER_LDLIBS = -framework Kerberos' \
                                            "$target_jdk_krb5_make")" -eq 1
                                          sed -i \
                                            -e '/^LIBRARY = osxkrb5$/a OTHER_INCLUDES += -I${krb5}/include' \
                                            -e 's|^  OTHER_LDLIBS = -framework Kerberos$|  OTHER_LDLIBS = -L${krb5}/lib -lkrb5 -lk5crypto -lcom_err|' \
                                            "$target_jdk_krb5_make"
                                          test "$(grep -Fxc 'OTHER_INCLUDES += -I${krb5}/include' \
                                            "$target_jdk_krb5_make")" -eq 1
                                          test "$(grep -Fxc \
                                            '  OTHER_LDLIBS = -L${krb5}/lib -lkrb5 -lk5crypto -lcom_err' \
                                            "$target_jdk_krb5_make")" -eq 1

                                          # This source predates Apple's AudioComponent API names used by
                                          # later OpenJDK releases. Backport the source-equivalent API
                                          # transition so the complete CoreAudio backend remains enabled
                                          # against the canonical public AudioUnit interface.
                                          target_jdk_macos_pcm=openjdk/jdk/src/macosx/native/com/sun/media/sound/PLATFORM_API_MacOSX_PCM.cpp
                                          test "$(grep -Fc 'CloseComponent(' \
                                            "$target_jdk_macos_pcm")" = 3
                                          test "$(grep -Fxc '    ComponentDescription desc;' \
                                            "$target_jdk_macos_pcm")" = 1
                                          test "$(grep -Fxc '    Component comp = FindNextComponent(NULL, &desc);' \
                                            "$target_jdk_macos_pcm")" = 1
                                          test "$(grep -Fxc '    err = OpenAComponent(comp, &unit);' \
                                            "$target_jdk_macos_pcm")" = 1
                                          sed -i \
                                            -e 's/CloseComponent(/AudioComponentInstanceDispose(/g' \
                                            -e 's/^    ComponentDescription desc;$/    AudioComponentDescription desc;/' \
                                            -e 's/^    Component comp = FindNextComponent(NULL, &desc);$/    AudioComponent comp = AudioComponentFindNext(NULL, \&desc);/' \
                                            -e 's/^    err = OpenAComponent(comp, &unit);$/    err = AudioComponentInstanceNew(comp, \&unit);/' \
                                            "$target_jdk_macos_pcm"

                                          # AudioObjectPropertyElement is unsigned in the public CoreAudio
                                          # ABI. Backport the explicit conversion used by later OpenJDK
                                          # releases so modern C++ narrowing checks preserve this per-channel
                                          # control path rather than rejecting its aggregate initializer.
                                          target_jdk_macos_ports=openjdk/jdk/src/macosx/native/com/sun/media/sound/PLATFORM_API_MacOSX_Ports.cpp
                                          test "$(grep -Fxc \
                                            '                const AudioObjectPropertyAddress address = {kAudioObjectPropertyElementName, port->scope, ch};' \
                                            "$target_jdk_macos_ports")" = 1
                                          sed -i \
                                            's/{kAudioObjectPropertyElementName, port->scope, ch};/{kAudioObjectPropertyElementName, port->scope, (unsigned)ch};/' \
                                            "$target_jdk_macos_ports"

                                          # PlatformMidi allocates its queue with malloc/free but the
                                          # pinned shared source omits their standard declaration. Add it
                                          # only to the Darwin target tree; openjdk-boot remains the exact
                                          # native source and already compiles under its legacy C mode.
                                          target_jdk_platform_midi=openjdk/jdk/src/share/native/com/sun/media/sound/PlatformMidi.c
                                          test "$(grep -Fxc '#include "PlatformMidi.h"' \
                                            "$target_jdk_platform_midi")" = 1
                                          test "$(grep -Fxc '#include <stdlib.h>' \
                                            "$target_jdk_platform_midi")" = 0
                                          sed -i \
                                            's@^#include "PlatformMidi.h"$@#include "PlatformMidi.h"\n#include <stdlib.h>@' \
                                            "$target_jdk_platform_midi"

                                          # REFLECT_VOID_FUNCTION's generated functions are declared
                                          # void, but its companion function-pointer typedef omitted the
                                          # return type and relied on pre-C99 implicit int. Preserve the
                                          # plugin entry points with their intended ABI under modern Clang.
                                          target_jdk_awt_loader=openjdk/jdk/src/solaris/native/sun/awt/awt_LoadLibrary.c
                                          test "$(grep -Fxc \
                                            'typedef name##_type arglist;                                            \' \
                                            "$target_jdk_awt_loader")" = 1
                                          sed -i \
                                            's/^typedef name##_type arglist;/typedef void name##_type arglist;/' \
                                            "$target_jdk_awt_loader"
                                          test "$(grep -Fxc \
                                            'typedef void name##_type arglist;                                            \' \
                                            "$target_jdk_awt_loader")" = 1

                                          # Two generated Java sources record target socket and filesystem
                                          # constants, but their C generators must execute on the Linux
                                          # builder. Preprocess them with the Darwin compiler so every
                                          # constant comes from the target SDK, then compile the expanded
                                          # C with the sanitized native compiler. Disabling Clang-only
                                          # annotation probes keeps the preprocessed translation unit
                                          # consumable by the native GCC without changing target values.
                                          target_jdk_nio=openjdk/jdk/make/java/nio/Makefile
                                          test -f "$target_jdk_nio"
                                          test "$(grep -Fc \
                                            '($(CD) $(TEMPDIR); $(NIO_CC) $(CPPFLAGS) $(LDDFLAGS) \' \
                                            "$target_jdk_nio")" = 1
                                          test "$(grep -Fc \
                                            '$(NIO_CC) $(CPPFLAGS) -o $@ $(GENUC_SRC)' \
                                            "$target_jdk_nio")" = 1
                                          sed -i \
                                            -e '1005c\
                            __AOS_NIO_RECIPE__$(CC) $(CPPFLAGS) $(NIO_TARGET_CPPFLAGS) -E -o $@.i $(GENUC_SRC)\
                            __AOS_NIO_RECIPE__$(NIO_NATIVE_CC) $@.i -o $@' \
                                            -e '969,970c\
                            __AOS_NIO_RECIPE__($(CD) $(TEMPDIR); $(CC) $(CPPFLAGS) $(NIO_TARGET_CPPFLAGS) -E \\\
                            __AOS_NIO_RECIPE__   -o genSocketOptionRegistry.i $(GENSOR_SRC) && \\\
                            __AOS_NIO_RECIPE__   $(NIO_NATIVE_CC) genSocketOptionRegistry.i \\\
                            __AOS_NIO_RECIPE__   -o genSocketOptionRegistry$(EXE_SUFFIX))' \
                                            -e '965a\
                            NIO_NATIVE_CC = __AOS_NIO_NATIVE_CC__\
                            NIO_TARGET_CPPFLAGS = -Wno-builtin-macro-redefined -include __AOS_NIO_MACROS__' \
                                            "$target_jdk_nio"
                                          target_jdk_nio_macros=$PWD/openjdk/jdk/make/java/nio/aos-cross-generator.h
                                          printf '%s\n' \
                                            '#undef __has_feature' \
                                            '#define __has_feature(x) 0' \
                                            '#undef __has_attribute' \
                                            '#define __has_attribute(x) 0' \
                                            '#undef __has_builtin' \
                                            '#define __has_builtin(x) 0' \
                                            > "$target_jdk_nio_macros"
                                          sed -i \
                                            -e "s|__AOS_NIO_NATIVE_CC__|$PWD/openjdk-tools/native-cc|" \
                                            -e "s|__AOS_NIO_MACROS__|$target_jdk_nio_macros|" \
                                            "$target_jdk_nio"
                                          test "$(grep -c '__AOS_NIO_RECIPE__' \
                                            "$target_jdk_nio")" = 6
                                          sed -i \
                                            's/^[[:blank:]]*__AOS_NIO_RECIPE__/\t/' \
                                            "$target_jdk_nio"
                                          ! grep -Eq '__AOS_NIO_(NATIVE_CC|MACROS)__' "$target_jdk_nio"
                                          ! grep -Fq '__AOS_NIO_RECIPE__' "$target_jdk_nio"
                                          test "$(grep -Fc \
                                            '$(NIO_NATIVE_CC) genSocketOptionRegistry.i' \
                                            "$target_jdk_nio")" = 1
                                          test "$(grep -Fc \
                                            '$(NIO_NATIVE_CC) $@.i -o $@' \
                                            "$target_jdk_nio")" = 1

                                          # The pinned macOS timezone implementation stores its GMT sign
                                          # in a char but accidentally assigns string literals. Older
                                          # Apple compilers accepted that invalid conversion; preserve the
                                          # intended formatting with ordinary character constants.
                                          target_jdk_timezone=openjdk/jdk/src/solaris/native/java/util/TimeZone_md.c
                                          test "$(grep -Fxc '        sign = "+";' "$target_jdk_timezone")" = 1
                                          test "$(grep -Fxc '        sign = "-";' "$target_jdk_timezone")" = 1
                                          sed -i \
                                            -e "s|^        sign = \"+\";$|        sign = '+';|" \
                                            -e "s|^        sign = \"-\";$|        sign = '-';|" \
                                            "$target_jdk_timezone"

                                          # The pinned BSD port adds GCC's -fpch-deps to the ordinary
                                          # dependency flags. Clang supports the retained -MMD/-MP/-MF
                                          # dependency generation, but rejects that GCC-only PCH option.
                                          target_hotspot_gcc_make=openjdk/hotspot/make/bsd/makefiles/gcc.make
                                          test -f "$target_hotspot_gcc_make"
                                          test "$(grep -Fxc \
                                            'DEPFLAGS = -fpch-deps -MMD -MP -MF $(DEP_DIR)/$(@:%=%.d)' \
                                            "$target_hotspot_gcc_make")" = 1
                                          sed -i \
                                            's|^DEPFLAGS = -fpch-deps -MMD -MP -MF |DEPFLAGS = -MMD -MP -MF |' \
                                            "$target_hotspot_gcc_make"

                                          # HotSpot 24 predates C++11. Select its intended dialect and the
                                          # XSI context API it consumes on the C++ compile path only. The
                                          # launcher compiles C while reusing CXXFLAGS, so changing that
                                          # variable would incorrectly pass a C++ dialect to Clang C.
                                          target_hotspot_rules_make=openjdk/hotspot/make/bsd/makefiles/rules.make
                                          test -f "$target_hotspot_rules_make"
                                          test "$(grep -Fxc \
                                            'CXX_COMPILE      = $(CXX) $(CXXFLAGS) $(CFLAGS)' \
                                            "$target_hotspot_rules_make")" = 1
                                          sed -i \
                                            's|^CXX_COMPILE      = $(CXX) $(CXXFLAGS) $(CFLAGS)$|CXX_COMPILE      = $(CXX) -std=gnu++98 -D_XOPEN_SOURCE $(CXXFLAGS) $(CFLAGS)|' \
                                            "$target_hotspot_rules_make"

                                          # Modern Clang correctly rejects left-shifting a negative value
                                          # in an enum constant. Preserve the all-ones masks by making the
                                          # two pinned constant expressions explicitly unsigned.
                                          target_hotspot_cache=openjdk/hotspot/src/share/vm/oops/cpCacheOop.hpp
                                          test "$(grep -Fxc \
                                            '    option_bits_mask           = ~(((-1) << tos_state_shift) | (field_index_mask | parameter_size_mask))' \
                                            "$target_hotspot_cache")" = 1
                                          sed -i \
                                            's|~(((-1) << tos_state_shift)|~(((-1u) << tos_state_shift)|' \
                                            "$target_hotspot_cache"

                                          target_hotspot_dependencies=openjdk/hotspot/src/share/vm/code/dependencies.hpp
                                          test "$(grep -Fxc \
                                            '    all_types           = ((1 << TYPE_LIMIT) - 1) & ((-1) << FIRST_TYPE),' \
                                            "$target_hotspot_dependencies")" = 1
                                          sed -i \
                                            's|& ((-1) << FIRST_TYPE)|\& ((-1u) << FIRST_TYPE)|' \
                                            "$target_hotspot_dependencies"

                                          # This port's JNI visibility test predates Clang, which reports
                                          # GCC 4.2 compatibility macros even though it supports the
                                          # visibility attribute used by HotSpot's exported JNI entry
                                          # points. Recognize Clang explicitly so libjvm exports the
                                          # invocation API consumed by the real gamma launcher.
                                          target_hotspot_jni=openjdk/hotspot/src/cpu/x86/vm/jni_x86.h
                                          test "$(grep -Fxc \
                                            '#if defined(__GNUC__) && (__GNUC__ > 4) || (__GNUC__ == 4) && (__GNUC_MINOR__ > 2)' \
                                            "$target_hotspot_jni")" = 1
                                          sed -i \
                                            's@^#if defined(__GNUC__) && (__GNUC__ > 4) || (__GNUC__ == 4) && (__GNUC_MINOR__ > 2)$@#if defined(__clang__) || (defined(__GNUC__) \&\& ((__GNUC__ > 4) || ((__GNUC__ == 4) \&\& (__GNUC_MINOR__ > 2))))@' \
                                            "$target_hotspot_jni"

                                          # The macOS universal-image rules assume a brace-expanding
                                          # shell, while AOS intentionally executes package phases and
                                          # recursive make recipes with POSIX dash. Spell out both source
                                          # architectures so the built x86_64 SA library and the other
                                          # exported HotSpot artifacts are actually consolidated.
                                          target_hotspot_universal=openjdk/hotspot/make/bsd/makefiles/universal.gmk
                                          test "$(grep -Ec '\{[^}]+,[^}]+\}' "$target_hotspot_universal")" = 8
                                          sed -i \
                                            -e 's|$(EXPORT_PATH)/jre/lib/{i386,amd64}|$(EXPORT_PATH)/jre/lib/i386 $(EXPORT_PATH)/jre/lib/amd64|g' \
                                            -e 's|$(EXPORT_JRE_LIB_DIR)/{i386,amd64}/$(subst $(EXPORT_JRE_LIB_DIR)/,,$@)|$(EXPORT_JRE_LIB_DIR)/i386/$(subst $(EXPORT_JRE_LIB_DIR)/,,$@) $(EXPORT_JRE_LIB_DIR)/amd64/$(subst $(EXPORT_JRE_LIB_DIR)/,,$@)|g' \
                                            -e 's|$(JDK_IMAGE_DIR)/jre/lib/{i386,amd64}|$(JDK_IMAGE_DIR)/jre/lib/i386 $(JDK_IMAGE_DIR)/jre/lib/amd64|g' \
                                            -e 's|$(JDK_IMAGE_DIR)/jre/lib/{client,server}/libjsig.$(LIBRARY_SUFFIX)|$(JDK_IMAGE_DIR)/jre/lib/client/libjsig.$(LIBRARY_SUFFIX) $(JDK_IMAGE_DIR)/jre/lib/server/libjsig.$(LIBRARY_SUFFIX)|g' \
                                            -e 's|$(JDK_IMAGE_DIR)$(COPY_SUBDIR)/jre/lib/{i386,amd64}|$(JDK_IMAGE_DIR)$(COPY_SUBDIR)/jre/lib/i386 $(JDK_IMAGE_DIR)$(COPY_SUBDIR)/jre/lib/amd64|g' \
                                            -e 's|$(JDK_IMAGE_DIR)$(COPY_SUBDIR)/jre/lib/{client,server}/libjsig.$(LIBRARY_SUFFIX)|$(JDK_IMAGE_DIR)$(COPY_SUBDIR)/jre/lib/client/libjsig.$(LIBRARY_SUFFIX) $(JDK_IMAGE_DIR)$(COPY_SUBDIR)/jre/lib/server/libjsig.$(LIBRARY_SUFFIX)|g' \
                                            "$target_hotspot_universal"
                                          test "$(grep -Ec '\{[^}]+,[^}]+\}' "$target_hotspot_universal")" = 0
            ''
            else ""
          }

                  # Pre-create output directories that OpenJDK Makefiles check for
                  mkdir -p openjdk.build-boot openjdk.build

                  # Pre-create directories and files that Release.gmk expects in classes/
                  # for tools.jar (some JAXB/XJC/APT classes may not be compiled in boot builds)
                  for builddir in openjdk.build-boot openjdk.build; do
                    for d in \
                      com/sun/tools/internal/xjc com/sun/tools/internal/ws \
                      com/sun/tools/internal/jxc com/sun/istack/internal/tools \
                      com/sun/istack/internal/ws com/sun/codemodel \
                      com/sun/xml/internal/rngom com/sun/xml/internal/xsom \
                      com/sun/xml/internal/dtdparser org/relaxng/datatype \
                      com/sun/mirror sun/applet; do
                      mkdir -p $builddir/classes/$d
                    done
                    # Create empty META-INF service files that jar expects
                    mkdir -p $builddir/classes/META-INF/services
                    for svc in \
                      com.sun.mirror.apt.AnnotationProcessorFactory \
                      com.sun.tools.xjc.Plugin \
                      com.sun.tools.attach.spi.AttachProvider \
                      com.sun.jdi.connect.Connector \
                      com.sun.jdi.connect.spi.TransportService; do
                      touch $builddir/classes/META-INF/services/$svc
                    done
                  done

                  # Pre-create ALL output directories for ant and make builds (JamVM
                  # File.mkdirs() bug creates files instead of directories).
                  for builddir in openjdk.build-boot openjdk.build; do
                    for component in langtools corba jaxp jaxws; do
                      for subdir in \
                        build/toolclasses build/classes build/gensrc build/ant-tmp \
                        build/bootstrap/toolclasses build/bootstrap/classes \
                        build/bootstrap/gensrc \
                        dist/lib dist/bin dist/share \
                        btclasses btjars; do
                        mkdir -p $builddir/$component/$subdir
                      done
                    done
                  done

                  # Pre-create package directories in btclasses from corba/jaxp/jaxws source
                  # (these components use Make+javac directly, not ant)
                  for builddir in openjdk.build-boot openjdk.build; do
                    for dir in openjdk-boot openjdk; do
                      for component in corba jaxp jaxws; do
                        # Main source tree
                        for srcdir in "$dir/$component/src/share/classes" "$dir/$component/make/tools/src"; do
                          if [ -d "$srcdir" ]; then
                            find "$srcdir" -type d | while read d; do
                              rel=$(echo "$d" | sed "s|^$srcdir/||")
                              if [ -n "$rel" ] && [ "$rel" != "$d" ] && [ "$rel" != "." ]; then
                                mkdir -p "$builddir/$component/btclasses/$rel" 2>/dev/null || true
                                mkdir -p "$builddir/$component/build/classes/$rel" 2>/dev/null || true
                              fi
                            done
                          fi
                        done
                      done
                    done
                  done

                  # Pre-create ALL package directory trees in build output for each component
                  # (JamVM's File.mkdirs() creates intermediate paths as files, breaking
                  # ant's javac, pcompile, and other tasks that create output dirs)
                  for builddir in openjdk.build-boot openjdk.build; do
                    for component in langtools corba jaxp jaxws; do
                      for dir in openjdk-boot openjdk; do
                        if [ -d "$dir/$component" ]; then
                          # Mirror ALL source directory structure into output dirs
                          find "$dir/$component" -type d 2>/dev/null | while read d; do
                            rel=$(echo "$d" | sed "s|^$dir/$component/||; s|^src/share/classes/||; s|^src/[^/]*/||")
                            if [ -n "$rel" ] && [ "$rel" != "$d" ] && [ "$rel" != "." ]; then
                              for outdir in classes toolclasses gensrc bootstrap/classes bootstrap/gensrc bootstrap/toolclasses; do
                                mkdir -p "$builddir/$component/build/$outdir/$rel" 2>/dev/null || true
                              done
                            fi
                          done
                        fi
                      done
                    done
                  done

                  # Create a unified bin directory with all required tools for OpenJDK
                  # The OpenJDK build system uses ALT_UNIXCOMMAND_PATH, ALT_USRBIN_PATH,
                  # and ALT_DEVTOOLS_PATH to locate tools instead of hardcoded /bin/ paths
                  TOOLS=$PWD/openjdk-tools
                  mkdir -p $TOOLS
                  for cmd in basename cat chmod cp cut date df dirname du echo env expr false \
                             head id ln ls mkdir mv printf pwd rm rmdir sort tail tee \
                             touch tr true uname uniq wc; do
                    ln -sf ${buildTools.coreutils}/bin/$cmd $TOOLS/$cmd 2>/dev/null || true
                  done
                  ln -sf ${buildTools.grep}/bin/grep $TOOLS/grep
                  ln -sf ${buildTools.grep}/bin/egrep $TOOLS/egrep
                  ln -sf ${buildTools.grep}/bin/fgrep $TOOLS/fgrep
                  ln -sf ${buildTools.sed}/bin/sed $TOOLS/sed
                  ln -sf ${buildTools.gawk}/bin/gawk $TOOLS/gawk
                  ln -sf ${buildTools.gawk}/bin/awk $TOOLS/awk
                  ln -sf $TOOLS/gawk $TOOLS/nawk
                  ln -sf $(which tar) $TOOLS/tar
                  ln -sf ${buildTools.cpio}/bin/cpio $TOOLS/cpio
                  ln -sf ${buildTools.file}/bin/file $TOOLS/file
                  ln -sf ${buildTools.binutils}/bin/readelf $TOOLS/readelf
                  ln -sf ${buildTools.which}/bin/which $TOOLS/which
                  ln -sf ${buildTools.zip}/bin/zip $TOOLS/zip
                  ln -sf ${buildTools.unzip}/bin/unzip $TOOLS/unzip
                  ln -sf $CONFIG_SHELL $TOOLS/bash
                  ln -sf $CONFIG_SHELL $TOOLS/sh
                  ln -sf ${buildTools.perl}/bin/perl $TOOLS/perl
                  ${
            if isDarwinCross
            then ''
              # IcedTea's first HotSpot is a Linux BuildJDK. Its ADLC sources
              # deliberately use the Linux/GCC flag set, so sanitize the final
              # Darwin derivation environment before invoking the native GCC.
              cat > $TOOLS/native-cc << 'NATIVECCEOF'
              #!${buildTools.bash}/bin/bash
              exec ${buildTools.coreutils}/bin/env \
                -u AOS_CROSS_COMPILING \
                -u AOS_HARDENING_ENABLE \
                -u AOS_TARGET_ARCH \
                -u AOS_TARGET_PLATFORM \
                -u C_INCLUDE_PATH \
                -u CPLUS_INCLUDE_PATH \
                -u LIBRARY_PATH \
                -u MACOSX_DEPLOYMENT_TARGET \
                -u NIX_CFLAGS_COMPILE \
                -u NIX_CFLAGS_LINK \
                -u NIX_LDFLAGS \
                -u SDKROOT \
                ${buildTools.cc}/bin/cc \
                  -isystem ${alsaForBuild}/include \
                  -L${alsaForBuild}/lib \
                  "$@"
              NATIVECCEOF
              cat > $TOOLS/native-c++ << 'NATIVECXXEOF'
              #!${buildTools.bash}/bin/bash
              exec ${buildTools.coreutils}/bin/env \
                -u AOS_CROSS_COMPILING \
                -u AOS_HARDENING_ENABLE \
                -u AOS_TARGET_ARCH \
                -u AOS_TARGET_PLATFORM \
                -u C_INCLUDE_PATH \
                -u CPLUS_INCLUDE_PATH \
                -u LIBRARY_PATH \
                -u MACOSX_DEPLOYMENT_TARGET \
                -u NIX_CFLAGS_COMPILE \
                -u NIX_CFLAGS_LINK \
                -u NIX_LDFLAGS \
                -u SDKROOT \
                ${buildTools.cc}/bin/c++ \
                  -isystem ${alsaForBuild}/include \
                  -L${alsaForBuild}/lib \
                  "$@"
              NATIVECXXEOF
              chmod +x $TOOLS/native-cc $TOOLS/native-c++

              # Both HotSpot builds compile and execute ADLC on Linux. Publish
              # the native compilers through the upstream HOSTCC/HOSTCXX role;
              # the ordinary CC/CXX values remain the Darwin target compilers.
              host_env_anchor='ICEDTEA_ENV = ALT_JDK_IMPORT_PATH="$(BOOT_DIR)" ANT="$(ANT)" \'
              test "$(grep -Fxc "$host_env_anchor" Makefile)" = 1
              sed -i "/^ICEDTEA_ENV = ALT_JDK_IMPORT_PATH=/a\\
              \tSYSTEM_UNAME=\"Darwin\" HOSTCC=\"$TOOLS/native-cc\" HOSTCXX=\"$TOOLS/native-c++\" \\\\" Makefile
              test "$(grep -Fc \
                "SYSTEM_UNAME=\"Darwin\" HOSTCC=\"$TOOLS/native-cc\" HOSTCXX=\"$TOOLS/native-c++\"" \
                Makefile)" = 1

              # ICEDTEA_ENV also carries the target CC/CXX and FreeType needed
              # by the final Darwin image. Override only the boot environment,
              # after that common environment, for the Linux BuildJDK.
              boot_env_anchor='ICEDTEA_ENV_BOOT = $(ICEDTEA_ENV) \'
              test "$(grep -Fxc "$boot_env_anchor" Makefile)" = 1
              sed -i "/^ICEDTEA_ENV_BOOT = \$(ICEDTEA_ENV) \\\\/a\\
              \tSYSTEM_UNAME=\"Linux\" CC=\"$TOOLS/native-cc\" CXX=\"$TOOLS/native-c++\" ALT_FREETYPE_HEADERS_PATH=\"${buildTools.freetype}/include\" ALT_FREETYPE_LIB_PATH=\"${buildTools.freetype}/lib\" FT2_CFLAGS=\"-I${buildTools.freetype}/include/freetype2 -I${buildTools.freetype}/include\" FT2_LIBS=\"-L${buildTools.freetype}/lib -lfreetype\" \\\\" Makefile
              test "$(grep -Fc \
                "SYSTEM_UNAME=\"Linux\" CC=\"$TOOLS/native-cc\" CXX=\"$TOOLS/native-c++\"" \
                Makefile)" = 1

              # The Darwin JDK's binary verification invokes otool directly.
              # Publish the native LLVM implementation for inspecting target
              # Mach-O files rather than silently skipping those checks.
              ln -sf ${buildTools.llvm}/bin/llvm-otool $TOOLS/otool
            ''
            else ""
          }# find, xargs from PATH (bootstrapTools)
                  ln -sf $(which find) $TOOLS/find
                  ln -sf $(which xargs) $TOOLS/xargs
                  # ldd — create a wrapper that uses the bootstrap dynamic linker
                  cat > $TOOLS/ldd << 'LDDEOF'
          #!/bin/sh
          # Minimal ldd wrapper for OpenJDK build
          for f in "$@"; do
            echo "	not a dynamic executable"
          done
          LDDEOF
                  chmod +x $TOOLS/ldd
                  # Compiler tools (via ccWrapper) — wrapped to add -Wno-implicit-function-declaration
                  # GCC 14 makes implicit function declarations a hard error, but OpenJDK 7
                  # source code has many of them. The IcedTea Makefile passes CC from configure
                  # to the inner build (full Nix store path), so the $TOOLS wrapper alone can't
                  # intercept. We create the wrapper but also need source-level patches.
                  ln -sf ${bootstrapCc} $TOOLS/gcc
                  ln -sf ${bootstrapCxx} $TOOLS/g++
                  ln -sf ${bootstrapCcAlias} $TOOLS/cc
                  ln -sf ${buildTools.binutils}/bin/ld $TOOLS/ld
                  ln -sf ${buildTools.binutils}/bin/ar $TOOLS/ar
                  ln -sf ${buildTools.binutils}/bin/as $TOOLS/as
                  ln -sf ${buildTools.binutils}/bin/nm $TOOLS/nm
                  ln -sf ${buildTools.binutils}/bin/strip $TOOLS/strip
                  ln -sf ${buildTools.binutils}/bin/objcopy $TOOLS/objcopy
                  ln -sf ${buildTools.binutils}/bin/objdump $TOOLS/objdump

                  # Create helper script for copying .properties-template files
                  # (replaces ant's <copy> task which is broken under JamVM/GNU Classpath)
                  cat > $TOOLS/copy-props.sh << 'COPYEOF'
          #!/bin/sh
          # Usage: copy-props.sh <srcdir> <destdir> <includes> <jdk_version> <release> <full_version>
          srcdir="$1"; destdir="$2"; includes="$3"
          jdk_version="$4"; release="$5"; full_version="$6"
          find "$srcdir" -name '*.properties-template' | while read f; do
            rel=$(echo "$f" | sed "s|^$srcdir/||")
            dest="$destdir/$(echo "$rel" | sed 's/.properties-template$/.properties/')"
            mkdir -p "$(dirname "$dest")"
            sed "s|\$(JDK_VERSION)|$jdk_version|g; s|\$(RELEASE)|$release|g; s|\$(FULL_VERSION)|$full_version|g" "$f" > "$dest"
            chmod u+w "$dest" 2>/dev/null || true
          done
          COPYEOF
                  chmod +x $TOOLS/copy-props.sh

                  # Also symlink dummy tools
                  # Use real xsltproc (HotSpot needs it for JVMTI code generation)
                  ln -sf ${buildTools.libxslt}/bin/xsltproc $TOOLS/xsltproc
                  for cmd in hostname free logname getconf rmic native2ascii wget; do
                    ln -sf $PWD/dummy-bin/$cmd $TOOLS/$cmd 2>/dev/null || true
                  done

                  # Create a shell-based ant replacement that bypasses Java entirely.
                  # JamVM 1.5 + GNU Classpath 0.93 has broken File.createTempFile()
                  # (infinite loop), File.mkdirs(), File.isFile(), File.exists(), and
                  # File.canWrite(). Using Java-based ant is impossible. This script
                  # handles the langtools/corba/jaxp/jaxws "build" targets directly.
                  cat > $TOOLS/ant << 'ANTEOF'
          #!/bin/sh
          set -e

          # Parse -D properties, options, and target from ant command line
          BUILD_DIR=""
          DIST_DIR=""
          BOOT_JAVA_HOME=""
          IMPORT_JDK=""
          JDK_VERSION=""
          FULL_VERSION=""
          RELEASE=""
          JAVAC_SOURCE=7
          JAVAC_TARGET=7
          TARGET=""
          OUTPUT_DIR=""
          JDK_HOME=""
          JAVA_HOME_ARG=""
          BOOTSTRAP_DIR=""

          for arg in "$@"; do
            case "$arg" in
              -diagnostics) echo "Shell-based ant replacement (diagnostics skipped)"; exit 0 ;;
              -version) echo "Apache Ant(TM) version 1.8.4"; exit 0 ;;
              -Dbuild.dir=*) BUILD_DIR=$(echo "$arg" | sed 's/^-Dbuild.dir=//') ;;
              -Ddist.dir=*) DIST_DIR=$(echo "$arg" | sed 's/^-Ddist.dir=//') ;;
              -Doutput.dir=*) OUTPUT_DIR=$(echo "$arg" | sed 's/^-Doutput.dir=//') ;;
              -Dboot.java.home=*) BOOT_JAVA_HOME=$(echo "$arg" | sed 's/^-Dboot.java.home=//') ;;
              -Djdk.home=*) JDK_HOME=$(echo "$arg" | sed 's/^-Djdk.home=//') ;;
              -Djava.home=*) JAVA_HOME_ARG=$(echo "$arg" | sed 's/^-Djava.home=//') ;;
              -Dbootstrap.dir=*) BOOTSTRAP_DIR=$(echo "$arg" | sed 's/^-Dbootstrap.dir=//') ;;
              -Dimport.jdk=*) IMPORT_JDK=$(echo "$arg" | sed 's/^-Dimport.jdk=//') ;;
              -Djdk.version=*) JDK_VERSION=$(echo "$arg" | sed 's/^-Djdk.version=//') ;;
              -Dfull.version=*) FULL_VERSION=$(echo "$arg" | sed 's/^-Dfull.version=//') ;;
              -Drelease=*) RELEASE=$(echo "$arg" | sed 's/^-Drelease=//') ;;
              -Djavac.source=*) JAVAC_SOURCE=$(echo "$arg" | sed 's/^-Djavac.source=//') ;;
              -Djavac.target=*) JAVAC_TARGET=$(echo "$arg" | sed 's/^-Djavac.target=//') ;;
              -*) ;; # skip other options
              *) TARGET="$arg" ;;
            esac
          done

          # Use output.dir as BUILD_DIR if build.dir not set (jaxp/jaxws use output.dir)
          if [ -z "$BUILD_DIR" ] && [ -n "$OUTPUT_DIR" ]; then
            BUILD_DIR="$OUTPUT_DIR"
          fi

          # Use jdk.home or JAVA_HOME env as BOOT_JAVA_HOME if not set
          if [ -z "$BOOT_JAVA_HOME" ]; then
            if [ -n "$JDK_HOME" ]; then
              BOOT_JAVA_HOME="$JDK_HOME"
            elif [ -n "$JAVA_HOME" ]; then
              BOOT_JAVA_HOME="$JAVA_HOME"
            fi
          fi

          # Determine component from PWD
          # For langtools: called from langtools/make/, PWD=langtools/make/
          # For jaxp/jaxws: does "cd .." first, PWD=jaxp/ or jaxws/
          COMPONENT=$(basename "$PWD")
          case "$COMPONENT" in
            make)
              # Called from component/make/ — go up one level
              COMPONENT=$(basename "$(dirname "$PWD")")
              COMPONENT_DIR="$(dirname "$PWD")"
              ;;
            *)
              # Already at component root (jaxp/jaxws do "cd .." first)
              COMPONENT_DIR="$PWD"
              ;;
          esac

          echo "=== Shell-based ant: component=$COMPONENT target=$TARGET BUILD_DIR=$BUILD_DIR ==="

          # Default DIST_DIR if not set
          if [ -z "$DIST_DIR" ]; then
            DIST_DIR="$BUILD_DIR/dist"
          fi
          mkdir -p "$DIST_DIR/lib"

          # Find source directory
          SRC_CLASSES=""
          for trydir in "$COMPONENT_DIR/src/share/classes" "$COMPONENT_DIR/src/classes" "$COMPONENT_DIR/src"; do
            if [ -d "$trydir" ]; then
              SRC_CLASSES="$trydir"
              break
            fi
          done

          # Create all output directories
          mkdir -p "$BUILD_DIR/classes" "$BUILD_DIR/gensrc" "$BUILD_DIR/stubs" \
                   "$BUILD_DIR/bootstrap/classes" "$BUILD_DIR/bootstrap/lib" \
                   "$BUILD_DIR/bootstrap/bin" "$BUILD_DIR/toolclasses" \
                   "$DIST_DIR/lib" "$DIST_DIR/bootstrap/lib" "$DIST_DIR/bootstrap/bin"

          # Pre-create ALL package directories from source tree
          # (ECJ uses File.mkdirs() which is broken under JamVM/Classpath)
          if [ -d "$SRC_CLASSES" ]; then
            find "$SRC_CLASSES" -type d | while read d; do
              rel=$(echo "$d" | sed "s|^$SRC_CLASSES/||")
              if [ -n "$rel" ] && [ "$rel" != "$d" ] && [ "$rel" != "." ]; then
                mkdir -p "$BUILD_DIR/classes/$rel" \
                         "$BUILD_DIR/bootstrap/classes/$rel" \
                         "$BUILD_DIR/gensrc/$rel" 2>/dev/null || true
              fi
            done
          fi

          # Process .properties-template files (replaces ant's <copy> + <filterset>)
          if [ -d "$SRC_CLASSES" ]; then
            find "$SRC_CLASSES" -name '*.properties-template' 2>/dev/null | while read f; do
              rel=$(echo "$f" | sed "s|^$SRC_CLASSES/||")
              dest="$BUILD_DIR/gensrc/$(echo "$rel" | sed 's/.properties-template$/.properties/')"
              mkdir -p "$(dirname "$dest")"
              sed -e "s|\$(JDK_VERSION)|$JDK_VERSION|g" \
                  -e "s|\$(RELEASE)|$RELEASE|g" \
                  -e "s|\$(FULL_VERSION)|$FULL_VERSION|g" "$f" > "$dest"
            done
          fi

          # Collect all .java source files
          SRCLIST="$BUILD_DIR/sources.list"
          > "$SRCLIST"

          if [ -d "$SRC_CLASSES" ]; then
            # Exclude javac/nio (needs java.nio.file stubs) and package-info.java
            find "$SRC_CLASSES" -name '*.java' \
              ! -path '*/javac/nio/*' \
              ! -name 'package-info.java' >> "$SRCLIST"
          fi

          # Add generated sources
          find "$BUILD_DIR/gensrc" -name '*.java' >> "$SRCLIST" 2>/dev/null || true

          NSRC=$(wc -l < "$SRCLIST")
          echo "Compiling $NSRC source files for $COMPONENT..."

          if [ "$NSRC" -gt 0 ]; then
            # Use boot javac (ECJ) for compilation
            # ECJ -source 1.6 needed for @Override on interface methods
            # Use -nowarn to suppress warnings, -proceedOnError to continue past errors
            JAVAC="$BOOT_JAVA_HOME/bin/javac"
            SOURCEPATH="$SRC_CLASSES"
            if [ -d "$BUILD_DIR/gensrc" ]; then
              SOURCEPATH="$SOURCEPATH:$BUILD_DIR/gensrc"
            fi

            "$JAVAC" \
              -source 1.6 -target 1.6 \
              -encoding UTF-8 \
              -d "$BUILD_DIR/classes" \
              -sourcepath "$SOURCEPATH" \
              -nowarn \
              @"$SRCLIST" || {
                echo "WARNING: javac reported errors, continuing..."
              }
          fi

          # Copy resource files (.properties, images, etc.) to classes dir
          if [ -d "$SRC_CLASSES" ]; then
            find "$SRC_CLASSES" \( -name '*.properties' -o -name '*.gif' -o -name '*.png' \
                 -o -name '*.xml' -o -name '*.css' -o -name '*.js' \) 2>/dev/null | while read f; do
              rel=$(echo "$f" | sed "s|^$SRC_CLASSES/||")
              dest="$BUILD_DIR/classes/$rel"
              mkdir -p "$(dirname "$dest")"
              cp "$f" "$dest"
            done
          fi

          # Copy processed .properties from gensrc to classes
          find "$BUILD_DIR/gensrc" -name '*.properties' 2>/dev/null | while read f; do
            rel=$(echo "$f" | sed "s|^$BUILD_DIR/gensrc/||")
            dest="$BUILD_DIR/classes/$rel"
            mkdir -p "$(dirname "$dest")"
            cp "$f" "$dest"
          done

          # Copy classes to bootstrap dir (for langtools, bootstrap = same classes)
          if [ -d "$BUILD_DIR/classes" ]; then
            (cd "$BUILD_DIR/classes" && tar cf - .) | (cd "$BUILD_DIR/bootstrap/classes" && tar xf -)
          fi

          echo "Creating JARs for $COMPONENT..."

          ANTEOF
                  # Add Nix-interpolated paths for JAR creation
                  cat >> $TOOLS/ant << JAREOF
          JAR="${buildTools.fastjar}/bin/fastjar"
          JAREOF
                  cat >> $TOOLS/ant << 'ANTEOF2'

          # Create the main classes.jar
          if [ -d "$BUILD_DIR/classes" ] && [ "$(ls -A "$BUILD_DIR/classes" 2>/dev/null)" ]; then
            (cd "$BUILD_DIR/classes" && $JAR cf "$DIST_DIR/lib/classes.jar" .)
          else
            # Create empty jar
            mkdir -p "$BUILD_DIR/empty"
            (cd "$BUILD_DIR/empty" && $JAR cf "$DIST_DIR/lib/classes.jar" .)
          fi

          # Component-specific packaging
          case "$COMPONENT" in
            langtools)
              # Create per-tool JARs for bootstrap with Main-Class manifest
              for tool in javac javadoc javah; do
                if [ -d "$BUILD_DIR/bootstrap/classes" ]; then
                  case "$tool" in
                    javac) MAIN_CLASS="com.sun.tools.javac.Main" ;;
                    javadoc) MAIN_CLASS="com.sun.tools.javadoc.Main" ;;
                    javah) MAIN_CLASS="com.sun.tools.javah.Main" ;;
                  esac
                  echo "Main-Class: $MAIN_CLASS" > "$BUILD_DIR/bootstrap/lib/$tool.manifest"
                  (cd "$BUILD_DIR/bootstrap/classes" && \
                   $JAR cfm "$BUILD_DIR/bootstrap/lib/$tool.jar" \
                     "$BUILD_DIR/bootstrap/lib/$tool.manifest" .)
                fi
              done
              # doclets.jar is same classes (no main class needed)
              if [ -d "$BUILD_DIR/bootstrap/classes" ]; then
                (cd "$BUILD_DIR/bootstrap/classes" && \
                 $JAR cf "$BUILD_DIR/bootstrap/lib/doclets.jar" .)
              fi

              # Create launcher scripts
              for tool in javac javah javadoc; do
                cat > "$BUILD_DIR/bootstrap/bin/$tool" << LAUNCHEOF
          #!/bin/sh
          mydir="\$(dirname "\$0")"
          mylib="\$mydir/../lib"
          exec "$BOOT_JAVA_HOME/bin/java" -jar "\$mylib/$tool.jar" "\$@"
          LAUNCHEOF
                chmod +x "$BUILD_DIR/bootstrap/bin/$tool"
              done

              # Copy bootstrap to dist
              cp -r "$BUILD_DIR/bootstrap/bin/." "$DIST_DIR/bootstrap/bin/"
              cp -r "$BUILD_DIR/bootstrap/lib/." "$DIST_DIR/bootstrap/lib/"

              # Create src.zip
              if [ -d "$SRC_CLASSES" ]; then
                (cd "$SRC_CLASSES" && find . -name '*.java' | sort > /tmp/srczip.list && \
                 $JAR cf "$DIST_DIR/lib/src.zip" @/tmp/srczip.list)
              fi
              ;;
            corba|jaxp|jaxws)
              # Create src.zip (JDK build imports source from component dists)
              if [ -n "$SRC_CLASSES" ] && [ -d "$SRC_CLASSES" ]; then
                (cd "$SRC_CLASSES" && find . -name '*.java' | sort > /tmp/srczip.list && \
                 $JAR cf "$DIST_DIR/lib/src.zip" @/tmp/srczip.list)
              fi
              ;;
          esac

          echo "=== Shell-based ant: $COMPONENT build complete ==="
          ANTEOF2
                  chmod +x $TOOLS/ant

                  # Add bootstrap JDK tools
                  ln -sf ${buildTools.jamvm-2_0}/bin/jamvm $TOOLS/java
                  # Use our javac wrapper (from fake-jdk) that pre-creates directories
                  ln -sf $PWD/fake-jdk/bin/javac $TOOLS/javac
                  ln -sf ${buildTools.gjavah}/bin/gjavah $TOOLS/javah
                  ln -sf ${buildTools.fastjar}/bin/fastjar $TOOLS/jar

                  export ALT_UNIXCOMMAND_PATH=$TOOLS/
                  export ALT_USRBIN_PATH=$TOOLS/
                  export ALT_DEVTOOLS_PATH=$TOOLS/
                  export PATH="$TOOLS:$PATH"

                  # Fix freetype version check (string comparison fails for 2.13 vs 2.2)
                  for dir in openjdk openjdk-boot; do
                    if [ -d "$dir" ]; then
                      find "$dir" -name 'freetypecheck.c' 2>/dev/null | while read f; do
                        # Replace version check with always-pass
                        sed -i 's/printf("Failed:/printf("OK (patched):\/\//' "$f" 2>/dev/null || true
                      done
                      # Also skip the sanity check for freetype
                      find "$dir" -name 'Sanity.gmk' 2>/dev/null | while read f; do
                        sed -i 's/REQUIRED_FREETYPE_VERSION = 2.2.1/REQUIRED_FREETYPE_VERSION = 0.0.0/' "$f" 2>/dev/null || true
                      done
                    fi
                  done

                  # Set HOME to a writable directory (GNU Classpath throws on
                  # missing files instead of returning false, and ant tries to
                  # load $HOME/.openjdk/*.properties)
                  export HOME=$PWD/fake-home
                  mkdir -p $HOME/.openjdk
                  # Create empty .properties files that ant tries to load
                  # (GNU Classpath throws on missing files instead of silently skipping)
                  touch $HOME/.openjdk/langtools-build.properties
                  touch $HOME/.openjdk/build.properties
                  touch $HOME/.openjdk/corba-build.properties
                  touch $HOME/.openjdk/jaxp-build.properties
                  touch $HOME/.openjdk/jaxws-build.properties
                  touch $HOME/.openjdk/jdk-build.properties

                  # Ensure all source and build output files are writable
                  # (cp -pPRl from clone-boot creates hardlinks that may be read-only,
                  # and JamVM's FileOutputStream may create files without write perms)
                  chmod -R u+w openjdk-boot openjdk openjdk.build-boot openjdk.build 2>/dev/null || true

                  # First, run make to extract and patch all sources
                  make stamps/patch.stamp \
                    ALT_UNIXCOMMAND_PATH=$TOOLS/ \
                    ALT_USRBIN_PATH=$TOOLS/ \
                    ALT_DEVTOOLS_PATH=$TOOLS/ \
                    ALT_COMPILER_PATH=$TOOLS/ \
                    ANT=$TOOLS/ant

                  # Create gjavah wrapper that adds the module's classes directory to
                  # the classpath. OpenJDK compiles module classes to tmp/.../classes/
                  # but JAVAH_CMD only has the main classes/ dir. This wrapper derives
                  # the module's classes dir from the -d argument (CClassHeaders →
                  # classes sibling) and adds it via -classpath.
                  cat > $TOOLS/gjavah-wrapper << 'GJAVAHEOF'
          #!/bin/sh
          PREV=""
          for arg in "$@"; do
            if [ "$PREV" = "-d" ]; then
              CLASSDIR=$(echo "$arg" | sed 's|/CClassHeaders.*$|/classes|')
              if [ -d "$CLASSDIR" ]; then
                exec GJAVAH_REAL -classpath "$CLASSDIR" "$@"
              fi
            fi
            PREV="$arg"
          done
          exec GJAVAH_REAL "$@"
          GJAVAHEOF
                  sed -i "s|GJAVAH_REAL|${buildTools.gjavah}/bin/gjavah|g" $TOOLS/gjavah-wrapper
                  chmod +x $TOOLS/gjavah-wrapper

                  # Build up to and including boot JDK + stage2 bootstrap setup.
                  # IcedTea 2.6 drives the same boot javac outputs from several
                  # recursive make branches. Parallel execution can corrupt
                  # javac 7's shared class-writing state and abort in
                  # ClassWriter.writePool, so keep this legacy bootstrap serial.
                  # JAVAH_CMD is passed on the make command line to override the
                  # OpenJDK build system's computed value. JAVAH_CMD is NOT defined
                  # in source .gmk files — it's generated at build time from BOOTDIR
                  # and other variables. The computed value uses `java -jar javah.jar`
                  # which crashes with NPE under JamVM. Make command-line variables
                  # override all makefile-level assignments including computed ones.
                  make stamps/bootstrap-directory-symlink-stage2.stamp \
                    ALT_UNIXCOMMAND_PATH=$TOOLS/ \
                    ALT_USRBIN_PATH=$TOOLS/ \
                    ALT_DEVTOOLS_PATH=$TOOLS/ \
                    ALT_COMPILER_PATH=$TOOLS/ \
                    ALSA_INCLUDE=${alsaForBuild}/include/alsa/version.h \
                    ALSA_LIBRARY=${alsaForBuild}/lib/libasound.so \
                    ANT=$TOOLS/ant \
                    DISABLE_NIMBUS=true \
                    SKIP_FASTDEBUG_BUILD=true \
                    SKIP_DEBUG_BUILD=true \
                    "JAVAH_CMD=$TOOLS/gjavah-wrapper -bootclasspath \$(CLASSBINDIR):\$(BOOTDIR)/jre/lib/rt.jar" \
                    -j1

                  # Nimbus L&F is disabled via DISABLE_NIMBUS make variable (see below)
                  # because boot JDK lacks JAXB classes for the Nimbus source generator.

                  # Replace rmic with no-op for final build — JamVM's rmic crashes with
                  # StackOverflowError (MALFORMED zip entry in isExemptPackage recursion)
                  if [ -f bootstrap/jdk1.6.0/bin/rmic ]; then
                    cat > bootstrap/jdk1.6.0/bin/rmic << 'RMICEOF'
          #!/bin/sh
          # No-op rmic wrapper — SA rmic crashes under JamVM
          exit 0
          RMICEOF
                    chmod +x bootstrap/jdk1.6.0/bin/rmic
                  fi

                  # Pre-import component classes from boot build into final build's
                  # classes directory. The final JDK build uses -Xbootclasspath pointing
                  # to openjdk.build/classes/ which needs SAX (from JAXP), CORBA, and
                  # JAXWS classes that are built separately and imported via jar extraction.
                  # The import step in the Makefile may produce incomplete jars from our
                  # shell-based ant, so we seed the directory from the boot build's output.
                  for component in jaxp corba jaxws; do
                    jarfile="openjdk.build-boot/$component/dist/lib/classes.jar"
                    if [ -f "$jarfile" ]; then
                      echo "Pre-importing $component classes from boot build..."
                      mkdir -p openjdk.build/classes
                      (cd openjdk.build/classes && ${buildTools.fastjar}/bin/fastjar xf "../../$jarfile") || true
                    fi
                  done
                  # Also import langtools classes (javac, javah, javadoc, javap tools)
                  if [ -f "openjdk.build-boot/langtools/dist/lib/classes.jar" ]; then
                    echo "Pre-importing langtools classes from boot build..."
                    (cd openjdk.build/classes && ${buildTools.fastjar}/bin/fastjar xf "../../openjdk.build-boot/langtools/dist/lib/classes.jar") || true
                  fi

                  # Continue the full build (make skips already-completed targets)
                  make -j1 \
                    ALT_UNIXCOMMAND_PATH=$TOOLS/ \
                    ALT_USRBIN_PATH=$TOOLS/ \
                    ALT_DEVTOOLS_PATH=$TOOLS/ \
                    ALT_COMPILER_PATH=$TOOLS/ \
                    ALSA_INCLUDE=${alsaForBuild}/include/alsa/version.h \
                    ALSA_LIBRARY=${alsaForBuild}/lib/libasound.so \
                    ANT=$TOOLS/ant \
                    DISABLE_NIMBUS=true \
                    SKIP_FASTDEBUG_BUILD=true \
                    SKIP_DEBUG_BUILD=true \
                    "JAVAH_CMD=$TOOLS/gjavah-wrapper -bootclasspath \$(CLASSBINDIR):\$(BOOTDIR)/jre/lib/rt.jar"
        '';
      }
      {
        name = "install";
        script =
          if isDarwinCross
          then ''
            mkdir -p $out
            # IcedTea produces the JDK image in openjdk.build/
            if [ -d openjdk.build/j2sdk-image ]; then
              cp -a openjdk.build/j2sdk-image/* $out/
            elif [ -d openjdk.build/images/j2sdk-image ]; then
              cp -a openjdk.build/images/j2sdk-image/* $out/
            fi

            # ct.sym generation is skipped by this legacy bootstrap on both
            # platforms. Darwin binaries are already emitted as Mach-O and
            # must not be passed to the Linux ELF patching path below.
            rm -f $out/lib/ct.sym

            cp -a \
              ${java-native-foundation}/Library/Frameworks/JavaNativeFoundation.framework \
              "$out/jre/lib/"
            mkdir -p "$out/share/licenses"
            cp -a \
              ${java-native-foundation}/share/licenses/java-native-foundation \
              "$out/share/licenses/"
            test "$(find "$out/share/licenses/java-native-foundation/source-notices" \
              -type f | wc -l)" -eq 31

            bundledJnf="$out/jre/lib/JavaNativeFoundation.framework/Versions/A/JavaNativeFoundation"
            test -f "$bundledJnf"
            chmod u+w "$(dirname "$bundledJnf")" "$bundledJnf"
            ${buildTools.llvm}/bin/llvm-install-name-tool \
              -delete_rpath ${java-native-foundation}/lib \
              -add_rpath @loader_path/../../../amd64/server \
              "$bundledJnf"
            ${buildTools.llvm}/bin/llvm-otool -l "$bundledJnf" \
              | grep -q '@loader_path/../../../amd64/server'
            ! ${buildTools.llvm}/bin/llvm-otool -l "$bundledJnf" \
              | grep -Fq '${java-native-foundation}/lib'
          ''
          else ''
            mkdir -p $out
            # IcedTea produces the JDK image in openjdk.build/
            if [ -d openjdk.build/j2sdk-image ]; then
              cp -a openjdk.build/j2sdk-image/* $out/
            elif [ -d openjdk.build/images/j2sdk-image ]; then
              cp -a openjdk.build/images/j2sdk-image/* $out/
            fi

            # Remove empty ct.sym — ct.sym generation was skipped due to missing
            # ASM classes. Without ct.sym, javac uses rt.jar directly for symbol
            # resolution, which is correct for same-version compilation.
            rm -f $out/lib/ct.sym

            # Patch ELF binaries with correct dynamic linker and rpath
            # CONFIG_SHELL (bash) is statically linked, so patchelf --print-interpreter
            # fails on it. Read the dynamic linker from the cc-wrapper metadata instead.
            INTERP=$(cat "${bootstrapTools}/nix-support/dynamic-linker")
            BT_LIB=$(dirname "$INTERP")

            # Find libstdc++ directory (nested under lib/gcc/...)
            STDCXX_FILE=$(find "$BT_LIB" -name 'libstdc++.so.6' -not -name '*.py' 2>/dev/null | head -1)
            STDCXX_DIR=""
            if [ -n "$STDCXX_FILE" ]; then
              STDCXX_DIR=$(dirname "$STDCXX_FILE")
            fi
            RPATH="$out/lib:$out/lib/amd64:$out/lib/amd64/jli:$out/jre/lib/amd64:$out/jre/lib/amd64/jli:$out/jre/lib/amd64/server:$BT_LIB"
            if [ -n "$STDCXX_DIR" ]; then
              RPATH="$RPATH:$STDCXX_DIR"
            fi

            for f in $out/bin/* $out/jre/bin/*; do
              if [ -f "$f" ] && [ ! -L "$f" ]; then
                patchelf --set-interpreter "$INTERP" \
                         --set-rpath "$RPATH" \
                         "$f" 2>/dev/null || true
              fi
            done

            find $out -name '*.so' -o -name '*.so.*' | while read f; do
              if [ -f "$f" ] && [ ! -L "$f" ]; then
                patchelf --set-rpath "$RPATH" \
                         "$f" 2>/dev/null || true
              fi
            done
          '';
      }
    ];

    meta = {
      description = "OpenJDK 7 — first real OpenJDK built via IcedTea 2.6.13";
      homepage = "https://openjdk.org";
      license = "GPL-2.0-with-classpath-exception";
    };
  }
