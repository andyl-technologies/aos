##! OpenLDAP — LDAP client libraries, tools, and directory server
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  file,
  libtool,
  cyrus-sasl,
  krb5,
  openssl,
  buildPackages,
  stdenv,
}: let
  version = "2.6.10";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
in
  mkDerivation {
    pname = "openldap";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${version}.tgz"
      ];
      hash = "sha256-wGXwSq1Cc3rr1gsv5JOXBKyEQma8CuqhYJ8MrZh75RY=";
    };

    buildDeps = [gnumake pkg-config file];
    runtimeDeps = [libtool cyrus-sasl krb5 openssl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd openldap-${version}

          # Libtool's generated configure probe must use AOS's native file
          # utility; the upstream FHS path is neither present nor permitted.
          sed -i 's|/usr/bin/file|${buildPackages.file}/bin/file|g' configure
        '';
      }
      {
        name = "configure";
        script =
          if isDarwinCross
          then ''
            # Autoconf pessimistically selects OpenLDAP's internal memcmp
            # replacement whenever it cannot execute a target probe.  That
            # replacement lives in the server-only liblutil archive, leaving
            # the public Darwin libldap dylib with an unresolved
            # lutil_memcmp. Darwin's libc memcmp is conforming.
            ac_cv_func_memcmp_working=yes ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-dynamic \
              --enable-modules \
              --enable-slapd \
              --enable-overlays=mod \
              --with-cyrus-sasl \
              --with-tls=openssl \
              --with-yielding-select=yes

            # OpenLDAP's bundled Libtool predates macOS 11, so its deployment
            # target case leaves allow_undefined_flag empty.  Slapd backends
            # and overlays are bundles whose host symbols are intentionally
            # resolved when slapd loads them; keep ordinary dylibs strict and
            # restore dynamic lookup only for Libtool's module commands.
            sed -i \
              -e '/^module_cmds=/s/$allow_undefined_flag/-Wl,-undefined,dynamic_lookup/' \
              -e '/^module_expsym_cmds=/s/$allow_undefined_flag/-Wl,-undefined,dynamic_lookup/' \
              libtool
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-dynamic \
              --enable-modules \
              --enable-slapd \
              --enable-overlays=mod \
              --with-cyrus-sasl \
              --with-tls=openssl
          '';
      }
      {
        name = "build";
        script = ''
          # Upstream's version generator otherwise embeds the sandbox hostname
          # and build directory into every client and server executable.
          SOURCE_DATE_EPOCH=1
          export SOURCE_DATE_EPOCH

          # OpenLDAP expands shared roff fragments while generating its manual
          # pages.  AOS does not yet package groff's soelim, so provide the
          # small part of its behavior used here instead of dropping the docs.
          mkdir -p "$TMPDIR/openldap-tools"
          printf '#!%s\n' "$CONFIG_SHELL" > "$TMPDIR/openldap-tools/soelim"
          cat >> "$TMPDIR/openldap-tools/soelim" <<'EOF'
          expandSoelim() {
            while IFS= read -r line; do
              case "$line" in
                '.so '*)
                  includePath=''${line#'.so '}
                  expandSoelim < "$includePath"
                  ;;
                *) printf '%s\n' "$line" ;;
              esac
            done
          }

          case "''${1:-}" in
            "" | -) expandSoelim ;;
            *)
              for inputPath in "$@"; do
                expandSoelim < "$inputPath"
              done
              ;;
          esac
          EOF
          chmod +x "$TMPDIR/openldap-tools/soelim"
          PATH="$TMPDIR/openldap-tools:$PATH"
          export PATH

          make -j$NIX_BUILD_CORES depend
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      cli = testing.mkToolCheck {
        pname = "tool-openldap";
        tool = self;
        command = "slapd -VV";
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libldap.so" "liblber.so"];
      };
    };

    meta = {
      description = "OpenLDAP client libraries, tools, and directory server";
      homepage = "https://www.openldap.org/";
      license = "OLDAP-2.8";
    };
  }
