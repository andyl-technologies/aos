##! OpenLDAP — LDAP client libraries, tools, and directory server
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libtool,
  cyrus-sasl,
  krb5,
  openssl,
}: let
  version = "2.6.10";
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

    buildDeps = [gnumake pkg-config libtool];
    runtimeDeps = [cyrus-sasl krb5 openssl libtool];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd openldap-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
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
          # OpenLDAP uses soelim only to flatten pre-generated manual pages.
          # Supply the same hermetic passthrough used by other AOS packages;
          # no host groff tooling is consulted.
          mkdir -p .aos-build-tools
          printf '#!%s\nexec cat "$@"\n' "$CONFIG_SHELL" > .aos-build-tools/soelim
          chmod +x .aos-build-tools/soelim
          export PATH="$PWD/.aos-build-tools:$PATH"
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
