##! MIT Kerberos — GSSAPI authentication and Kerberos network services
{
  mkDerivation,
  fetchurl,
  gnumake,
  bison,
  pkg-config,
  perl,
  openssl,
}: let
  version = "1.22.1";
in
  mkDerivation {
    pname = "krb5";
    inherit version;

    src = fetchurl {
      urls = [
        "https://kerberos.org/dist/krb5/1.22/krb5-${version}.tar.gz"
      ];
      hash = "sha256-GogyuMrZI+u/E5T2fi789B46SfRgKFpm41reyPoAU68=";
    };

    buildDeps = [gnumake bison pkg-config perl];
    runtimeDeps = [openssl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd krb5-${version}/src
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --enable-shared \
            --with-crypto-impl=openssl \
            --with-tls-impl=openssl
        '';
      }
      {
        name = "build";
        script = ''
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
        pname = "tool-krb5-config";
        tool = self;
        command = "krb5-config --version";
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libkrb5.so" "libgssapi_krb5.so"];
      };
    };

    meta = {
      description = "MIT Kerberos and GSSAPI implementation";
      homepage = "https://web.mit.edu/kerberos/";
      license = "MIT";
    };
  }
