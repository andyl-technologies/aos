##! MIT Kerberos — GSSAPI authentication and Kerberos network services
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  perl,
  openssl,
  bash,
  stdenv,
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

    buildDeps = [gnumake pkg-config perl];
    runtimeDeps =
      [openssl]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
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
            $configureFlags \
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
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            for script in compile_et k5srvutil krb5-send-pr; do
              [ -f "$out/bin/$script" ] || continue
              sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/$script"
            done
          ''
          else ''
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
