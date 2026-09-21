##! gpgme — High-level API for GnuPG operations
{
  mkDerivation,
  lib,
  stdenv,
  bash,
  fetchurl,
  gnumake,
  pkg-config,
  texinfo,
  gnupg,
  libassuan,
  libgpg-error,
  npth,
  glib,
}: let
  version = "2.2.0";
in
  mkDerivation {
    pname = "gpgme";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnupg.org/ftp/gcrypt/gpgme/gpgme-${version}.tar.bz2"
      ];
      hash = "sha256-cWDoDoTa/QDZVshIkcUzu3qxampU++FXSy86zwSWl3s=";
    };

    buildDeps = [gnumake pkg-config texinfo gnupg libgpg-error];
    runtimeDeps = [libassuan libgpg-error npth glib] ++ lib.optional (stdenv.isCross && stdenv.hostPlatform.isLinux) bash;
    propagatedDeps = [libassuan libgpg-error];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd gpgme-${version}
        '';
      }
      {
        name = "configure";
        script =
          lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # The native libgpg-error supplies yat2m, but its config helper would
            # select native libraries. Resolve target metadata with the build shell.
            mkdir -p .aos-build-tools
            cat > .aos-build-tools/gpgrt-config <<EOF
            #!$CONFIG_SHELL
            exec "$CONFIG_SHELL" ${libgpg-error}/bin/gpgrt-config "\$@"
            EOF
            chmod +x .aos-build-tools/gpgrt-config
            export GPGRT_CONFIG="$PWD/.aos-build-tools/gpgrt-config"
            export PKG_CONFIG_LIBDIR=
            export PKG_CONFIG_PATH="${libgpg-error}/lib/pkgconfig:${libassuan}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
          ''
          + ''
            ./configure \
              $configureFlags \
              --prefix="$out" \
              --enable-fixed-path=${gnupg}/bin \
              --with-libgpg-error-prefix=${libgpg-error} \
              --with-libassuan-prefix=${libassuan}
          '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''make -j"$NIX_BUILD_CORES" check'';
      }
      {
        name = "install";
        script =
          ''make install''
          + lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''

            # Public config helpers run on the target, including when invoked by
            # target Python during an emulated consumer build.
            sed -i '1s|^#!.*|#!${bash}/bin/bash|' "$out/bin/gpgme-config"
          '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-gpgme";
        library = self;
        libs = ["-lgpgme"];
        testSource = ''
          #include <gpgme.h>

          int main(void) {
              return gpgme_check_version(NULL) == NULL;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-gpgme";
        tool = self;
        command = "gpgme-tool --version";
      };
    };

    meta = {
      description = "High-level API for GnuPG operations";
      homepage = "https://gnupg.org/software/gpgme/";
      license = "LGPL-2.1-or-later AND GPL-3.0-or-later";
    };
  }
