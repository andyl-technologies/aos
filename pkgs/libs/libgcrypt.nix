##! libgcrypt — general-purpose cryptographic library from the GnuPG project
{
  mkDerivation,
  fetchurl,
  gnumake,
  libgpg-error,
  bash,
  stdenv,
}: let
  version = "1.12.2";
in
  mkDerivation {
    pname = "libgcrypt";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-${version}.tar.bz2"
        "https://mirrors.dotsrc.org/gcrypt/libgcrypt/libgcrypt-${version}.tar.bz2"
      ];
      hash = "sha256-fOM8JJIiGgQ2+WqFACFenz49y1/SanV81BXnqEO6vV4=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      [libgpg-error]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
    propagatedDeps = [libgpg-error];

    # The CPU Jitter RNG (cipher/rndjent.c) must be built without optimization
    # for the entropy collector to work; the release tarball enforces that with
    # a per-file `#pragma GCC optimize ("O0")` (gcc-only). -fstrict-flex-arrays=3
    # would also miscompile the trailing flexible arrays in libgcrypt's internal
    # structures, so step it down to match nixpkgs.
    hardeningDisable = ["strictflexarrays3"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libgcrypt-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-static \
            --with-libgpg-error-prefix=${libgpg-error}
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
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/libgcrypt-config"
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "General-purpose cryptographic library from the GnuPG project";
      homepage = "https://gnupg.org/software/libgcrypt/";
      license = "LGPL-2.1-or-later";
    };
  }
