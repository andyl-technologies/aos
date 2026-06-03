##! libselinux — SELinux userspace library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libsepol,
  pcre2,
}: let
  version = "3.10";
in
  mkDerivation {
    pname = "libselinux";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/SELinuxProject/selinux/releases/download/${version}/selinux-${version}.tar.gz"
      ];
      hash = "sha256-tHDgCV1FBpqAzs+Av5xRImQrycFU9BqnbTBQ6DfVmiA=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      libsepol
      pcre2
    ];
    propagatedDeps = [
      pcre2
      libsepol
    ];

    # SELinux userspace has unchecked memory-copy patterns that trip
    # _FORTIFY_SOURCE. Disabling fortify disables fortify3 too.
    hardeningDisable = ["fortify"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd selinux-${version}/libselinux
        '';
      }
      {
        name = "build";
        script = ''
          make PREFIX=$out SHLIBDIR=$out/lib \
            CFLAGS="-I${libsepol}/include -I${pcre2}/include" \
            LDFLAGS="-L${libsepol}/lib -L${pcre2}/lib -lpcre2-8" \
            USE_PCRE2=y \
            -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install PREFIX=$out SHLIBDIR=$out/lib
        '';
      }
    ];

    meta = {
      description = "libselinux — SELinux userspace runtime library";
      homepage = "https://github.com/SELinuxProject/selinux";
      license = "LGPL-2.1-or-later";
    };
  }
