##! libsemanage — SELinux policy management library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  bison,
  flex,
  bzip2,
  libsepol,
  libselinux,
  audit,
}: let
  version = "3.10";
in
  mkDerivation {
    pname = "libsemanage";
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
      bison
      flex
    ];
    runtimeDeps = [
      bzip2
      libsepol
      libselinux
      audit
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd selinux-${version}/libsemanage
        '';
      }
      {
        name = "build";
        script = ''
          make PREFIX=$out SHLIBDIR=$out/lib \
            CFLAGS="-I${libsepol}/include -I${libselinux}/include -I${audit}/include -I${bzip2}/include" \
            LDFLAGS="-L${libsepol}/lib -L${libselinux}/lib -L${audit}/lib -L${bzip2}/lib" \
            -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install PREFIX=$out SHLIBDIR=$out/lib SYSCONFDIR=$out/etc
        '';
      }
    ];

    meta = {
      description = "libsemanage — SELinux policy management library";
      homepage = "https://github.com/SELinuxProject/selinux";
      license = "LGPL-2.1-or-later";
    };
  }
