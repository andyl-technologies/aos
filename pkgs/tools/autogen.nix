##! autogen — Automated text and program generation
{
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  automake,
  pkg-config,
  perl,
  which,
  file,
  guile,
  libxml2,
}: let
  version = "5.18.16";
  guile3Patch = fetchurl {
    urls = [
      "https://gitweb.gentoo.org/repo/gentoo.git/plain/sys-devel/autogen/files/autogen-5.18.16-guile-3.patch?id=43bcc61c56a5a7de0eaf806efec7d8c0e4c01ae7"
    ];
    hash = "sha256-LCcZZBrxAx//5G3qcS6H/RmJUa2Qn2UlbP5uYYeHnSk=";
  };
in
  mkDerivation {
    pname = "autogen";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.gnu.org/gnu/autogen/rel${version}/autogen-${version}.tar.xz"
      ];
      hash = "sha256-+KE0ZrSPqjupn+F6Bp5xyasAbZsc+r5pn4xgpH1btJo=";
    };

    buildDeps = [gnumake autoconf automake pkg-config perl which file];
    runtimeDeps = [guile libxml2];
    propagatedDeps = [guile libxml2];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd autogen-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          patch -p1 < ${guile3Patch}
          sed -i 's|/usr/bin/file|${file}/bin/file|g' configure
        '';
      }
      {
        name = "configure";
        script = ''
          export MAN_PAGE_DATE=1970-01-01
          ./configure $configureFlags \
            --prefix="$out" \
            --disable-dependency-tracking \
            --with-libxml2=${libxml2} \
            --with-libxml2-cflags=-I${libxml2}/include/libxml2 \
            --enable-timeout=78 \
            CFLAGS=-D_FILE_OFFSET_BITS=64
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p .aos-autotools
          ln -s ${automake}/bin/aclocal .aos-autotools/aclocal-1.16
          ln -s ${automake}/bin/automake .aos-autotools/automake-1.16
          export PATH="$PWD/.aos-autotools:$PATH"
          make -j"$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''make check'';
      }
      {
        name = "install";
        script = ''
          make install
          "$out/bin/autogen" --version
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-autogen";
        tool = self;
        command = "autogen --version && columns --version";
      };
    };

    meta = {
      description = "Automated text and program generation tool";
      homepage = "https://www.gnu.org/software/autogen/";
      license = "GPL-3.0-or-later AND LGPL-3.0-or-later";
      mainProgram = "autogen";
    };
  }
