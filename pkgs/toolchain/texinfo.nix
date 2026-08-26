##! GNU Texinfo — Documentation system
{
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
}: let
  version = "7.2";
in
  mkDerivation {
    pname = "texinfo";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnu.mirror.constant.com/texinfo/texinfo-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/texinfo/texinfo-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/texinfo/texinfo-${version}.tar.xz"
      ];
      hash = "sha256-AynXeI++8RP6gsuAiJyhl6NEzg33ZG/gAJdMXXFDY6Y=";
    };

    buildDeps = [
      gnumake
      perl
    ];
    runtimeDeps = [perl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd texinfo-${version}
          # Build helpers use native Perl; the installed scripts are retargeted
          # to the Darwin Perl after make has finished executing them.
          nativePerl=$(command -v perl)
          for f in maintain/*.pl tp/maintain/*.pl; do
            if [ -f "$f" ]; then
              ref_time=$(stat -c %Y "$f")
              sed -i "1s|#!.*/usr/bin/perl|#!$nativePerl|" "$f"
              sed -i "1s|#!.*/usr/bin/env perl|#!$nativePerl|" "$f"
              touch -d "@$ref_time" "$f"
            fi
          done
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-nls
        '';
      }
      {
        name = "build";
        script = ''
          # Prevent automake/autoconf regeneration if any generated file
          # becomes out of date (e.g. from regenerate_file_lists.pl runs)
          make -j$NIX_BUILD_CORES AUTOMAKE=true AUTOCONF=true ACLOCAL=true AUTOHEADER=true
        '';
      }
      {
        name = "install";
        script = ''
          make install
          nativePerlRoot=$(dirname "$(dirname "$(command -v perl)")")
          grep -IrlZ -F "$nativePerlRoot" "$out" 2>/dev/null \
            | xargs -0 -r sed -i "s|$nativePerlRoot|${perl}|g"
        '';
      }
    ];

    meta = {
      description = "GNU Texinfo — documentation system for online and printed output";
      homepage = "https://www.gnu.org/software/texinfo/";
      license = "GPL-3.0-or-later";
    };
  }
