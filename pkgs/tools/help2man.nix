##! Generate manual pages from command help output.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  perl,
  perl-locale-gettext,
  gettext,
}: let
  version = "1.49.3";
in
  mkDerivation {
    pname = "help2man";
    inherit version;
    src = fetchurl {
      urls = ["https://ftp.gnu.org/gnu/help2man/help2man-${version}.tar.xz"];
      hash = "0kzxla1w0w4z5la255lg9q51wy3qx8f1b0i6gbhaz9pcybg4yzjd";
    };

    buildDeps = [buildPackages.gnumake buildPackages.perl buildPackages.perl-locale-gettext buildPackages.gettext];
    runtimeDeps = [perl perl-locale-gettext gettext];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd help2man-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export PERL5LIB=${buildPackages.perl-locale-gettext}/lib/perl5
          $CONFIG_SHELL ./configure $configureFlags --prefix="$out" --enable-nls
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL"
        '';
      }
      {
        name = "install";
        script = ''
          make install SHELL="$CONFIG_SHELL"
          # Bind the installed script to its interpreter and translation module.
          sed -i '1c#!${perl}/bin/perl' "$out/bin/help2man"
          sed -i '2iuse lib "${perl-locale-gettext}/lib/perl5";' "$out/bin/help2man"
          mkdir -p "$out/share/licenses/help2man"
          cp COPYING "$out/share/licenses/help2man/"
        '';
      }
    ];

    meta = {
      description = "Manual page generator with translated help support";
      homepage = "https://www.gnu.org/software/help2man/";
      license = "GPL-3.0-or-later";
    };
  }
