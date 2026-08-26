##! libburn — block-level optical media driver
##!
##! Part of the libburnia trio (libburn, libisofs, libisoburn). libburn
##! handles the raw SCSI / BD-RE layer; libisofs reads and writes the
##! ISO9660 filesystem on top; libisoburn ties the two together and
##! ships the `xorriso` CLI we actually consume (for the `aos-metadata`
##! ISO in the VM test harness). AOS only needs ISO image creation, not
##! physical media burning — but xorriso's configure marks libburn as
##! a FATAL prerequisite so it's packaged unconditionally.
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
}: let
  version = "1.5.6";
in
  mkDerivation {
    pname = "libburn";
    inherit version;

    src = fetchurl {
      urls = [
        "https://files.libburnia-project.org/releases/libburn-${version}.tar.gz"
      ];
      hash = "sha256-cpVJG0vl7qxeej+yBn4jbilV/9xrvUX1RkZu3uMhZEs=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libburn-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure $configureFlags --prefix=$out
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

    meta = {
      description = "libburn — block-level optical media driver";
      homepage = "https://dev.lovelyhq.com/libburnia/";
      license = "GPL-2.0-or-later";
    };
  }
