##! libisofs — ISO9660 filesystem reader/writer
##!
##! Companion to libburn; together with libisoburn provides the xorriso
##! CLI. AOS uses xorriso to produce the `aos-metadata` ISO consumed
##! by the VM test harness and bare-metal operators via IPMI virtual
##! media.
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  zlib,
  acl,
  attr,
}: let
  version = "1.5.6";
in
  mkDerivation {
    pname = "libisofs";
    inherit version;

    src = fetchurl {
      urls = [
        "https://files.libburnia-project.org/releases/libisofs-${version}.tar.gz"
      ];
      hash = "sha256-AVLWap00C2Wf6ciA65GQ81cPtHesB89S6LzRNKHTDXA=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [zlib acl attr];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libisofs-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure --prefix=$out
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
      description = "libisofs — ISO9660 filesystem reader/writer";
      homepage = "https://dev.lovelyhq.com/libburnia/";
      license = "GPL-2.0-or-later";
    };
  }
