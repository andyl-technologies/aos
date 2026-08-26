##! libisoburn — ISO manipulation + xorriso CLI
##!
##! Sits on top of libburn + libisofs (both marked FATAL prerequisites
##! in its configure.ac). Installs `bin/xorriso` which AOS uses to
##! produce the ISO9660 `aos-metadata` channel for VM tests and
##! bare-metal operator workflows (read from
##! /dev/disk/by-label/aos-metadata).
##!
##! The --disable-* flags drop features we don't use: Jigdo template
##! engine (DVD mirroring), libcdio SCSI CD-ROM reading, and the setuid
##! privilege-drop paths in xorriso's CLI (we're not running it setuid).
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  zlib,
  acl,
  attr,
  readline,
  libburn,
  libisofs,
  bash,
  stdenv,
}: let
  version = "1.5.6";
in
  mkDerivation {
    pname = "libisoburn";
    inherit version;

    src = fetchurl {
      urls = [
        "https://files.libburnia-project.org/releases/libisoburn-${version}.tar.gz"
      ];
      hash = "sha256-K4Cm9z3WM6XSQ/rL6XoV5cmgdkSl4aJCwhm5N1pF9xs=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [
      zlib
      acl
      attr
      readline
      libburn
      libisofs
    ]
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
          cd libisoburn-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-libjte \
            --disable-libcdio \
            --disable-external-filters-setuid \
            --disable-launch-frontend-setuid
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
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/xorriso-dd-target"
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "libisoburn + xorriso — ISO9660 manipulation";
      homepage = "https://dev.lovelyhq.com/libburnia/";
      license = "GPL-2.0-or-later";
    };
  }
