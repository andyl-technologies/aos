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
  lib,
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
  version = "1.5.8.pl02";
  sourceVersion = "1.5.8";
in
  mkDerivation {
    pname = "libisoburn";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [
          {
            "path" = "extracted.txt";
            "text" = "answer=42\n";
          }
        ];
        "expected" = "Xorriso round-trips the file through its ISO filesystem implementation.";
        "files" = {
          "answer.txt" = "answer=42\n";
        };
        "input" = "A file containing answer=42 for the root of an ISO image.";
        "operation" = "Create the ISO with xorriso, extract the file, and compare its exact contents.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/xorriso"
              "-report_about"
              "SORRY"
              "-outdev"
              "image.iso"
              "-map"
              "answer.txt"
              "/answer.txt"
              "-commit"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "xorriso 1.5.8.pl02 : RockRidge filesystem manipulator, libburnia project.\n\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@out@/bin/xorriso"
              "-report_about"
              "SORRY"
              "-osirrox"
              "on"
              "-indev"
              "image.iso"
              "-extract"
              "/answer.txt"
              "extracted.txt"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "xorriso 1.5.8.pl02 : RockRidge filesystem manipulator, libburnia project.\n\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Xorriso rejects the command with status 5.";
        "files" = {};
        "input" = "An xorriso command name that does not exist.";
        "operation" = "Parse the unsupported command through xorriso's dispatcher.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/xorriso"
              "-report_about"
              "SORRY"
              "-qualification-invalid"
            ];
            "exit_code" = 5;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://files.libburnia-project.org/releases/libisoburn-${version}.tar.gz"
      ];
      hash = "sha256-qXewPcNobZ/cpgBFixV4+crCuHVgm9XsIfWtpV8g7FA=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps =
      [zlib]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [acl attr]
      )
      ++ [readline libburn libisofs]
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
          cd libisoburn-${sourceVersion}
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
