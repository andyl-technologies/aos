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
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
}: let
  version = "1.5.8";
in
  mkDerivation {
    pname = "libburn";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Cdrskin creates one padded track whose payload and zero-filled remainder are exact.";
        "files" = {
          "answer.txt" = "answer=42\n";
        };
        "input" = "A ten-byte data track containing answer=42.";
        "operation" = "Burn the track into an emulated stdio device through cdrskin.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/cdrskin"
              "--allow_emulated_drives"
              "dev=stdio:track.img"
              "-data"
              "answer.txt"
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@python@"
              "-c"
              "data=open('track.img','rb').read(); assert len(data)==2048 and data[:10]==b'answer=42\\n' and not any(data[10:])"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Cdrskin rejects the missing source with status 3.";
        "files" = {};
        "input" = "A data-track pathname that does not exist.";
        "operation" = "Attach the missing track to an emulated stdio device through cdrskin.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/cdrskin"
              "--allow_emulated_drives"
              "dev=stdio:track.img"
              "-data"
              "missing.txt"
            ];
            "exit_code" = 3;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://files.libburnia-project.org/releases/libburn-${version}.tar.gz"
      ];
      hash = "sha256-jiTdmfW3yvvs8BFtYbYZ7okJjiAmPm9Hx5Oq9KmNZHM=";
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
