##! gptfdisk — GPT partitioning utilities (sgdisk / gdisk / cgdisk)
##!
##! sgdisk is the non-interactive scripting front-end used by image and
##! provisioning disk-layout code. Built from the Makefile-only upstream
##! release; no autoconf.
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  popt,
  ncurses,
  util-linux,
  stdenv,
}: let
  version = "1.0.10";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "gptfdisk";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Sgdisk writes and validates the primary and backup GPT metadata.";
        "files" = {};
        "input" = "A sparse 8 MiB disk image.";
        "operation" = "Create a GPT with one Linux partition and verify both tables.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "with open('disk.img', 'wb') as disk: disk.truncate(8 * 1024 * 1024)"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@out@/bin/sgdisk"
              "--clear"
              "--new=1:2048:-2048"
              "--typecode=1:8300"
              "disk.img"
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@out@/bin/sgdisk"
              "--verify"
              "disk.img"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Sgdisk rejects the geometry with status 4.";
        "files" = {};
        "input" = "A one-sector disk image, too small to hold GPT headers and entries.";
        "operation" = "Create a new GPT on the undersized image.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "with open('tiny.img', 'wb') as disk: disk.truncate(512)"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@out@/bin/sgdisk"
              "--clear"
              "tiny.img"
            ];
            "exit_code" = 4;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://downloads.sourceforge.net/gptfdisk/gptfdisk-${version}.tar.gz"
      ];
      hash = "sha256-Kr7WG8bSuexJiXPARAuLgEt6ctcUQGm1qSCbKtaTooI=";
    };

    buildDeps = [gnumake];
    # gptfdisk dlopens uuid (libuuid from util-linux), parses
    # options via popt, and uses ncurses for the interactive cgdisk
    # variant. Keep all three in runtimeDeps.
    runtimeDeps =
      [
        popt
        ncurses
      ]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [util-linux]
      );

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gptfdisk-${version}
        '';
      }
      {
        name = "build";
        # gptfdisk's plain Makefile honors CC/CXX/CFLAGS. The AOS
        # ccWrapper already injects -isystem/-L/-Wl,-rpath flags for
        # the runtime deps, so `make` links correctly without hints.
        script = ''
          make -j$NIX_BUILD_CORES \
            CC="$CC" \
            CXX="$CXX" \
            ${
            if stdenv.hostPlatform.isDarwin
            then ''
              TARGET=macos \
              FATBINFLAGS= \
              THINBINFLAGS= \
              CXXFLAGS="''${CXXFLAGS:-} -O2 -Wall -D_FILE_OFFSET_BITS=64 -stdlib=libc++" \
              LDLIBS= \
              SGDISK_LDLIBS=-lpopt \
              CGDISK_LDLIBS=-lncursesw
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/sbin $out/share/man/man8
          install -m 0755 sgdisk $out/sbin/sgdisk
          install -m 0755 gdisk  $out/sbin/gdisk
          install -m 0755 cgdisk $out/sbin/cgdisk
          install -m 0755 fixparts $out/sbin/fixparts
          for m in sgdisk gdisk cgdisk fixparts; do
            [ -f "$m.8" ] && install -m 0644 "$m.8" "$out/share/man/man8/$m.8"
          done
        '';
      }
    ];

    meta = {
      description = "gptfdisk — GPT fdisk family (sgdisk, gdisk, cgdisk)";
      homepage = "https://www.rodsbooks.com/gdisk/";
      license = "GPL-2.0-only";
    };
  }
