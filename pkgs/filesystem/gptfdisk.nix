##! gptfdisk — GPT partitioning utilities (sgdisk / gdisk / cgdisk)
##!
##! sgdisk is the non-interactive scripting front-end used by image and
##! provisioning disk-layout code. Built from the Makefile-only upstream
##! release; no autoconf.
{
  mkDerivation,
  fetchurl,
  gnumake,
  popt,
  ncurses,
  util-linux,
}: let
  version = "1.0.10";
in
  mkDerivation {
    pname = "gptfdisk";
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
    runtimeDeps = [
      popt
      ncurses
      util-linux
    ];

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
          make -j$NIX_BUILD_CORES CC="$CC" CXX="$CXX"
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
