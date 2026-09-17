##! pciutils — PCI bus inspection and configuration tools
{
  mkDerivation,
  fetchurl,
  lib,
  stdenv,
  gnumake,
  pkg-config,
  hwdata,
  kmod,
  zlib,
}: let
  version = "3.15.0";
  # Upstream otherwise selects CPU-specific access methods using uname on
  # the builder, which enables x86 I/O instructions in an ARM cross build.
  targetMakeFlags = lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) " HOST=${stdenv.hostPlatform.config}";
in
  mkDerivation {
    pname = "pciutils";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/pciutils/pciutils/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-BvRnZCBXWZrPOWvBc0BFL6wzCPHgi+GeDDJYfkLXAXs=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [kmod zlib];
    propagatedDeps = [zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd pciutils-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" \
            CC="$CC" AR="$AR" RANLIB="$RANLIB" \
            PREFIX="$out" LIBDIR="$out/lib" \
            SHARED=yes DNS=yes IDSDIR="$out/share"${targetMakeFlags}
        '';
      }
      {
        name = "install";
        script = ''
          make install install-lib \
            CC="$CC" AR="$AR" RANLIB="$RANLIB" \
            PREFIX="$out" LIBDIR="$out/lib" \
            SHARED=yes DNS=yes IDSDIR="$out/share"${targetMakeFlags}
          cp "${hwdata}/share/hwdata/pci.ids" "$out/share/pci.ids"
          rm -f "$out/sbin/update-pciids"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-pciutils";
        tool = self;
        command = "lspci --version";
      };
    };

    meta = {
      description = "PCI bus inspection and configuration tools";
      homepage = "https://mj.ucw.cz/sw/pciutils/";
      license = "GPL-2.0-or-later";
      mainProgram = "lspci";
    };
  }
