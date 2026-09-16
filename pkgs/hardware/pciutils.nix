##! pciutils — PCI bus inspection and configuration tools
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  hwdata,
  kmod,
  zlib,
}: let
  version = "3.15.0";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "pciutils";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Lspci reports the exact bus address, class, device ID, and revision.";
        "files" = {
          "pci.dump" = "00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)\n00: 86 80 37 12 06 00 00 00 02 00 00 06 00 00 00 00\n";
        };
        "input" = "A PCI configuration dump for an Intel 8086:1237 host bridge.";
        "operation" = "Parse the dump and render its numeric identity through lspci.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/lspci"
              "-F"
              "pci.dump"
              "-n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "00:00.0 0600: 8086:1237 (rev 02)\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Lspci rejects the dump with status 1.";
        "files" = {
          "pci.dump" = "unterminated";
        };
        "input" = "A PCI dump containing an unterminated record.";
        "operation" = "Parse the malformed dump through lspci.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/lspci"
              "-F"
              "pci.dump"
              "-n"
            ];
            "exit_code" = 1;
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
            SHARED=yes DNS=yes IDSDIR="$out/share"
        '';
      }
      {
        name = "install";
        script = ''
          make install install-lib \
            CC="$CC" AR="$AR" RANLIB="$RANLIB" \
            PREFIX="$out" LIBDIR="$out/lib" \
            SHARED=yes DNS=yes IDSDIR="$out/share"
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
