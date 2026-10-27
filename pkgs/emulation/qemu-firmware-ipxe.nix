##! Builds every QEMU iPXE BIOS and combined BIOS/EFI ROM from source.
##!
##! Original iPXE configurations and EDK2 EfiRom sources accompany the
##! actual compiled products. This provider preserves all eight PCI targets.
{
  mkDerivation,
  fetchurl,
  gccUnwrapped,
  binutils,
  gnumake,
  bash,
  perl,
  python3,
  xz,
}: let
  version = "11.1.1";
  recipe = ./qemu-firmware-ipxe.nix;
  prepareSource = ./prepare-ipxe-source.py;
  verifyProducts = ./verify-ipxe-products.py;
in
  mkDerivation {
    # Current hosted helpers and raw -m32/-m64 GCC recipes require x86 builders.
    # ROM guest ISA is data; it does not establish another native build port.
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };

    pname = "qemu-firmware-ipxe";
    inherit version;
    outputs = ["out" "source"];

    src = fetchurl {
      urls = ["https://download.qemu.org/qemu-${version}.tar.xz"];
      hash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
    };

    buildDeps = [gccUnwrapped binutils gnumake bash perl python3 xz];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar --no-same-owner -xf "$src"
          cd qemu-${version}
          export SOURCE_DATE_EPOCH=1
          ${python3}/bin/python3 ${prepareSource} \
            ${bash}/bin/bash ${perl}/bin/perl ${python3}/bin/python3
        '';
      }
      {
        name = "build";
        script = ''
          # Hosted EfiRom and compression helpers use the AOS wrapper; firmware
          # uses raw GCC so no hosted loader or rpath enters freestanding code.
          ${gnumake}/bin/make -C roms/edk2/BaseTools/Source/C/Common \
            -j"$NIX_BUILD_CORES" HOST_ARCH=X64 CC="$CC" AR="${binutils}/bin/ar" \
            SHELL="${bash}/bin/bash"
          ${gnumake}/bin/make -C roms/edk2/BaseTools/Source/C/EfiRom \
            -j"$NIX_BUILD_CORES" HOST_ARCH=X64 CC="$CC" AR="${binutils}/bin/ar" \
            SHELL="${bash}/bin/bash"

          targets="8086100e 808610d3 80861209 10500940 10222000 10ec8139 1af41000 15ad07b0"
          for format in bin/rom bin-x86_64-efi/efidrv; do
            directory="''${format%/*}"
            extension="''${format##*/}"
            set --
            for target in $targets; do
              set -- "$@" "$directory/$target.$extension"
            done
            ${gnumake}/bin/make -C roms/ipxe/src -j"$NIX_BUILD_CORES" \
              CONFIG=qemu V=1 HOST_CC="$CC" CC="${gccUnwrapped}/bin/gcc" \
              AS="${binutils}/bin/as" LD="${binutils}/bin/ld" \
              AR="${binutils}/bin/ar" OBJCOPY="${binutils}/bin/objcopy" \
              OBJDUMP="${binutils}/bin/objdump" NM="${binutils}/bin/nm" \
              RANLIB="${binutils}/bin/ranlib" PERL="${perl}/bin/perl" \
              SHELL="${bash}/bin/bash" "$@"
          done

          # These are the original roms/Makefile PCI mappings and EfiRom flags.
          mkdir firmware-products
          for binding in e1000:8086:100e e1000e:8086:10d3 eepro100:8086:1209 \
            ne2k_pci:1050:0940 pcnet:1022:2000 rtl8139:10ec:8139 \
            virtio:1af4:1000 vmxnet3:15ad:07b0; do
            name="''${binding%%:*}"
            ids="''${binding#*:}"
            vendor="''${ids%:*}"
            device="''${ids#*:}"
            cp "roms/ipxe/src/bin/$vendor$device.rom" "firmware-products/pxe-$name.rom"
            roms/edk2/BaseTools/Source/C/bin/EfiRom \
              -f "0x$vendor" -i "0x$device" -l 0x02 \
              -b "roms/ipxe/src/bin/$vendor$device.rom" \
              -ec "roms/ipxe/src/bin-x86_64-efi/$vendor$device.efidrv" \
              -o "firmware-products/efi-$name.rom"
          done
          ${python3}/bin/python3 ${verifyProducts}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/qemu" "$source/share/qemu-firmware-ipxe-source"
          cp firmware-products/*.rom "$out/share/qemu/"
          cp "$src" "$source/share/qemu-firmware-ipxe-source/qemu-${version}.tar.xz"
          cp -R roms/ipxe roms/edk2 firmware-products \
            "$source/share/qemu-firmware-ipxe-source/"
          cp roms/Makefile COPYING LICENSE \
            "$source/share/qemu-firmware-ipxe-source/"
          cp ${recipe} "$source/share/qemu-firmware-ipxe-source/qemu-firmware-ipxe.nix"
          cp ${prepareSource} ${verifyProducts} interpreter-rewrites.json \
            "$source/share/qemu-firmware-ipxe-source/"
          for product in firmware-products/*.rom; do
            cmp "$product" "$out/share/qemu/''${product##*/}"
          done
          ln -s "$source" "$out/share/qemu-firmware-ipxe-source"
        '';
      }
    ];
  }
