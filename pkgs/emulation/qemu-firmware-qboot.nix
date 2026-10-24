##! Builds QEMU's qboot firmware from its original freestanding source.
##!
##! The binary and complete corresponding source are separate co-retained
##! outputs. This provider contributes qboot.rom to the full firmware roster.
{
  mkDerivation,
  fetchurl,
  gccUnwrapped,
  binutils,
  meson,
  ninja,
  bash,
  python3,
}: let
  version = "11.1.1";
  recipe = ./qemu-firmware-qboot.nix;
  verifyProduct = ./verify-qboot-product.py;
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

    pname = "qemu-firmware-qboot";
    inherit version;
    outputs = ["out" "source"];

    src = fetchurl {
      urls = ["https://download.qemu.org/qemu-${version}.tar.xz"];
      hash = "sha256-B5/7/4pxEbvIkCIQfLq/O7/WFNX8nXzGdZkRlqyhJII=";
    };

    buildDeps = [gccUnwrapped binutils meson ninja bash python3];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar --no-same-owner -xf "$src"
          cd qemu-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export SOURCE_DATE_EPOCH=1

          # Raw AOS GCC keeps hosted dynamic-loader and rpath flags out of the
          # freestanding image. Meson must never try to execute this firmware.
          cat > qboot-toolchain.ini <<EOF
          [binaries]
          c = '${gccUnwrapped}/bin/gcc'
          ar = '${binutils}/bin/ar'
          strip = '${binutils}/bin/strip'
          objcopy = '${binutils}/bin/objcopy'

          [host_machine]
          system = 'baremetal'
          cpu_family = 'x86'
          cpu = 'i386'
          endian = 'little'

          [properties]
          needs_exe_wrapper = true

          [built-in options]
          c_args = ['-m32', '-ffreestanding']
          # Freestanding probes lack _start and misclassify these supported
          # flags under fatal linker warnings. Retain a static raw-ROM link.
          c_link_args = ['-m32', '-nostdlib', '-no-pie', '-Wl,--build-id=none']
          EOF

          ${meson}/bin/meson setup qboot-build roms/qboot \
            --cross-file qboot-toolchain.ini --buildtype=release
        '';
      }
      {
        name = "build";
        script = ''
          ${ninja}/bin/ninja -C qboot-build -j"$NIX_BUILD_CORES" -v

          # Retain Ninja's actual compiler commands and resolved dependencies,
          # including dependency data normally consumed from temporary .d files.
          ${ninja}/bin/ninja -C qboot-build -t commands > qboot-build/compile-commands.txt
          ${ninja}/bin/ninja -C qboot-build -t deps > qboot-build/compiler-dependencies.txt
          ${python3}/bin/python3 ${verifyProduct} qboot-build qboot-build/product.json
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/qemu" "$source/share/qemu-firmware-qboot-source"
          cp qboot-build/bios.bin "$out/share/qemu/qboot.rom"

          # This retains the original full archive, every configured source,
          # compiled object, link product, dependency journal and build input.
          cp "$src" "$source/share/qemu-firmware-qboot-source/qemu-${version}.tar.xz"
          cp -R roms/qboot "$source/share/qemu-firmware-qboot-source/qboot"
          cp -R qboot-build "$source/share/qemu-firmware-qboot-source/build"
          cp qboot-toolchain.ini COPYING LICENSE \
            "$source/share/qemu-firmware-qboot-source/"
          cp ${recipe} "$source/share/qemu-firmware-qboot-source/qemu-firmware-qboot.nix"
          cp ${verifyProduct} "$source/share/qemu-firmware-qboot-source/verify-qboot-product.py"
          cmp "$out/share/qemu/qboot.rom" \
            "$source/share/qemu-firmware-qboot-source/build/bios.bin"
          ln -s "$source" "$out/share/qemu-firmware-qboot-source"
        '';
      }
    ];
  }
