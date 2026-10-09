##! Source-built AArch64 firmware for gem5 ARM full-system board fixtures
{
  mkDerivation,
  gem5,
  llvm-gem5,
  gnumake,
  python3,
}:
mkDerivation {
  pname = "gem5-aarch64-bootloader";
  version = gem5.version;
  src = gem5.src;
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
  buildDeps = [llvm-gem5 gnumake python3];
  runtimeDeps = [];
  phases = [
    {
      name = "unpack";
      script = ''
        tar xf "$src"
        cd gem5-*
      '';
    }
    {
      name = "build";
      script = ''
        # Build all four upstream AArch64 boards, including their original
        # GICv2/GICv3 startup paths; no downloaded firmware enters the fixture.
        cd system/arm/bootloader/arm64
        make CC="${llvm-gem5}/bin/clang --target=aarch64-none-elf" \
          LD=${llvm-gem5}/bin/ld.lld \
          LDFLAGS="-N --image-base=0 -Ttext 0x00000010 -static"
      '';
    }
    {
      name = "check";
      script = ''
        for image in boot_emm.arm64 boot.arm64 boot_v2.arm64 boot_foundation.arm64; do
          ${python3}/bin/python3 ${./_gem5/aarch64-artifact-check.py} executable "$image"
        done
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/share/gem5/bootloader" "$out/share/gem5/bootloader/source"
        cp boot_emm.arm64 boot.arm64 boot_v2.arm64 boot_foundation.arm64 \
          "$out/share/gem5/bootloader/"
        cp boot.S makefile "$out/share/gem5/bootloader/source/"
      '';
    }
  ];
  meta.description = "Builds the pinned gem5 AArch64 firmware from its BSD-licensed assembly with AOS LLVM";
  meta.license = "BSD-3-Clause";
}
