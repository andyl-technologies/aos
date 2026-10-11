##! Freestanding source-built AArch64 PID1 with Linux device roundtrip probes
{
  mkDerivation,
  gem5-aarch64-linux,
  llvm-gem5,
  python3,
}:
mkDerivation {
  pname = "gem5-aarch64-linux-device-fixture";
  version = "1";
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
  buildDeps = [gem5-aarch64-linux llvm-gem5 python3];
  runtimeDeps = [];
  phases = [
    {
      name = "build";
      script = ''
        # Linux's sanitized ARM UAPI supplies syscall numbers and structures;
        # no host libc headers or target libc binary enter this executable.
        ${llvm-gem5}/bin/clang --target=aarch64-linux-gnu -fuse-ld=lld \
          -nostdinc -nostdlib -static -fno-pie -Wl,-no-pie -ffreestanding -fno-builtin \
          -fno-stack-protector -O2 -Wall -Wextra -Werror \
          -I${./_gem5/freestanding-uapi} -I${gem5-aarch64-linux}/include -Wl,--build-id=none -Wl,-e,_start \
          ${./_gem5/aarch64-linux-device-init.c} -o init
        ${python3}/bin/python3 ${./_gem5/make-device-initramfs.py} init initrd.img
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out"
        cp init initrd.img "$out/"
      '';
    }
    {
      name = "check";
      script = ''
        ${python3}/bin/python3 ${./_gem5/aarch64-artifact-check.py} init "$out"
      '';
    }
  ];
  meta.description = "Builds a static ARM PID1/initramfs with serial, modern VirtIO network/block/9p probes; runtime device parity requires independent native witnesses";
}
