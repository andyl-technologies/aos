##! Actual source-built ARM Linux modern VirtIO MMIO block driver witness
{
  mkDerivation,
  gem5,
  gem5-aarch64-linux,
  gem5-aarch64-linux-device-fixture,
  gem5-aarch64-bootloader,
  coreutils,
  grep,
}:
mkDerivation {
  pname = "gem5-aarch64-linux-block-check";
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
  buildDeps = [gem5 gem5-aarch64-linux gem5-aarch64-linux-device-fixture gem5-aarch64-bootloader coreutils grep];
  runtimeDeps = [];
  phases = [
    {
      name = "check";
      script = ''
        ulimit -c 0
        timeout 1800 ${gem5}/bin/gem5 --listener-mode=off --outdir=native-output \
          ${./_gem5/aarch64-linux-block-check.py} \
          ${gem5}/share/gem5/configs ${gem5-aarch64-linux}/boot/vmlinux \
          ${gem5-aarch64-linux-device-fixture}/initrd.img \
          ${gem5-aarch64-bootloader}/share/gem5/bootloader/boot_v2.arm64 \
          3000000000000 > native-check.log 2>&1
        grep -q '"linuxGuestRoundtripVerified":true' native-check.log
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out"
        grep '"schema":"crucible.gem5.aarch64-linux-block-mechanism.v1"' \
          native-check.log > "$out/result.json"
      '';
    }
  ];
  meta.description = "Checks a bounded real ARM Linux block roundtrip on modern VirtIO MMIO without CPU-timing or exact-capture admission";
}
