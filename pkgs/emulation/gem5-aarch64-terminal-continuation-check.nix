##! Real ARM Linux serial birth and unchanged opaque-image continuation
{
  mkDerivation,
  gem5-full-system-foundation,
  gem5-aarch64-linux,
  gem5-aarch64-linux-device-fixture,
  gem5-aarch64-bootloader,
  dmtcp,
  gem5-process-custody,
  python3,
  coreutils,
  abseil-cpp,
}:
mkDerivation {
  pname = "gem5-aarch64-terminal-continuation-check";
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
  buildDeps = [python3 coreutils];
  runtimeDeps = [
    gem5-full-system-foundation
    gem5-aarch64-linux
    gem5-aarch64-linux-device-fixture
    gem5-aarch64-bootloader
    dmtcp
    gem5-process-custody
  ];
  phases = [
    {
      name = "check";
      script = ''
        export PYTHONDONTWRITEBYTECODE=1
        ${python3}/bin/python3 -B ${./_gem5/terminal-custody-check.py} \
          ${./_gem5/terminal-continuation-check.py}
        export LD_LIBRARY_PATH="${abseil-cpp}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        witness_root="$(mktemp -d /tmp/gem5-arm-terminal-continuation.XXXXXXXX)"
        ${coreutils}/bin/timeout 300 ${python3}/bin/python3 -B \
          ${./_gem5/terminal-continuation-check.py} \
          ${gem5-full-system-foundation}/bin/gem5 ${dmtcp} \
          ${gem5-process-custody}/lib/libcrucible-resource-custody.so \
          ${./_gem5/full-system-arm-terminal-owner.py} "$witness_root/native" \
          ${gem5-full-system-foundation}/share/gem5/configs \
          ${gem5-aarch64-linux}/boot/vmlinux \
          ${gem5-aarch64-linux-device-fixture}/initrd.img \
          ${gem5-aarch64-bootloader}/share/gem5/bootloader/boot_v2.arm64 > native-check.log
        ${python3}/bin/python3 -B ${./_gem5/terminal-continuation-summary.py} \
          "$witness_root/native/result.json" summary.json
        mkdir -p "$out/share/checks" "$out/share/licenses/gem5-aarch64-terminal-continuation-check"
        cp summary.json "$out/share/checks/arm-linux-terminal-continuation.json"
        cp ${../../LICENSES/MIT.txt} "$out/share/licenses/gem5-aarch64-terminal-continuation-check/LICENSE"
        rm -rf "$witness_root"
      '';
    }
  ];
  meta = {
    description = "Preserves original real ARM Linux serial birth and a finite native suffix after source namespace deletion and two fresh restorations; full-system closure and readiness remain unqualified";
    license = "MIT";
  };
}
