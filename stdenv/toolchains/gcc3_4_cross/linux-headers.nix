# stdenv/toolchains/gcc3_4_cross/linux-headers.nix — Phase 3
#
# Linux 2.6.9 headers for x86_64 target.
#
{
  prev,
  buildPlatform,
  hostPlatform,
  ...
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://cdn.kernel.org/pub/linux/kernel/v2.6/linux-2.6.9.tar.bz2";
    hash = "1hrnvjlgr4alcs1xcvc98c4vx3bmnc42idp3bav8jnvd0n4kwmq2";
  };

  # Linux 2.6.9 uses include/asm-<arch> directory names
  asmDirMap = {
    x86_64 = "asm-x86_64";
    i686 = "asm-i386";
    aarch64 = "asm-arm64";
  };
  asmDir =
    asmDirMap.${hostPlatform.constraints.cpu}
      or (throw "unsupported CPU for linux-headers: ${hostPlatform.constraints.cpu}");
in
builtins.derivation {
  name = "linux-headers-2.6.9";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${prev.bash}/bin"

      mkdir -p "$out/include"
      cp -r ${src}/include/linux "$out/include/"
      cp -r ${src}/include/${asmDir} "$out/include/asm"
      cp -r ${src}/include/asm-generic "$out/include/"
      chmod -R u+w "$out/include"

      # Architecture-independent version header
      printf '#define UTS_RELEASE "2.6.9"\n#define LINUX_VERSION_CODE 132617\n#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))\n' \
        > "$out/include/linux/version.h"

      echo "Linux 2.6.9 headers (${hostPlatform.constraints.cpu}) installed to $out"
    ''
  ];
}
