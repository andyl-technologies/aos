##! linux-firmware — Firmware files for Linux kernel drivers
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "20260110";
in
  mkDerivation {
    pname = "firmware";
    inherit version;

    src = fetchurl {
      urls = [
        "https://cdn.kernel.org/pub/linux/kernel/firmware/linux-firmware-${version}.tar.xz"
      ];
      hash = "sha256-SOBRZttTn07o0prJ0japRELFsbGhYKlm9v5rQr1xQzE=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd linux-firmware-${version}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/lib/firmware

          # Install selected firmware families needed for server/cloud usage.
          # Network adapters
          cp -a intel $out/lib/firmware/ 2>/dev/null || true
          cp -a i915 $out/lib/firmware/ 2>/dev/null || true
          cp -a iwlwifi* $out/lib/firmware/ 2>/dev/null || true
          cp -a mellanox $out/lib/firmware/ 2>/dev/null || true
          cp -a bnx2 $out/lib/firmware/ 2>/dev/null || true
          cp -a bnx2x $out/lib/firmware/ 2>/dev/null || true
          cp -a bnxt $out/lib/firmware/ 2>/dev/null || true

          # Storage controllers
          cp -a qed $out/lib/firmware/ 2>/dev/null || true
          cp -a qla2xxx $out/lib/firmware/ 2>/dev/null || true
          cp -a cxgb4 $out/lib/firmware/ 2>/dev/null || true
          cp -a amd $out/lib/firmware/ 2>/dev/null || true
          cp -a amd-ucode $out/lib/firmware/ 2>/dev/null || true
          cp -a intel-ucode $out/lib/firmware/ 2>/dev/null || true

          # Install the WHENCE and LICENSE files
          cp WHENCE LICENCE.* $out/lib/firmware/ 2>/dev/null || true
        '';
      }
    ];

    meta = {
      description = "linux-firmware — firmware files for Linux kernel drivers";
      homepage = "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git";
      license = "Linux-firmware";
    };
  }
