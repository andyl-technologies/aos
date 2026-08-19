##! server-initrd-firmware — pre-root firmware for supported server adapters
{
  mkDerivation,
  firmware,
}: let
  version = firmware.version;
in
  mkDerivation {
    pname = "server-initrd-firmware";
    inherit version;
    src = null;

    buildDeps = [firmware];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib/firmware"

          # These families back storage and network adapters that can be
          # required for discovery, provisioning, or unlocking before the
          # immutable root is available. Other firmware stays in the runtime
          # image and can be selected explicitly for hardware-specific initrds.
          for family in bnx2 bnx2x cxgb4 qed; do
            cp -a "${firmware}/lib/firmware/$family" "$out/lib/firmware/"
          done
          cp -a ${firmware}/lib/firmware/WHENCE \
            ${firmware}/lib/firmware/LICENCE.* "$out/lib/firmware/"
        '';
      }
    ];

    meta = {
      description = "Firmware subset for server devices needed before switch-root";
      homepage = firmware.meta.homepage;
      license = firmware.meta.license;
    };
  }
