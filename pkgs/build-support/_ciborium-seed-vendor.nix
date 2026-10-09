##! Pinned CBOR borrowed-seed API applied after archive verification.
{
  mkDerivation,
  buildPackages,
}: vendor:
mkDerivation {
  pname = "ciborium-seed-vendor";
  version = "0.2.2-1";
  src = null;
  buildDeps = [buildPackages.coreutils buildPackages.python3 buildPackages.patch];
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out"
        cp -R "${vendor}/." "$out/"
        ${buildPackages.python3}/bin/python3 ${./patch-ciborium-seed-vendor.py} \
          "$out" ${./ciborium-borrowed-seed.patch} ${buildPackages.patch}/bin/patch
      '';
    }
  ];
  passthru = {
    unpatchedVendor = vendor;
    evidenceSources = [vendor ./ciborium-borrowed-seed.patch ./patch-ciborium-seed-vendor.py];
  };
  meta = {
    description = "Verified Cargo sources with a borrowed CBOR seed entry";
  };
}
