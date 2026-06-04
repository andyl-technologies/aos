##! tzdata — IANA timezone database
##!
##! Builds the binary timezone database (share/zoneinfo) from the IANA
##! tzcode + tzdata source pair. Hermetic: no host-side `/usr/share/zoneinfo`
##! reference. Consumed by `modules/base/system.nix`'s `localtime` entry so
##! the composefs dump script sees a `/nix/store/...` path rather than a
##! host path.
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "2026b";
in
  mkDerivation {
    pname = "tzdata";
    inherit version;

    # IANA ships tzcode (the C source for zic) and tzdata (the zone
    # tables) as two tarballs; the canonical build extracts both into
    # the same directory.
    tzcodeSrc = fetchurl {
      urls = [
        "https://data.iana.org/time-zones/releases/tzcode${version}.tar.gz"
      ];
      hash = "sha256-N+nthCf101IcIvxY4pPL+wQ9cO7fEAOHCzPzY/Yco0Q=";
    };
    tzdataSrc = fetchurl {
      urls = [
        "https://data.iana.org/time-zones/releases/tzdata${version}.tar.gz"
      ];
      hash = "sha256-EUVD2fGaa/61vKQ2hq6hc9OHVaPbHy7sESZHrpLG9UQ=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir build
          cd build
          tar xzf "$tzcodeSrc"
          tar xzf "$tzdataSrc"
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES zic
        '';
      }
      {
        name = "install";
        # Compile the IANA primary tables (plus `backward` for legacy
        # aliases like `US/Pacific` → `America/Los_Angeles`, and
        # `factory` for the default-when-unset placeholder zone) into
        # the binary database. `-b slim` produces post-1970-only data
        # which is what glibc + systemd actually consume.
        script = ''
          mkdir -p $out/share/zoneinfo
          ./zic -b slim -d $out/share/zoneinfo \
            africa antarctica asia australasia europe \
            northamerica southamerica etcetera backward factory
        '';
      }
    ];

    meta = {
      description = "IANA timezone database (binary form)";
      homepage = "https://www.iana.org/time-zones";
      license = "Public Domain";
    };
  }
