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
  stdenv,
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
        script =
          if stdenv.isCross
          then ''
            # zic compiles the architecture-independent zone database and is
            # executed during install. Keep this build-machine generator away
            # from the target SDK and cross hardening/linker flags.
            native_cc="$BUILD_CC"
            mkdir -p .aos-build-tools
            cat > .aos-build-tools/cc <<EOF
            #!$CONFIG_SHELL
            unset AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM
            unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
            unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
            exec "$native_cc" "\$@"
            EOF
            chmod +x .aos-build-tools/cc

            make -j$NIX_BUILD_CORES CC="$PWD/.aos-build-tools/cc" zic
          ''
          else ''
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
