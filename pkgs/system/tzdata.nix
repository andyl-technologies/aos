##! tzdata — IANA timezone database
##!
##! Builds the binary timezone database (share/zoneinfo) from the IANA
##! tzcode + tzdata source pair. Hermetic: no host-side `/usr/share/zoneinfo`
##! reference. Consumed by `modules/base/system.nix`'s `localtime` entry so
##! the composefs dump script sees a `/nix/store/...` path rather than a
##! host path.
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "2026c";
  tzcodeSrc = fetchurl {
    urls = [
      "https://data.iana.org/time-zones/releases/tzcode${version}.tar.gz"
    ];
    hash = "sha256-sc/8Os5MTHzQ77ovet2G7D0LedpIvPA1gmcf08j+rOg=";
  };
  tzdataSrc = fetchurl {
    urls = [
      "https://data.iana.org/time-zones/releases/tzdata${version}.tar.gz"
    ];
    hash = "sha256-5KF4pEd/PQ6nfMMYKP9yqjj+/41hqhPn6Z4ULp2QK+Q=";
  };
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "tzdata";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The zone reports UTC-08:00 in January and UTC-07:00 in July.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\n\n\nfrom datetime import datetime, timezone, timedelta\nfrom zoneinfo import ZoneInfo, reset_tzpath\nreset_tzpath([\"@out@/share/zoneinfo\"])\nzone = ZoneInfo(\"America/Los_Angeles\")\nassert datetime(2026, 1, 15, tzinfo=timezone.utc).astimezone(zone).utcoffset() == timedelta(hours=-8)\nassert datetime(2026, 7, 15, tzinfo=timezone.utc).astimezone(zone).utcoffset() == timedelta(hours=-7)\n\n";
        };
        "input" = "The America/Los_Angeles zone and two UTC instants on opposite sides of the 2026 daylight transition.";
        "operation" = "Load the packaged TZif data with Python zoneinfo and inspect both offsets.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "ZoneInfo rejects the key with ZoneInfoNotFoundError.";
        "files" = {
          "probe.py" = "import glob\nimport sys\n\n\n\nfrom zoneinfo import ZoneInfo, ZoneInfoNotFoundError, reset_tzpath\nreset_tzpath([\"@out@/share/zoneinfo\"])\ntry:\n    ZoneInfo(\"Qualification/Zone-Does-Not-Exist\")\nexcept ZoneInfoNotFoundError:\n    pass\nelse:\n    raise RuntimeError(\"zoneinfo accepted a nonexistent zone\")\n\n";
        };
        "input" = "A time-zone key absent from the IANA database.";
        "operation" = "Resolve the nonexistent key from the packaged TZif tree.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "probe.py"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    # IANA ships tzcode (the C source for zic) and tzdata (the zone
    # tables) as two tarballs; the canonical build extracts both into
    # the same directory.
    inherit tzcodeSrc tzdataSrc;

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    passthru.evidenceSources = [
      tzcodeSrc
      tzdataSrc
    ];

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
