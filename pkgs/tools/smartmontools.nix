##! smartmontools — S.M.A.R.T. disk monitoring tools (smartctl, smartd)
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  patch,
  patchelf,
  pkg-config,
  bash,
  coreutils,
  curl,
  gnupg,
  sed,
  stdenv,
  buildPackages,
}: let
  version = "7.5";
in
  mkDerivation {
    pname = "smartmontools";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Smartctl reports its version and bundled drive database release.";
        "files" = {};
        "input" = "The installed smartctl executable and drive database.";
        "operation" = "Query smartctl's build and database identity without opening a device.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/sbin/smartctl\", \"--version\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"smartctl\" in result.stdout and \"smartmontools\" in result.stdout\nprint(\"smartmontools operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "smartmontools operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Smartctl rejects the unknown device type.";
        "files" = {};
        "input" = "An unsupported smartctl device type for /dev/null.";
        "operation" = "Validate the device-type selector before issuing any disk command.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/sbin/smartctl\", \"--device\", \"qualification-invalid\", \"/dev/null\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"Unknown device type\" in result.stdout\n\nsys.stderr.write(\"smartmontools rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "smartmontools rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://sourceforge.net/projects/smartmontools/files/smartmontools/${version}/smartmontools-${version}.tar.gz"
      ];
      hash = "sha256-aQuDyjMTeNqeoNnWEAjEsi3eOROHubutfyk4fyWV924=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then [bash coreutils curl gnupg sed]
      else [];
    propagatedDeps = [];

    abilities = ./_smartmontools/module.nix;

    # Guard: keep the autotools build toolchain out of smartctl/smartd's
    # `--version` strings (which previously pinned xz-5.6.4 and the entire
    # live-bootstrap chain into the closure).
    disallowedReferences = [
      buildPackages.gnumake
      buildPackages.pkg-config
      buildPackages.patch
      buildPackages.patchelf
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd smartmontools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --sysconfdir=$out/etc \
            --without-systemdsystemunitdir \
            --without-nvme-devicescan
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            updateScript="$out/sbin/update-smart-drivedb"
            if [ -f "$updateScript" ]; then
              sed -i \
                -e "1s|^#!.*|#!${bash}/bin/bash|" \
                -e "s|^export PATH=.*|export PATH=\"${curl}/bin:${gnupg}/bin:${coreutils}/bin:${sed}/bin\"|" \
                "$updateScript"
            fi
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "S.M.A.R.T. disk monitoring tools (smartctl, smartd)";
      homepage = "https://www.smartmontools.org/";
      license = "GPL-2.0-or-later";
    };
  }
