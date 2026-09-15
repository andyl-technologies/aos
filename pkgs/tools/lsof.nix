##! lsof — List open files
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  patch,
  patchelf,
  pkg-config,
  linux-headers,
  libtirpc,
  stdenv,
  buildPackages,
}: let
  version = "4.99.7";
in
  mkDerivation {
    pname = "lsof";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Lsof reports its revision and compiler identity.";
        "files" = {};
        "input" = "The packaged open-file inspector's release identity.";
        "operation" = "Request verbose version information without scanning processes.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/lsof\"] + [\"-v\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"revision:\" in result.stderr.lower() and \"compiler\" in result.stderr.lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"lsof primary passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "lsof primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Lsof rejects the unsupported option.";
        "files" = {};
        "input" = "An lsof invocation containing an unsupported long option.";
        "operation" = "Parse the invalid option without scanning processes.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/lsof\"] + [\"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"illegal option\" in result.stderr.lower(), (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"lsof rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "lsof rejected invalid input\n";
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
        "https://github.com/lsof-org/lsof/releases/download/${version}/lsof-${version}.tar.gz"
      ];
      hash = "sha256-ShA5GqsLjOH1OegqGWZpOyps8iWXKmUE67fsT6cWdd4=";
    };

    buildDeps =
      [
        gnumake
        pkg-config
      ]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then []
        else [linux-headers]
      );
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then []
      else [libtirpc];
    propagatedDeps = [];

    # Guard: keep the autotools build toolchain out of lsof's
    # `-v`-baked PKG_CONFIG_PATH / CC strings.
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
          cd lsof-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-dependency-tracking \
            ${
            if stdenv.hostPlatform.isDarwin
            then ""
            else "--with-libtirpc"
          }
        '';
      }
      {
        name = "build";
        script = ''
          cat > soelim-wrapper <<SCRIPT
          #!$CONFIG_SHELL
          cat "\$@"
          SCRIPT
          chmod +x soelim-wrapper
          PATH="$PWD:$PATH"
          ln -s soelim-wrapper soelim
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "List open files";
      homepage = "https://github.com/lsof-org/lsof";
      license = "lsof";
    };
  }
