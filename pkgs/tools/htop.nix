##! htop — Interactive process viewer
{
  lib,
  mkDerivation,
  fetchurl,
  autoconf,
  automake,
  libtool,
  gnumake,
  pkg-config,
  ncurses,
  libcap,
  libnl,
  lm-sensors,
  systemd,
}: let
  version = "3.5.3";
in
  mkDerivation {
    pname = "htop";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Htop describes its delay, filter, sort, and tree options.";
        "files" = {};
        "input" = "The packaged interactive process viewer's option inventory.";
        "operation" = "Request help without opening the interactive display.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/htop\", \"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"--sort-key\" in result.stdout and \"--filter\" in result.stdout, (result.returncode, result.stdout, result.stderr)\nprint(\"htop operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "htop operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Htop rejects the unknown sort field.";
        "files" = {};
        "input" = "A sort request naming a field that does not exist.";
        "operation" = "Validate the sort field before opening the display.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/htop\", \"--sort-key=AOS_INVALID_FIELD\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"htop rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "htop rejected invalid input\n";
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
      urls = ["https://github.com/htop-dev/htop/archive/refs/tags/${version}.tar.gz"];
      hash = "sha256-7fJe4CClJj/7757vWowUOSv3Tniz1ci8ZNk0PdmoJgU=";
    };

    buildDeps = [autoconf automake libtool gnumake pkg-config];
    runtimeDeps = [ncurses libcap libnl lm-sensors systemd];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd htop-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i 's|/usr/include/libnl3|${libnl}/include/libnl3|' configure.ac
          sed -i \
            -e 's|libnl-3.so|${libnl}/lib/libnl-3.so|' \
            -e 's|libnl-genl-3.so|${libnl}/lib/libnl-genl-3.so|' \
            linux/LibNl.c
          sed -i \
            's|"libsensors.so"|"${lm-sensors}/lib/libsensors.so"|' \
            linux/LibSensors.c
          sed -i \
            's|"libsystemd.so.0"|"${systemd}/lib/libsystemd.so.0"|' \
            linux/SystemdMeter.c
          autoreconf -fi
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --sysconfdir=/etc \
            --enable-unicode \
            --enable-affinity \
            --enable-capabilities \
            --enable-delayacct \
            --enable-sensors
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-htop";
        tool = self;
        command = "htop --version";
      };
    };

    meta = {
      description = "Interactive process viewer";
      homepage = "https://htop.dev/";
      license = "GPL-2.0-only";
      mainProgram = "htop";
    };
  }
