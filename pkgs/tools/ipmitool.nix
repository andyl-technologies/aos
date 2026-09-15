##! ipmitool — in-band and network IPMI management utility
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  automake,
  libtool,
  m4,
  pkg-config,
  openssl,
  readline,
  stdenv,
}: let
  version = "1.8.19";
in
  mkDerivation {
    pname = "ipmitool";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The command returns success and documents its invocation contract.";
        "files" = {};
        "input" = "The packaged ipmitool command-line interface.";
        "operation" = "Request its offline help text.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/ipmitool\", \"-h\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"interfaces\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"ipmitool operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "ipmitool operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The command rejects the unsupported option before performing external I/O.";
        "files" = {};
        "input" = "A ipmitool invocation containing an unsupported option.";
        "operation" = "Parse the invalid option without accessing a device or service.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/ipmitool\", \"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"ipmitool rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "ipmitool rejected invalid input\n";
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
        "https://github.com/ipmitool/ipmitool/archive/refs/tags/IPMITOOL_1_8_19.tar.gz"
      ];
      hash = "sha256-SLAQ57zfk+TktuQ8U8f2CqaHPVdMvUWo2G+nqu66/5w=";
    };

    buildDeps = [gnumake autoconf automake libtool m4 pkg-config];
    runtimeDeps = [openssl readline];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd ipmitool-IPMITOOL_1_8_19
        '';
      }
      {
        name = "configure";
        script = ''
          nativeLibtool=$(dirname "$(dirname "$(command -v libtoolize)")")
          export ACLOCAL_PATH="$nativeLibtool/share/aclocal''${ACLOCAL_PATH:+:$ACLOCAL_PATH}"
          sed -i '/AM_CONDITIONAL(\[DOWNLOAD\]/d' configure.ac
          sed -i '/AC_MSG_WARN(\[\*\* Download is:\])/i AM_CONDITIONAL([DOWNLOAD], [test "x$DOWNLOAD" != "x"])' configure.ac
          libtoolize --copy --force
          ./bootstrap
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-intf-open=${
            if stdenv.hostPlatform.isDarwin
            then "no"
            else "yes"
          } \
            --enable-intf-lan=yes \
            --enable-intf-lanplus=yes \
            --enable-intf-free=no \
            --enable-intf-dbus=no \
            --enable-intf-usb=no
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

    meta = {
      description = "Command-line utility for IPMI hardware management";
      homepage = "https://github.com/ipmitool/ipmitool";
      license = "BSD-3-Clause";
    };
  }
