##! procps-ng — Process monitoring utilities (ps, top, free, vmstat, etc.)
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  ncurses,
}: let
  version = "4.0.5";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "procps-ng";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The kernel reports the exact operating-system type Linux.";
        "files" = {};
        "input" = "The Linux kernel.ostype sysctl key.";
        "operation" = "Read the value through procps-ng sysctl.";
        "steps" = [
          {
            "argv" = [
              "@out@/sbin/sysctl"
              "-n"
              "kernel.ostype"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "Linux\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Sysctl rejects the key with status 1.";
        "files" = {};
        "input" = "A sysctl key absent from the kernel namespace.";
        "operation" = "Read the unknown key through procps-ng sysctl.";
        "steps" = [
          {
            "argv" = [
              "@out@/sbin/sysctl"
              "qualification.key.does.not.exist"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://sourceforge.net/projects/procps-ng/files/Production/procps-ng-${version}.tar.xz"
      ];
      hash = "sha256-wubRk8x4+EzW3bcqr21capFi8EcOWZIJIFf1/1GFYvo=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [ncurses];
    propagatedDeps = [];


    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd procps-ng-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-nls \
            --disable-modern-top \
            --disable-kill \
            --without-systemd \
            --with-ncurses
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
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "Process monitoring utilities (ps, top, free, vmstat, etc.)";
      homepage = "https://gitlab.com/procps-ng/procps";
      license = "GPL-2.0-or-later";
    };
  }
