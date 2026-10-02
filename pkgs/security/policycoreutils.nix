##! policycoreutils — SELinux core policy utilities
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  gettext,
  libsepol,
  libselinux,
  libsemanage,
  libxcrypt,
  audit,
}: let
  version = "3.11";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "policycoreutils";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Secon prints system_u exactly.";
        "files" = {};
        "input" = "The SELinux context system_u:system_r:init_t:s0.";
        "operation" = "Extract its user component through secon.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/secon"
              "-u"
              "system_u:system_r:init_t:s0"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "system_u\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Secon rejects the malformed context with status 1.";
        "files" = {};
        "input" = "A security context containing only one field.";
        "operation" = "Extract its user through secon.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/secon"
              "-u"
              "missing-fields"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "secon: Couldn't create context from: missing-fields\n";
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
        "https://github.com/SELinuxProject/selinux/releases/download/${version}/selinux-${version}.tar.gz"
      ];
      hash = "sha256-a21Hqw81/hwJvaDGKCHI2XoMvn9ulASzON973gGCxPQ=";
    };

    buildDeps = [
      gnumake
      pkg-config
      gettext
    ];
    runtimeDeps = [
      libsepol
      libselinux
      libsemanage
      libxcrypt
      audit
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd selinux-${version}/policycoreutils
        '';
      }
      {
        name = "build";
        script = ''
          make PREFIX=$out SBINDIR=$out/sbin \
            CFLAGS="-I${libsepol}/include -I${libselinux}/include -I${libsemanage}/include -I${audit}/include -I${libxcrypt}/include" \
            LDFLAGS="-L${libsepol}/lib -L${libselinux}/lib -L${libsemanage}/lib -L${audit}/lib -L${libxcrypt}/lib" \
            -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          # Fix po/Makefile: replace hardcoded /usr/bin/install with install
          sed -i 's|/usr/bin/install|install|g' po/Makefile
          make install PREFIX=$out SBINDIR=$out/sbin ETCDIR=$out/etc \
            DESTDIR=""
        '';
      }
    ];

    meta = {
      description = "policycoreutils — SELinux core policy management utilities";
      homepage = "https://github.com/SELinuxProject/selinux";
      license = "GPL-2.0-or-later";
    };
  }
