##! checkpolicy — SELinux policy compiler and module compiler
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  flex,
  bison,
  libsepol,
  libselinux,
}: let
  version = "3.11";
in
  mkDerivation {
    pname = "checkpolicy";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Checkmodule accepts the declarations and emits binary policy.";
        "files" = {
          "probe.te" = "module aos_probe 1.0;\n\nrequire {\n    type init_t;\n    class file read;\n}\n\nallow init_t init_t:file read;\n";
        };
        "input" = "A loadable SELinux policy module granting one file permission.";
        "operation" = "Compile the module source with checkmodule.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/checkmodule"
              "-M"
              "-m"
              "-o"
              "probe.mod"
              "probe.te"
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
        "expected" = "Checkmodule rejects the syntax error with status 1.";
        "files" = {
          "invalid.te" = "module aos_bad 1.0;\nrequire { type init_t; class file read; }\nallow init_t init_t:file read\n";
        };
        "input" = "A policy module whose allow rule omits its terminating semicolon.";
        "operation" = "Compile the malformed module source with checkmodule.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/checkmodule"
              "-M"
              "-m"
              "-o"
              "invalid.mod"
              "invalid.te"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
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
      flex
      bison
    ];
    runtimeDeps = [
      libsepol
      libselinux
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd selinux-${version}/checkpolicy
        '';
      }
      {
        name = "build";
        script = ''
          make PREFIX=$out BINDIR=$out/bin \
            -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install PREFIX=$out BINDIR=$out/bin
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      policy = testing.mkVMTest {
        name = "cross-cutting-selinux-policy";
        rootfsDeps = [
          self
          pkgs.libsepol
          pkgs.libselinux
        ];
        testScript = ''
          export PATH="${self}/bin:$PATH"
          export LD_LIBRARY_PATH="${self}/lib:${pkgs.libsepol}/lib:${pkgs.libselinux}/lib:$LD_LIBRARY_PATH"

          # Create a minimal SELinux type enforcement file
          cat > /tmp/test_module.te << 'EOF'
          policy_module(test_module, 1.0.0)

          type test_t;
          EOF

          echo "==> Compiling SELinux policy module with checkpolicy"
          # checkmodule compiles .te to .mod
          checkmodule -M -m -o /tmp/test_module.mod /tmp/test_module.te
          echo "    Module compiled: $(ls -l /tmp/test_module.mod | cut -d' ' -f5) bytes"

          echo "SELinux policy: PASS"
        '';
      };
    };

    meta = {
      description = "checkpolicy — SELinux policy compiler (checkpolicy, checkmodule)";
      homepage = "https://github.com/SELinuxProject/selinux";
      license = "GPL-2.0-or-later";
    };
  }
