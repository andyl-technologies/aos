##! checkpolicy — SELinux policy compiler and module compiler
{
  mkDerivation,
  fetchurl,
  gnumake,
  flex,
  bison,
  libsepol,
  libselinux,
}:
let
  version = "3.10";
in
mkDerivation {
  pname = "checkpolicy";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/SELinuxProject/selinux/releases/download/${version}/selinux-${version}.tar.gz"
    ];
    hash = "sha256-tHDgCV1FBpqAzs+Av5xRImQrycFU9BqnbTBQ6DfVmiA=";
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
  propagatedDeps = [ ];

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

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
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
