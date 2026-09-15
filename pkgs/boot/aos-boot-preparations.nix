##! aos-boot-preparations - exact compiled initrd configuration commands
{
  lib,
  mkDerivation,
  rust,
  aos,
  erofs-utils,
  util-linux,
}: let
  source = ../../crates/aos-boot-preparations;
  packageRuntime = aos.packageRuntime;
in
  mkDerivation {
    pname = "aos-boot-preparations";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-boot-preparations";
      entryPoint = "bin/aos-boot-preparations";
    };

    version = "0.1.0";
    src = source;

    buildDeps = [rust];
    runtimeDeps = [packageRuntime erofs-utils util-linux];
    propagatedDeps = [];
    abilities = ./_aos-boot-preparations/module.nix;

    phases = [
      {
        name = "build";
        script = ''
          export AOS_PACKAGE_RUNTIME=${packageRuntime}/bin/.aos-package-runtime-unwrapped
          export AOS_MKFS_EROFS=${erofs-utils}/bin/mkfs.erofs
          export AOS_FSCK_EROFS=${erofs-utils}/bin/fsck.erofs
          export AOS_MOUNT=${util-linux}/bin/mount

          rustc --edition=2024 ${source}/src/main.rs -o aos-boot-preparations
          rustc --edition=2024 --test ${source}/src/main.rs -o aos-boot-preparations-tests
          ./aos-boot-preparations-tests
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-boot-preparations $out/bin/
        '';
      }
    ];

    meta = {
      description = "Exact compiled initrd configuration preparations";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "aos-boot-preparations";
    };
  }
