##! aos-boot-preparations - exact compiled initrd configuration commands
{
  lib,
  mkDerivation,
  rust,
  aos,
  nix,
  service-management,
  aos-boot-storage,
  aos-configuration-lower,
  bash,
  coreutils,
  erofs-utils,
  jq,
  sbsigntools,
  tpm2-tools,
  util-linux,
}: let
  source = ../../crates/aos-boot-preparations;
  packageRuntime = aos.packageRuntime;
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "aos-boot-preparations";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-boot-preparations";
      entryPoint = "bin/aos-boot-preparations";
    };

    version = "0.1.0";
    src = source;

    buildDeps = [rust];
    runtimeDeps = [
      nix
      aos-configuration-lower
      packageRuntime
      bash
      coreutils
      erofs-utils
      jq
      sbsigntools
      tpm2-tools
      util-linux
    ];
    propagatedDeps = [];
    module = ./_aos-boot-preparations;
    moduleDeps = [service-management aos-boot-storage];

    phases = [
      {
        name = "build";
        script = ''
          export AOS_PACKAGE_RUNTIME=${packageRuntime}/bin/aos-package-runtime
          export AOS_BOOT_CONFIGURATION=${packageRuntime}/bin/aos-boot-configuration
          export AOS_CONFIGURATION_BOOT=${aos-configuration-lower}/bin/aos-configuration-boot

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
          for source in ${./_aos-boot-preparations}/*.sh; do
            destination="$out/bin/$(basename "$source" .sh)"
            sed -e 's|@bash@|${bash}|g' \
              -e 's|@package_runtime@|${packageRuntime}|g' \
              -e 's|@util_linux@|${util-linux}|g' \
              -e 's|@nix@|${nix}|g' \
              -e 's|@coreutils@|${coreutils}|g' \
              "$source" > "$destination"
            chmod 0555 "$destination"
          done
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
