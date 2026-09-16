##! aos-boot-preparations - exact compiled initrd configuration commands
{
  lib,
  mkDerivation,
  rust,
  aos,
  bash,
  coreutils,
  erofs-utils,
  jq,
  sbsigntools,
  systemd,
  tpm2-tools,
  util-linux,
}: let
  source = ../../crates/aos-boot-preparations;
  packageRuntime = aos.packageRuntime;
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
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
      packageRuntime
      bash
      coreutils
      erofs-utils
      jq
      sbsigntools
      systemd
      tpm2-tools
      util-linux
    ];
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
          mkdir -p $out/bin $out/lib/systemd/system
          cp aos-boot-preparations $out/bin/
          for source in ${./_aos-boot-preparations}/*.sh; do
            destination="$out/bin/$(basename "$source" .sh)"
            sed 's|@bash@|${bash}|g' "$source" > "$destination"
            chmod 0555 "$destination"
          done

          sed \
            's#^ExecStart=.*#ExecStart=${systemd}/lib/systemd/systemd-networkd-wait-online --any#' \
            ${systemd}/lib/systemd/system/systemd-networkd-wait-online.service \
            > $out/lib/systemd/system/systemd-networkd-wait-online.service
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
