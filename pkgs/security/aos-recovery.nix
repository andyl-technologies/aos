##! aos-recovery — bounded console application for the signed recovery initrd
{
  mkDerivation,
  rust,
  stdenv,
}: let
  identitySource = ../../crates/aos-boot-identity;
  recoverySource = ../../crates/aos-recovery;

  # The build compiler carries the target standard library; rustc still needs
  # an explicit target and linker because these recipes do not use Cargo.
  buildRust =
    if stdenv.isCross
    then rust.passthru.buildTool
    else rust;
  rustcCommand =
    if stdenv.isCross
    then "${buildRust}/bin/rustc --target ${stdenv.hostPlatform.config} -C linker=${stdenv.cc}/bin/cc"
    else "rustc";
in
  mkDerivation {
    pname = "aos-recovery";
    version = "0.1.0";
    src = recoverySource;

    buildDeps = [buildRust];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "build";
        script = ''
          ${rustcCommand} --edition=2024 \
            --crate-name aos_boot_identity \
            --crate-type rlib \
            ${identitySource}/src/lib.rs \
            -o libaos_boot_identity.rlib
          ${rustcCommand} --edition=2024 \
            --crate-name aos_recovery \
            --crate-type rlib \
            ${recoverySource}/src/lib.rs \
            --extern aos_boot_identity=libaos_boot_identity.rlib \
            -o libaos_recovery.rlib
          ${rustcCommand} --edition=2024 \
            ${recoverySource}/src/main.rs \
            --extern aos_boot_identity=libaos_boot_identity.rlib \
            --extern aos_recovery=libaos_recovery.rlib \
            -o aos-recovery
          ${rustcCommand} --edition=2024 --test ${recoverySource}/src/lib.rs \
            --extern aos_boot_identity=libaos_boot_identity.rlib \
            -o aos-recovery-tests
          ./aos-recovery-tests
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-recovery $out/bin/
        '';
      }
    ];

    meta = {
      description = "Run the bounded AOS signed-recovery console";
      license = "Apache-2.0";
    };
  }
