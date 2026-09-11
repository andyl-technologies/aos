##! aos-boot-identity — fail-closed normal boot command-line validator
{
  mkDerivation,
  rust,
  stdenv,
}: let
  source = ../../crates/aos-boot-identity;

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
    pname = "aos-boot-identity";
    version = "0.1.0";
    src = source;

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
            ${source}/src/lib.rs \
            -o libaos_boot_identity.rlib
          ${rustcCommand} --edition=2024 \
            ${source}/src/main.rs \
            --extern aos_boot_identity=libaos_boot_identity.rlib \
            -o aos-boot-identity
          ${rustcCommand} --edition=2024 --test ${source}/src/lib.rs -o aos-boot-identity-tests
          ./aos-boot-identity-tests
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-boot-identity $out/bin/
        '';
      }
    ];

    meta = {
      description = "Validate the AOS normal-boot identity tuple";
      license = "Apache-2.0";
    };
  }
