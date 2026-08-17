##! aos-boot-identity — fail-closed normal boot command-line validator
{
  mkDerivation,
  rust,
}: let
  source = ../../crates/aos-boot-identity;
in
mkDerivation {
  pname = "aos-boot-identity";
  version = "0.1.0";
  src = source;

  buildDeps = [rust];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    {
      name = "build";
      script = ''
        rustc --edition=2024 \
          --crate-name aos_boot_identity \
          --crate-type rlib \
          ${source}/src/lib.rs \
          -o libaos_boot_identity.rlib
        rustc --edition=2024 \
          ${source}/src/main.rs \
          --extern aos_boot_identity=libaos_boot_identity.rlib \
          -o aos-boot-identity
        rustc --edition=2024 --test ${source}/src/lib.rs -o aos-boot-identity-tests
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
