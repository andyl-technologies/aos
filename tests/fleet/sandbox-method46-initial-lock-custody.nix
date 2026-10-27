# Actual root/helper and normal-owner FD checks; no installed Source or TPM claim.
{
  mkSystem,
  pkgs,
  ...
}: let
  helperSource = ../../pkgs/security/aos-method46-tpm-helper;
  probe = pkgs.mkDerivation {
    pname = "aos-method46-initial-lock-custody-probe";
    version = "1";
    src = helperSource;
    runtimeDeps = [pkgs.tpm2-tss pkgs.openssl];
    phases = [
      {
        name = "build";
        script = ''
          set -eu
          for role in controller storage; do
            case "$role" in
              controller) selection=AOS_METHOD46_INITIAL_CONTROLLER_HELPER ;;
              storage) selection=AOS_METHOD46_INITIAL_STORAGE_HELPER ;;
            esac
            $CC -std=c17 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
              -D"$selection" -DAOS_METHOD46_LOCK_OWNER_REQUIRE_ROOT \
              -I"$src" -I${pkgs.tpm2-tss}/include/tss2 \
              "$src/initial-lock-owner-test.c" \
              -L${pkgs.tpm2-tss}/lib -ltss2-esys -ltss2-sys -ltss2-mu -lcrypto \
              -Wl,-rpath,${pkgs.tpm2-tss}/lib -o "initial-$role-lock-owner-test"
          done
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          for role in controller storage; do
            install -m 0555 "initial-$role-lock-owner-test" "$out/bin/"
          done
        '';
      }
    ];
  };
  system = mkSystem [
    ../../systems/server-test.nix
    {environment.systemPackages = [probe];}
  ];
in {
  name = "sandbox-method46-initial-lock-custody";
  timeout = 300;
  machines.vm = {inherit system;};
  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=120)
    for role in ("controller", "storage"):
        output = vm.succeed(f"${probe}/bin/initial-{role}-lock-owner-test")
        assert "native root-owned helper / fixed journal-owner lock custody PASS" in output, output
        assert "fixed initial METHOD46 helper lock-owner checks PASS" in output, output
        assert "NOT RUN" not in output, output
    vm.succeed("test -z \"$(find /tmp -maxdepth 1 -name 'aos-method46-initial-lock-owner-*' -print -quit)\"")
  '';
}
