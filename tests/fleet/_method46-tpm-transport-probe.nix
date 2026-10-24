# Test-only provisioning authority around the production ESYS implementation.
{pkgs}:
pkgs.mkDerivation {
  pname = "aos-method46-tpm-transport-probe";
  version = "1";
  src = null;
  runtimeDeps = [pkgs.tpm2-tss pkgs.openssl];
  phases = [
    {
      name = "build";
      script = ''
        $CC -std=c17 -O2 -Wall -Wextra -Werror \
          -I${../../pkgs/security/aos-method46-tpm-helper} \
          -I${pkgs.tpm2-tss}/include/tss2 \
          ${../sandbox/method46-tpm-transport-probe.c} \
          -L${pkgs.tpm2-tss}/lib \
          -ltss2-esys -ltss2-sys -ltss2-tcti-device -ltss2-mu -lcrypto \
          -Wl,-rpath,${pkgs.tpm2-tss}/lib -o method46-tpm-transport-probe
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        cp method46-tpm-transport-probe $out/bin/
      '';
    }
  ];
}
