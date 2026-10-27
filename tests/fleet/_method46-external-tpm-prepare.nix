# Host-only hierarchy setup; this executable never enters the guest image.
{pkgs}:
pkgs.mkDerivation {
  pname = "aos-method46-external-tpm-prepare";
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
          ${../sandbox/method46-external-tpm-prepare.c} \
          -L${pkgs.tpm2-tss}/lib \
          -ltss2-esys -ltss2-sys -ltss2-tcti-swtpm -ltss2-tcti-device -ltss2-mu -lcrypto \
          -Wl,-rpath,${pkgs.tpm2-tss}/lib -o method46-external-tpm-prepare
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        install -m 0555 method46-external-tpm-prepare "$out/bin/"
      '';
    }
  ];
}
