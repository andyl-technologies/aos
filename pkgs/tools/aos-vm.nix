##! aos-vm — host CLI closure with local QEMU/UEFI runtime tools.
##!
##! The base `aos` package stays suitable for inclusion in AOS guest images.
##! This opt-in host wrapper adds the emulator, firmware, and GPT tooling used
##! by `aos vm run` without pulling them into every system root filesystem.
{
  mkDerivation,
  aos,
  bash,
  edk2,
  gptfdisk,
  qemu,
}:
mkDerivation {
  pname = "aos-vm";
  version = aos.version;
  src = null;

  runtimeDeps = [aos bash edk2 gptfdisk qemu];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"

        cat > "$out/bin/aos" <<EOF
        #!${bash}/bin/bash
        export AOS_OVMF_CODE="${edk2}/FV/OVMF_CODE.fd"
        export AOS_OVMF_VARS="${edk2}/FV/OVMF_VARS.fd"
        export AOS_QEMU="${qemu}/bin/qemu-system-x86_64"
        export AOS_SGDISK="${gptfdisk}/sbin/sgdisk"
        exec ${aos}/bin/aos "\$@"
        EOF

        cat > "$out/bin/apr" <<EOF
        #!${bash}/bin/bash
        exec ${aos}/bin/apr "\$@"
        EOF

        chmod +x "$out/bin/aos" "$out/bin/apr"
      '';
    }
  ];

  meta = {
    description = "AOS CLI with QEMU, OVMF, and GPT tools for local virtual machines";
    homepage = "https://github.com/andyl-technologies/aos";
    license = "MIT";
  };
}
