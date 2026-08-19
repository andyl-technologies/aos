##! aos-vm — host CLI closure with local QEMU/UEFI runtime tools.
##!
##! The base `aos` package stays suitable for inclusion in AOS guest images.
##! This opt-in host wrapper adds the emulator, firmware, and GPT tooling used
##! by `aos vm run` without pulling them into every system root filesystem.
{
  mkDerivation,
  aos,
  edk2,
  gptfdisk,
  qemu,
}:
mkDerivation {
  pname = "aos-vm";
  version = aos.version;
  src = null;

  runtimeDeps = [aos edk2 gptfdisk qemu];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"

        sed \
          -e '/^exec /i export AOS_OVMF_CODE="${edk2}/FV/OVMF_CODE.fd"' \
          -e '/^exec /i export AOS_OVMF_VARS="${edk2}/FV/OVMF_VARS.fd"' \
          -e '/^exec /i export AOS_QEMU="${qemu}/bin/qemu-system-x86_64"' \
          -e '/^exec /i export AOS_SGDISK="${gptfdisk}/sbin/sgdisk"' \
          "${aos}/bin/aos" > "$out/bin/aos"
        chmod +x "$out/bin/aos"
        ln -s "${aos}/bin/apr" "$out/bin/apr"
      '';
    }
  ];

  meta = {
    description = "AOS CLI with QEMU, OVMF, and GPT tools for local virtual machines";
    homepage = "https://github.com/andyl-technologies/aos";
    license = "MIT";
  };
}
