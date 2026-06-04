##! aos-uki — Unified Kernel Image assembly
##!
##! Wraps `systemd-ukify` (from the AOS systemd package built with
##! -Dukify=enabled) to produce a signed PE-COFF binary that UEFI
##! firmware loads directly: the sd-stub prepended with kernel +
##! initrd + cmdline + os-release as appended PE sections. One UKI
##! per (kernel, initrd, cmdline, os-release) tuple; the image
##! builder drops it under EFI/Linux/ on the ESP and sd-boot
##! auto-discovers it.
##!
##! Arguments:
##!   kernel     — kernel derivation (provides /boot/vmlinuz-*)
##!   initrd     — initrd derivation (provides /initrd.img)
##!   cmdline    — plain string baked into the UKI's .cmdline section
##!   osRelease  — path to an os-release file (typically the
##!                toplevel's /etc/os-release)
##!   name       — slug used in the output filename
##!   version    — version string used in the output filename
##!   stub       — optional stub PE path; defaults to x86_64 stub
##!                from the systemd package
##!
##! Output: $out/aos-${name}-${version}.efi
{
  mkDerivation,
  systemd,
}: {
  kernel,
  initrd,
  cmdline,
  osRelease,
  name,
  version,
  stub ? null,
}: let
  effectiveStub =
    if stub != null
    then stub
    else "${systemd}/lib/systemd/boot/efi/linuxx64.efi.stub";
in
  mkDerivation {
    pname = "aos-uki-${name}";
    inherit version;
    src = null;

    # systemd carries `ukify` (and pefile/pyelftools via the wrapper) in
    # its `tools` output. The main systemd output is still needed for
    # the linuxx64.efi.stub (consumed via ${effectiveStub} below).
    buildDeps = [systemd.tools systemd];
    runtimeDeps = [];

    phases = [
      {
        name = "build";
        script = ''
          mkdir -p $out
          # cmdline arrives as a Nix string; materialize to a file so
          # ukify's @path read path handles special characters and
          # trailing-newline rules consistently.
          printf '%s' "${cmdline}" > cmdline

          # Resolve the kernel's actual vmlinuz path — the kernel
          # derivation names it with the upstream version suffix
          # (vmlinuz-6.18.12). ukify rejects glob patterns passed
          # as --linux=.
          vmlinuz=$(ls ${kernel}/boot/vmlinuz-* | head -n1)
          if [ -z "$vmlinuz" ]; then
            echo "aos-uki: no vmlinuz-* found under ${kernel}/boot/" >&2
            exit 1
          fi

          ${systemd.tools}/bin/ukify build \
            --stub=${effectiveStub} \
            --linux="$vmlinuz" \
            --initrd=${initrd}/initrd.img \
            --cmdline=@cmdline \
            --os-release=@${osRelease} \
            --output=$out/aos-${name}-${version}.efi
        '';
      }
    ];

    meta = {
      description = "AOS Unified Kernel Image (sd-stub + kernel + initrd + cmdline)";
    };
  }
