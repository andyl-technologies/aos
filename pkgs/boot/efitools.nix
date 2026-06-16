##! efitools — UEFI Secure Boot key-management host tools
##!
##! Builds only the host-side utilities (cert-to-efi-sig-list,
##! sign-efi-sig-list, efi-updatevar, efi-readvar, …) — the ones that
##! create EFI signature lists / signed auth blobs and read or write the
##! SB variables through Linux efivarfs. The `.efi` applications
##! (KeyTool, LockDown) are deliberately NOT built: they need the
##! gnu-efi crt + an EFI ld script and we don't use them — RFC-0006
##! enrolls keys guest-side via efivarfs (`efi-updatevar`), mirroring the
##! Setup-Mode → User-Mode first-boot path.
##!
##! Used at two points: at build time the key-generation derivation runs
##! cert-to-efi-sig-list / sign-efi-sig-list to mint the PK/KEK/db ESLs
##! and signed `.auth` blobs; in the guest the test agent runs
##! efi-updatevar / efi-readvar to enroll and verify.
{
  mkDerivation,
  fetchurl,
  gnumake,
  openssl,
  gnu-efi,
}: let
  version = "1.9.2";
  # Host tools only — each links lib/lib.a + -lcrypto, no EFI crt.
  hostTools = "cert-to-efi-sig-list sign-efi-sig-list efi-updatevar efi-readvar cert-to-efi-hash-list hash-to-efi-sig-list sig-list-to-certs";
in
  mkDerivation {
    pname = "efitools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git/snapshot/efitools-${version}.tar.gz"
      ];
      hash = "sha256-DzFbNufRunS/yXq58wTwowcsR1eLvl5CWUrK44H5rP4=";
    };

    # gnu-efi supplies <efi.h> (the EFI type definitions efi-updatevar /
    # efi-readvar pull in); only headers are needed, the host tools don't
    # link libefi.
    buildDeps = [gnumake gnu-efi];
    # openssl provides -lcrypto + headers at build (C_INCLUDE_PATH /
    # LIBRARY_PATH come from runtimeDeps too) and is RPATH'd for runtime.
    runtimeDeps = [openssl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd efitools-${version}
        '';
      }
      {
        name = "build";
        script = ''
          # Build only the host utilities; their lib/lib.a dependency is
          # built automatically. The global CFLAGS carry EFI-ish flags
          # (-ffreestanding etc.) that the host tools tolerate.
          #
          # CPPFLAGS injects gnu-efi's headers while keeping Make.rules'
          # per-directory INCDIR/TOPDIR intact. The include roots cover
          # efitools' mixed styles and gnu-efi's own relative includes:
          #   include          → <efi/efi.h>, <efi/efilib.h> (lib/)
          #   include/efi      → bare <efi.h> (efi-updatevar.c)
          #   include/efi/x86_64 → efisetjmp.h's "efisetjmp_arch.h"
          #   include/efi/protocol → EFI protocol headers
          # efilib.h pulls legacy/efilib.h, now shipped by gnu-efi.
          # -D_GNU_SOURCE declares strptime() (sign-efi-sig-list.c).
          # -DCONFIG_x86_64 is restated because overriding CPPFLAGS
          # replaces the Makefile default. x86_64-only — all the SB
          # path targets.
          make -j$NIX_BUILD_CORES ${hostTools} \
            CPPFLAGS="-DCONFIG_x86_64 -D_GNU_SOURCE -I${gnu-efi}/include -I${gnu-efi}/include/efi -I${gnu-efi}/include/efi/x86_64 -I${gnu-efi}/include/efi/protocol"
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          for t in ${hostTools}; do
            cp "$t" "$out/bin/"
          done
        '';
      }
    ];

    meta = {
      description = "efitools — UEFI Secure Boot key-management host tools";
      homepage = "https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git";
      license = "GPL-2.0-only";
    };
  }
