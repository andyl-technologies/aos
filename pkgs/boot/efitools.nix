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
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  openssl,
  gnu-efi,
  stdenv,
}: let
  version = "1.9.2";
  hostPlatform = stdenv.hostPlatform;
  efiArch =
    if hostPlatform.isx86_64
    then "x86_64"
    else if hostPlatform.isAarch64
    then "aarch64"
    else throw "efitools: unsupported architecture ${hostPlatform.system}";
  # Host tools only — each links lib/lib.a + -lcrypto, no EFI crt.
  hostTools = "cert-to-efi-sig-list sign-efi-sig-list efi-updatevar efi-readvar cert-to-efi-hash-list hash-to-efi-sig-list sig-list-to-certs";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "efitools";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Efitools preserves the exact certificate through the ESL round trip.";
        "files" = {
          "certificate.pem" = "-----BEGIN CERTIFICATE-----\nMIICBDCCAW2gAwIBAgIUBpo7pnZgiu6BFkoZHAmIw523kQ0wDQYJKoZIhvcNAQEL\nBQAwFDESMBAGA1UEAwwJQU9TLVByb2JlMB4XDTI2MDkwODE4MTYwNloXDTM2MDkw\nNTE4MTYwNlowFDESMBAGA1UEAwwJQU9TLVByb2JlMIGfMA0GCSqGSIb3DQEBAQUA\nA4GNADCBiQKBgQDsf9H4+29Z0TBKfDviaHpzKyIddD0ft2CJjol2uiB9fa/EjshK\nYZ/tAQ+g2clVLsOotDsMvoCF5qxQBOmLpWU+d3Mm8cDjQemhsUofGvRQ0oDhBEO9\nygfHoxTtgG+4NbmxftXuDZiA79t7lfl3KBxRwT5ychOkhOwxSjcLwKbV+wIDAQAB\no1MwUTAdBgNVHQ4EFgQUD/NZzf0/C8lsVXxhdwMTGnv2XRowHwYDVR0jBBgwFoAU\nD/NZzf0/C8lsVXxhdwMTGnv2XRowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B\nAQsFAAOBgQAQTRLXhUH8Io0qtbCmgqcajHBEgeQKV4pPLBeN1GCQFu+4AIvM9Rjo\nsGYYcv1gaqIJHJSe5fgFKnZFhC+eGqY4pP8HqBac7cRyS8Stj453UKwJtHuy/nie\nIPASYzJSUrk84YRHhkFTw7ZR388UUFbbh26TaH6OCa/g0njP2+gQDg==\n-----END CERTIFICATE-----\n";
        };
        "input" = "A fixed X.509 certificate and a fixed EFI signature-owner GUID.";
        "operation" = "Encode the certificate as an EFI signature list, extract it, and compare the DER bytes.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/cert-to-efi-sig-list"
              "-g"
              "11111111-2222-3333-4444-555555555555"
              "certificate.pem"
              "certificate.esl"
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@out@/bin/sig-list-to-certs"
              "certificate.esl"
              "recovered"
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, ssl\nexpected = ssl.PEM_cert_to_DER_cert(pathlib.Path(\"certificate.pem\").read_text())\nassert pathlib.Path(\"recovered-0.der\").read_bytes() == expected\nprint(\"efitools round trip passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "efitools round trip passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Efitools rejects the incomplete request and prints its usage diagnostic.";
        "files" = {};
        "input" = "An extraction request with neither an ESL path nor an output basename.";
        "operation" = "Invoke the EFI signature-list extractor without its required arguments.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/sig-list-to-certs"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git/snapshot/efitools-${version}.tar.gz"
      ];
      hash = "sha256-DzFbNufRunS/yXq58wTwowcsR1eLvl5CWUrK44H5rP4=";
    };
    patches = [./efitools-openssl-4.patch];

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
          #   include/efi/${efiArch} → efisetjmp.h's "efisetjmp_arch.h"
          #   include/efi/protocol → EFI protocol headers
          # efilib.h pulls legacy/efilib.h, now shipped by gnu-efi.
          # -D_GNU_SOURCE declares strptime() (sign-efi-sig-list.c).
          # -DCONFIG_${efiArch} is restated because overriding CPPFLAGS
          # replaces the Makefile default.
          make -j$NIX_BUILD_CORES ${hostTools} \
            ARCH=${efiArch} \
            CPPFLAGS="-DCONFIG_${efiArch} -D_GNU_SOURCE -I${gnu-efi}/include -I${gnu-efi}/include/efi -I${gnu-efi}/include/efi/${efiArch} -I${gnu-efi}/include/efi/protocol"
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
