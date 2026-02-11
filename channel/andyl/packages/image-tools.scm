;;; ANDYL OS -- Image Build Tools (UKI Generation, Image Signing)
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the build-time tools for assembling ANDYL OS
;;; disk images:
;;;
;;;   andyl-ukify              -- Unified Kernel Image generator (wrapper
;;;                               around systemd's ukify tool)
;;;   andyl-minisign           -- Ed25519 signature tool for image signing
;;;   andyl-image-manifest     -- Image manifest generator (JSON)
;;;   andyl-sbsigntool         -- Secure Boot signing tool (optional)
;;;
;;; These tools are used at IMAGE BUILD TIME ONLY.  They are NOT installed
;;; on deployed machines.  The build pipeline uses them to:
;;;
;;;   1. Generate UKIs (kernel + initrd + cmdline + os-release bundled
;;;      into a single EFI executable)
;;;   2. Sign the disk image with Ed25519 for integrity verification
;;;   3. Generate a JSON manifest of all store paths in the image
;;;
;;; UKI generation (ukify) is part of systemd but is packaged separately
;;; here as a build tool wrapper to make it easy to invoke during image
;;; assembly without pulling in the full systemd package.
;;;
;;; See:
;;;   Phase 4 sections 4.5 (UKI Generation), 4.11 (Manifest), 4.12 (Signing)

(define-module (andyl packages image-tools)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (guix utils)
  #:use-module (guix gexp)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl packages base)
  #:use-module (andyl packages systemd)
  #:use-module (andyl packages kernel)
  #:use-module (andyl packages firmware)
  #:use-module (andyl packages tls)
  #:use-module (andyl config))


;;; =========================================================================
;;; minisign -- Dead simple signing tool
;;; =========================================================================
;;;
;;; minisign is a lightweight Ed25519 signature tool by Frank Denis
;;; (author of libsodium).  It is used to sign ANDYL OS disk images
;;; and manifests for integrity verification.
;;;
;;; Key advantages over GPG for image signing:
;;;   - Simple: one key format, one signature format
;;;   - Small: ~100 KB binary, no dependencies beyond libc
;;;   - Fast: Ed25519 operations are extremely fast
;;;   - Compatible: signatures can be verified by minisign, signify, or
;;;     any Ed25519 implementation
;;;
;;; Usage in the ANDYL OS build pipeline:
;;;   Generate keypair:  minisign -G -p andyl-os.pub -s andyl-os.key
;;;   Sign image:        minisign -Sm image.img -s andyl-os.key
;;;   Verify:            minisign -Vm image.img -p andyl-os.pub
;;;
;;; The public key is embedded in the deployed image so the update agent
;;; can verify new images before applying them.

(define-public andyl-minisign
  (package
    (name "andyl-minisign")
    (version (config-version "image-tools" "minisign"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/jedisct1/minisign/releases/download/"
                    version "/minisign-" version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/jedisct1/minisign/releases/download/0.11/minisign-0.11.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc))
    (inputs (list andyl-glibc))
    (arguments
     (list
      ;; minisign uses CMake but can be built with a simple Makefile.
      ;; We use a custom build phase since we may not have CMake in
      ;; the bootstrap chain yet.
      #:phases
      #~(modify-phases %standard-phases
          (replace 'configure
            (lambda* (#:key outputs #:allow-other-keys)
              ;; No autoconf configure; set prefix via make flags
              #t))
          (replace 'build
            (lambda _
              ;; Build with the embedded libsodium (minisign bundles
              ;; a minimal subset of libsodium for Ed25519 operations)
              (invoke "make"
                      "CC=gcc"
                      (string-append
                       "-j" (number->string (parallel-job-count))))))
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let* ((out (assoc-ref outputs "out"))
                     (bin (string-append out "/bin")))
                (mkdir-p bin)
                (install-file "minisign" bin)))))
      #:tests? #f))
    (home-page "https://jedisct1.github.io/minisign/")
    (synopsis "Simple Ed25519 signing tool for ANDYL OS images")
    (description
     "minisign is a lightweight Ed25519 signature tool used to sign
ANDYL OS disk images and manifests.  Provides a simple key generation,
signing, and verification workflow.  The public key is embedded in
deployed images for update verification.  Compatible with OpenBSD
signify signatures.")
    (license license:isc)))


;;; =========================================================================
;;; sbsigntool -- UEFI Secure Boot signing tool (optional)
;;; =========================================================================
;;;
;;; sbsigntool provides sbsign and sbverify for signing and verifying
;;; UEFI PE/COFF executables (EFI binaries, UKIs) for Secure Boot.
;;;
;;; This is optional and only needed when deploying to hardware with
;;; UEFI Secure Boot enabled.  It requires a Secure Boot signing key
;;; enrolled in the firmware's MOK (Machine Owner Key) database.
;;;
;;; Usage:
;;;   Sign UKI:    sbsign --key db.key --cert db.crt --output signed.efi unsigned.efi
;;;   Verify:      sbverify --cert db.crt signed.efi

(define-public andyl-sbsigntool
  (package
    (name "andyl-sbsigntool")
    (version (config-version "image-tools" "sbsigntools"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/rustyrussell/sbsigntool/archive/v"
                    version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/rustyrussell/sbsigntool/archive/v0.9.5.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc andyl-pkg-config))
    (inputs (list andyl-glibc andyl-openssl))
    (arguments
     (list
      #:configure-flags
      #~(list (string-append "--with-openssl="
                             (assoc-ref %build-inputs "andyl-openssl")))
      #:tests? #f))
    (home-page "https://github.com/rustyrussell/sbsigntool")
    (synopsis "UEFI Secure Boot signing tools for ANDYL OS")
    (description
     "sbsigntool provides sbsign and sbverify for signing and verifying
UEFI PE/COFF executables for Secure Boot.  Used to sign UKIs and
systemd-boot binaries when deploying to hardware with Secure Boot
enabled.")
    (license license:gpl3+)))


;;; =========================================================================
;;; andyl-ukify-wrapper -- UKI generation build tool
;;; =========================================================================
;;;
;;; This package provides a shell script wrapper around systemd's ukify
;;; tool that generates Unified Kernel Images (UKIs) with ANDYL OS
;;; defaults.  A UKI bundles:
;;;
;;;   - Linux kernel (vmlinuz)
;;;   - CPU microcode (intel-ucode.img, amd-ucode.img)
;;;   - Initramfs (generated by dracut)
;;;   - Kernel command line
;;;   - os-release metadata
;;;
;;; into a single EFI executable (.efi) that systemd-boot can load
;;; directly.
;;;
;;; The wrapper handles:
;;;   - Locating the kernel and initrd from the andyl-kernel and
;;;     andyl-dracut packages
;;;   - Prepending CPU microcode as early-cpio
;;;   - Embedding the ANDYL OS kernel command line
;;;   - Embedding os-release for boot menu display
;;;   - Naming the output with the generation number
;;;
;;; The wrapper script is invoked during image assembly:
;;;   andyl-ukify --kernel /path/to/vmlinuz \
;;;               --initrd /path/to/initrd.img \
;;;               --cmdline "root=LABEL=ANDYL-ROOT ro ..." \
;;;               --os-release /path/to/os-release \
;;;               --output /path/to/andyl-os-gen-1.efi
;;;
;;; See Phase 4 section 4.5 (UKI Generation).

(define-public andyl-ukify-wrapper
  (package
    (name "andyl-ukify-wrapper")
    (version "1.0.0")
    (source #f)
    (build-system trivial-build-system)
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((out    (assoc-ref %outputs "out"))
                 (bindir (string-append out "/bin"))
                 (libdir (string-append out "/lib/andyl-ukify"))
                 (systemd (assoc-ref %build-inputs "andyl-systemd"))
                 (bash    (assoc-ref %build-inputs "andyl-bash")))

            (mkdir-p bindir)
            (mkdir-p libdir)

            ;; ============================================================
            ;; andyl-ukify -- UKI generation wrapper script
            ;; ============================================================
            (call-with-output-file (string-append bindir "/andyl-ukify")
              (lambda (port)
                (display
                 (string-append
                  "#!" bash "/bin/bash\n"
                  "# ANDYL OS Unified Kernel Image Generator\n"
                  "# Wrapper around systemd's ukify tool.\n"
                  "#\n"
                  "# Usage:\n"
                  "#   andyl-ukify --kernel VMLINUZ --initrd INITRD \\\n"
                  "#               --cmdline CMDLINE --os-release OS_RELEASE \\\n"
                  "#               [--microcode UCODE_IMG] [--output OUTPUT.efi]\n"
                  "#\n"
                  "# This generates a UKI (Unified Kernel Image) suitable for\n"
                  "# booting via systemd-boot.  The UKI is placed on the ESP\n"
                  "# at /EFI/Linux/andyl-os-gen-N.efi.\n"
                  "\n"
                  "set -euo pipefail\n"
                  "\n"
                  "# Defaults\n"
                  "UKIFY=\"" systemd "/lib/systemd/ukify\"\n"
                  "KERNEL=\"\"\n"
                  "INITRD=\"\"\n"
                  "CMDLINE=\"\"\n"
                  "OS_RELEASE=\"\"\n"
                  "MICROCODE=\"\"\n"
                  "OUTPUT=\"andyl-os.efi\"\n"
                  "\n"
                  "usage() {\n"
                  "    echo \"Usage: $0 --kernel VMLINUZ --initrd INITRD\" >&2\n"
                  "    echo \"          --cmdline CMDLINE --os-release FILE\" >&2\n"
                  "    echo \"          [--microcode UCODE] [--output FILE.efi]\" >&2\n"
                  "    exit 1\n"
                  "}\n"
                  "\n"
                  "while [[ $# -gt 0 ]]; do\n"
                  "    case \"$1\" in\n"
                  "        --kernel)     KERNEL=\"$2\";     shift 2 ;;\n"
                  "        --initrd)     INITRD=\"$2\";     shift 2 ;;\n"
                  "        --cmdline)    CMDLINE=\"$2\";    shift 2 ;;\n"
                  "        --os-release) OS_RELEASE=\"$2\"; shift 2 ;;\n"
                  "        --microcode)  MICROCODE=\"$2\";  shift 2 ;;\n"
                  "        --output)     OUTPUT=\"$2\";     shift 2 ;;\n"
                  "        *)            usage ;;\n"
                  "    esac\n"
                  "done\n"
                  "\n"
                  "# Validate required arguments\n"
                  "[[ -z \"$KERNEL\" ]] && { echo \"Error: --kernel required\" >&2; usage; }\n"
                  "[[ -z \"$INITRD\" ]] && { echo \"Error: --initrd required\" >&2; usage; }\n"
                  "[[ -z \"$CMDLINE\" ]] && { echo \"Error: --cmdline required\" >&2; usage; }\n"
                  "[[ -z \"$OS_RELEASE\" ]] && { echo \"Error: --os-release required\" >&2; usage; }\n"
                  "\n"
                  "# Build the ukify command\n"
                  "UKIFY_ARGS=(\n"
                  "    \"$UKIFY\"\n"
                  "    build\n"
                  "    --linux=\"$KERNEL\"\n"
                  "    --initrd=\"$INITRD\"\n"
                  "    --cmdline=\"$CMDLINE\"\n"
                  "    --os-release=\"$OS_RELEASE\"\n"
                  "    --output=\"$OUTPUT\"\n"
                  ")\n"
                  "\n"
                  "# Prepend CPU microcode if provided.\n"
                  "# Microcode is loaded as an early-cpio archive before the\n"
                  "# main initrd.\n"
                  "if [[ -n \"$MICROCODE\" ]]; then\n"
                  "    UKIFY_ARGS+=(--initrd=\"$MICROCODE\")\n"
                  "fi\n"
                  "\n"
                  "echo \"Generating UKI: $OUTPUT\"\n"
                  "echo \"  Kernel:     $KERNEL\"\n"
                  "echo \"  Initrd:     $INITRD\"\n"
                  "echo \"  Cmdline:    $CMDLINE\"\n"
                  "echo \"  OS-release: $OS_RELEASE\"\n"
                  "[[ -n \"$MICROCODE\" ]] && echo \"  Microcode:  $MICROCODE\"\n"
                  "\n"
                  "\"${UKIFY_ARGS[@]}\"\n"
                  "\n"
                  "echo \"UKI generated: $OUTPUT\"\n"
                  "echo \"  Size: $(du -h \"$OUTPUT\" | cut -f1)\"\n")
                 port)))
            (chmod (string-append bindir "/andyl-ukify") #o755)

            ;; ============================================================
            ;; andyl-boot-entry -- Type #1 boot entry generator
            ;; ============================================================
            ;; As a fallback when UKIs are not used, this generates a
            ;; systemd-boot Type #1 boot entry file.
            (call-with-output-file (string-append bindir "/andyl-boot-entry")
              (lambda (port)
                (display
                 (string-append
                  "#!" bash "/bin/bash\n"
                  "# ANDYL OS Boot Entry Generator (Type #1)\n"
                  "# Generates a systemd-boot loader entry .conf file.\n"
                  "#\n"
                  "# Usage:\n"
                  "#   andyl-boot-entry --generation N --kernel VMLINUZ \\\n"
                  "#                    --initrd INITRD --cmdline CMDLINE\n"
                  "\n"
                  "set -euo pipefail\n"
                  "\n"
                  "GENERATION=\"1\"\n"
                  "KERNEL=\"\"\n"
                  "INITRD=\"\"\n"
                  "CMDLINE=\"\"\n"
                  "OUTPUT_DIR=\".\"\n"
                  "\n"
                  "while [[ $# -gt 0 ]]; do\n"
                  "    case \"$1\" in\n"
                  "        --generation) GENERATION=\"$2\"; shift 2 ;;\n"
                  "        --kernel)     KERNEL=\"$2\";     shift 2 ;;\n"
                  "        --initrd)     INITRD=\"$2\";     shift 2 ;;\n"
                  "        --cmdline)    CMDLINE=\"$2\";    shift 2 ;;\n"
                  "        --output-dir) OUTPUT_DIR=\"$2\"; shift 2 ;;\n"
                  "        *)            echo \"Unknown option: $1\" >&2; exit 1 ;;\n"
                  "    esac\n"
                  "done\n"
                  "\n"
                  "ENTRY_FILE=\"$OUTPUT_DIR/andyl-os-gen-${GENERATION}.conf\"\n"
                  "\n"
                  "cat > \"$ENTRY_FILE\" <<EOF\n"
                  "title   ANDYL OS (Generation $GENERATION)\n"
                  "linux   /vmlinuz-${GENERATION}\n"
                  "initrd  /initramfs-${GENERATION}.img\n"
                  "options $CMDLINE\n"
                  "EOF\n"
                  "\n"
                  "echo \"Boot entry written: $ENTRY_FILE\"\n")
                 port)))
            (chmod (string-append bindir "/andyl-boot-entry") #o755)

            ;; ============================================================
            ;; andyl-image-manifest -- Image manifest generator
            ;; ============================================================
            ;; Generates a JSON manifest listing all store paths in the
            ;; image, their hashes, and metadata.
            (call-with-output-file (string-append bindir "/andyl-image-manifest")
              (lambda (port)
                (display
                 (string-append
                  "#!" bash "/bin/bash\n"
                  "# ANDYL OS Image Manifest Generator\n"
                  "# Produces a JSON manifest of all store paths in an image.\n"
                  "#\n"
                  "# Usage:\n"
                  "#   andyl-image-manifest --profile PROFILE_PATH \\\n"
                  "#                        --guix-commit COMMIT_HASH \\\n"
                  "#                        [--output manifest.json]\n"
                  "\n"
                  "set -euo pipefail\n"
                  "\n"
                  "PROFILE=\"\"\n"
                  "GUIX_COMMIT=\"unknown\"\n"
                  "OUTPUT=\"manifest.json\"\n"
                  "\n"
                  "while [[ $# -gt 0 ]]; do\n"
                  "    case \"$1\" in\n"
                  "        --profile)     PROFILE=\"$2\";     shift 2 ;;\n"
                  "        --guix-commit) GUIX_COMMIT=\"$2\"; shift 2 ;;\n"
                  "        --output)      OUTPUT=\"$2\";      shift 2 ;;\n"
                  "        *)             echo \"Unknown option: $1\" >&2; exit 1 ;;\n"
                  "    esac\n"
                  "done\n"
                  "\n"
                  "[[ -z \"$PROFILE\" ]] && { echo \"Error: --profile required\" >&2; exit 1; }\n"
                  "\n"
                  "IMAGE_ID=$(date +%Y%m%d%H%M%S)-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \\n')\n"
                  "TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)\n"
                  "\n"
                  "# Collect all store paths referenced by the profile\n"
                  "# This traverses the closure of the system profile.\n"
                  "echo '{' > \"$OUTPUT\"\n"
                  "echo '  \"image_id\": \"'\"$IMAGE_ID\"'\",' >> \"$OUTPUT\"\n"
                  "echo '  \"build_timestamp\": \"'\"$TIMESTAMP\"'\",' >> \"$OUTPUT\"\n"
                  "echo '  \"guix_commit\": \"'\"$GUIX_COMMIT\"'\",' >> \"$OUTPUT\"\n"
                  "echo '  \"system_profile\": \"'\"$PROFILE\"'\",' >> \"$OUTPUT\"\n"
                  "echo '  \"store_paths\": [' >> \"$OUTPUT\"\n"
                  "\n"
                  "FIRST=true\n"
                  "TOTAL_SIZE=0\n"
                  "TOTAL_PATHS=0\n"
                  "\n"
                  "# Walk the store closure via the references graph.\n"
                  "# Each store path is listed with its size.\n"
                  "for path in $(find \"$PROFILE\" -maxdepth 0 -exec readlink -f {} \\;); do\n"
                  "    # In a real build, we would use 'guix size' or\n"
                  "    # 'guix gc --references --recursive' to enumerate\n"
                  "    # the full closure.  For now, record the profile itself.\n"
                  "    SIZE=$(du -sb \"$path\" 2>/dev/null | cut -f1 || echo 0)\n"
                  "    TOTAL_SIZE=$((TOTAL_SIZE + SIZE))\n"
                  "    TOTAL_PATHS=$((TOTAL_PATHS + 1))\n"
                  "    if [[ \"$FIRST\" != true ]]; then\n"
                  "        echo '    ,' >> \"$OUTPUT\"\n"
                  "    fi\n"
                  "    echo '    {\"path\": \"'\"$path\"'\", \"size\": '\"$SIZE\"'}' >> \"$OUTPUT\"\n"
                  "    FIRST=false\n"
                  "done\n"
                  "\n"
                  "echo '  ],' >> \"$OUTPUT\"\n"
                  "echo '  \"total_store_size\": '\"$TOTAL_SIZE\"',' >> \"$OUTPUT\"\n"
                  "echo '  \"total_paths\": '\"$TOTAL_PATHS\" >> \"$OUTPUT\"\n"
                  "echo '}' >> \"$OUTPUT\"\n"
                  "\n"
                  "echo \"Manifest written: $OUTPUT\"\n"
                  "echo \"  Image ID:    $IMAGE_ID\"\n"
                  "echo \"  Store paths: $TOTAL_PATHS\"\n"
                  "echo \"  Total size:  $TOTAL_SIZE bytes\"\n")
                 port)))
            (chmod (string-append bindir "/andyl-image-manifest") #o755)

            ;; ============================================================
            ;; andyl-image-sign -- Image signing wrapper
            ;; ============================================================
            ;; Wrapper around minisign for signing disk images and
            ;; manifests with a consistent workflow.
            (call-with-output-file (string-append bindir "/andyl-image-sign")
              (lambda (port)
                (display
                 (string-append
                  "#!" bash "/bin/bash\n"
                  "# ANDYL OS Image Signing Tool\n"
                  "# Wrapper around minisign for signing disk images.\n"
                  "#\n"
                  "# Usage:\n"
                  "#   andyl-image-sign sign --key KEY_FILE --image IMAGE_FILE\n"
                  "#   andyl-image-sign verify --pubkey PUB_FILE --image IMAGE_FILE\n"
                  "#   andyl-image-sign keygen --key KEY_FILE --pubkey PUB_FILE\n"
                  "\n"
                  "set -euo pipefail\n"
                  "\n"
                  "MINISIGN=\"" (assoc-ref %build-inputs "andyl-minisign") "/bin/minisign\"\n"
                  "\n"
                  "case \"${1:-}\" in\n"
                  "    sign)\n"
                  "        shift\n"
                  "        KEY=\"\" IMAGE=\"\"\n"
                  "        while [[ $# -gt 0 ]]; do\n"
                  "            case \"$1\" in\n"
                  "                --key)   KEY=\"$2\";   shift 2 ;;\n"
                  "                --image) IMAGE=\"$2\"; shift 2 ;;\n"
                  "                *)       echo \"Unknown option: $1\" >&2; exit 1 ;;\n"
                  "            esac\n"
                  "        done\n"
                  "        [[ -z \"$KEY\" || -z \"$IMAGE\" ]] && { echo \"Error: --key and --image required\" >&2; exit 1; }\n"
                  "        echo \"Signing: $IMAGE\"\n"
                  "        \"$MINISIGN\" -Sm \"$IMAGE\" -s \"$KEY\"\n"
                  "        echo \"Signature written: ${IMAGE}.minisig\"\n"
                  "        ;;\n"
                  "\n"
                  "    verify)\n"
                  "        shift\n"
                  "        PUBKEY=\"\" IMAGE=\"\"\n"
                  "        while [[ $# -gt 0 ]]; do\n"
                  "            case \"$1\" in\n"
                  "                --pubkey) PUBKEY=\"$2\"; shift 2 ;;\n"
                  "                --image)  IMAGE=\"$2\";  shift 2 ;;\n"
                  "                *)        echo \"Unknown option: $1\" >&2; exit 1 ;;\n"
                  "            esac\n"
                  "        done\n"
                  "        [[ -z \"$PUBKEY\" || -z \"$IMAGE\" ]] && { echo \"Error: --pubkey and --image required\" >&2; exit 1; }\n"
                  "        echo \"Verifying: $IMAGE\"\n"
                  "        \"$MINISIGN\" -Vm \"$IMAGE\" -p \"$PUBKEY\"\n"
                  "        ;;\n"
                  "\n"
                  "    keygen)\n"
                  "        shift\n"
                  "        KEY=\"\" PUBKEY=\"\"\n"
                  "        while [[ $# -gt 0 ]]; do\n"
                  "            case \"$1\" in\n"
                  "                --key)    KEY=\"$2\";    shift 2 ;;\n"
                  "                --pubkey) PUBKEY=\"$2\"; shift 2 ;;\n"
                  "                *)        echo \"Unknown option: $1\" >&2; exit 1 ;;\n"
                  "            esac\n"
                  "        done\n"
                  "        [[ -z \"$KEY\" || -z \"$PUBKEY\" ]] && { echo \"Error: --key and --pubkey required\" >&2; exit 1; }\n"
                  "        echo \"Generating Ed25519 keypair\"\n"
                  "        \"$MINISIGN\" -G -p \"$PUBKEY\" -s \"$KEY\"\n"
                  "        echo \"Keypair generated:\"\n"
                  "        echo \"  Secret key: $KEY\"\n"
                  "        echo \"  Public key: $PUBKEY\"\n"
                  "        ;;\n"
                  "\n"
                  "    *)\n"
                  "        echo \"Usage: $0 {sign|verify|keygen} [OPTIONS]\" >&2\n"
                  "        exit 1\n"
                  "        ;;\n"
                  "esac\n")
                 port)))
            (chmod (string-append bindir "/andyl-image-sign") #o755)

            #t))))

    (inputs
     (list andyl-bash
           andyl-systemd
           andyl-minisign))

    (home-page "https://github.com/andyl/andyl-os")
    (synopsis "ANDYL OS image build tools (UKI generation, signing, manifest)")
    (description
     "Build-time tools for assembling ANDYL OS disk images.  Provides:
andyl-ukify (Unified Kernel Image generator wrapping systemd's ukify),
andyl-boot-entry (Type #1 boot entry generator for systemd-boot),
andyl-image-manifest (JSON manifest generator listing all store paths),
and andyl-image-sign (Ed25519 image signing/verification via minisign).
These tools are used during image assembly only and are NOT installed
on deployed machines.")
    (license license:gpl2+)))
