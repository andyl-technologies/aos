;;; ANDYL OS -- Server Firmware Package
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the stripped firmware package for ANDYL OS.
;;;
;;; The full linux-firmware repository is ~862 MB.  We include only the
;;; firmware blobs needed for server hardware, reducing the installed
;;; size to approximately 20 MB:
;;;
;;;   - CPU microcode: Intel (intel-ucode), AMD (amd-ucode)
;;;   - Intel NICs:    ice (100GbE), i40e (40GbE)
;;;   - Mellanox NICs: mlx4, mlx5 (ConnectX-3/4/5/6/7)
;;;   - Broadcom NICs: bnxt (NetXtreme-E/C), bnx2x (NetXtreme II)
;;;   - QLogic:        qed (Marvell/QLogic storage & network)
;;;
;;; Firmware files are installed to lib/firmware/ for loading by the
;;; kernel's firmware loader at runtime.

(define-module (andyl packages firmware)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system trivial)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl config))

;;;
;;; Linux Firmware (server subset)
;;;
;;; Sourced from the kernel.org linux-firmware releases.  We use the
;;; trivial-build-system to unpack the tarball and selectively copy
;;; only the directories needed for server hardware.
;;;

(define-public andyl-firmware
  (package
    (name "andyl-firmware")
    (version (config-version "firmware" "linux-firmware"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://cdn.kernel.org/pub/linux/kernel/firmware/"
                    "linux-firmware-" version ".tar.xz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://cdn.kernel.org/pub/linux/kernel/firmware/linux-firmware-20241210.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system trivial-build-system)
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((source (assoc-ref %build-inputs "source"))
                 (out    (assoc-ref %outputs "out"))
                 (fwdir  (string-append out "/lib/firmware")))

            ;; Unpack the source tarball
            (invoke "tar" "xf" source)
            (chdir (string-append "linux-firmware-"
                                  #$(package-version this-package)))

            (mkdir-p fwdir)

            ;; Copy only server-relevant firmware directories.
            ;; This reduces the installed size from ~862 MB to ~20 MB.
            ;;
            ;; Directory        Driver          Purpose
            ;; ---------        ------          -------
            ;; intel-ucode      CPU             Intel CPU microcode updates
            ;; amd-ucode        CPU             AMD CPU microcode updates
            ;; intel/ice         ICE             Intel E800 100GbE NIC
            ;; intel/i40e        I40E            Intel XL710 40GbE NIC
            ;; mellanox          MLX4/MLX5       Mellanox ConnectX NICs
            ;; bnxt              BNXT            Broadcom NetXtreme-E/C
            ;; bnx2x             BNX2X           Broadcom NetXtreme II (legacy)
            ;; qed               QED             QLogic/Marvell FastLinQ
            (let ((firmware-dirs
                   '("intel-ucode"
                     "amd-ucode"
                     "intel/ice"
                     "intel/i40e"
                     "mellanox"
                     "bnxt"
                     "bnx2x"
                     "qed")))
              (for-each
               (lambda (dir)
                 (when (file-exists? dir)
                   (let ((dest (string-append fwdir "/" dir)))
                     (mkdir-p (dirname dest))
                     (copy-recursively dir dest))))
               firmware-dirs))

            ;; Install the WHENCE license/attribution file
            (when (file-exists? "WHENCE")
              (install-file "WHENCE"
                            (string-append out "/share/doc/"
                                           #$(package-name this-package))))))))

    (home-page "https://kernel.org/")
    (synopsis "Stripped linux-firmware for ANDYL OS server hardware")
    (description
     "Minimal subset of the linux-firmware repository containing only
firmware needed for server hardware: Intel and AMD CPU microcode, Intel
ice (100GbE) and i40e (40GbE) NIC firmware, Mellanox ConnectX NIC firmware,
Broadcom NetXtreme-E/C and NetXtreme II NIC firmware, and QLogic/Marvell
FastLinQ firmware.  Approximately 20 MB versus 862 MB for the full
firmware tree.")
    ;; linux-firmware contains blobs under various redistribution licenses;
    ;; see the WHENCE file for per-file license information.
    (license (license:non-copyleft
              "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/tree/WHENCE"))))
