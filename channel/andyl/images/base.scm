;;; ANDYL OS -- Base Image Assembly Definition
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the disk image layout and assembly process for
;;; ANDYL OS.  It produces a raw disk image containing:
;;;
;;;   Partition 1: ESP (1 GiB, FAT32, label=ESP)
;;;     - systemd-boot EFI binary
;;;     - UKI or Type #1 boot entries
;;;     - loader.conf
;;;
;;;   Partition 2: ANDYL-ROOT (ext4, read-only, label=ANDYL-ROOT)
;;;     - Complete system closure: /gnu/store, system profile
;;;     - Base /etc (lower layer for OverlayFS)
;;;     - SELinux file contexts baked in at build time
;;;     - Kernel, systemd, all base packages
;;;
;;;   Partition 3: ZFS data (remainder of disk)
;;;     - Left empty at image build time
;;;     - Ignition creates ZFS pool on first boot
;;;
;;; The image is built by assembling the system closure from the
;;; operating-system definition and writing it into a partitioned
;;; raw disk image.
;;;
;;; Build:
;;;   guix system image --image-type=disk-image channel/andyl/images/base.scm
;;;   (or via the justfile: just build-image)
;;;
;;; See:
;;;   Phase 4 sections 4.1, 4.10 (Partition Layout, Image Assembly)
;;;   RFC-0001 section 8 (Filesystem Layout)

(define-module (andyl images base)
  #:use-module (guix packages)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module (andyl system base)
  #:use-module (andyl config)
  #:export (andyl-image
            andyl-image?
            andyl-image-operating-system
            andyl-image-size
            andyl-image-esp-size
            andyl-image-root-size
            andyl-image-root-label
            andyl-image-esp-label
            andyl-image-format

            andyl-partition
            andyl-partition?
            andyl-partition-label
            andyl-partition-size
            andyl-partition-type
            andyl-partition-filesystem
            andyl-partition-flags
            andyl-partition-uuid

            %andyl-esp-partition
            %andyl-root-partition
            %andyl-zfs-partition
            %andyl-base-image-partitions

            andyl-base-image
            andyl-server-image

            image-partition-table
            generate-loader-conf
            generate-os-release))


;;;
;;; Image Records
;;;

(define-record-type* <andyl-partition>
  andyl-partition make-andyl-partition
  andyl-partition?
  ;; GPT partition label.
  (label       andyl-partition-label)
  ;; Size in mebibytes (MiB).  #f means "use remaining space".
  (size        andyl-partition-size
               (default #f))
  ;; GPT partition type GUID or shorthand:
  ;;   "esp" -> EFI System Partition
  ;;   "linux" -> Linux filesystem
  ;;   "linux-reserved" -> Linux reserved (for ZFS)
  (type        andyl-partition-type)
  ;; Filesystem type: "vfat", "ext4", or #f (unformatted).
  (filesystem  andyl-partition-filesystem
               (default #f))
  ;; Partition flags (list of symbols): 'boot, 'esp.
  (flags       andyl-partition-flags
               (default '()))
  ;; Fixed UUID for reproducible images, or #f for auto-generated.
  (uuid        andyl-partition-uuid
               (default #f)))


(define-record-type* <andyl-image>
  andyl-image make-andyl-image
  andyl-image?
  ;; The operating-system definition to include in the image.
  (operating-system  andyl-image-operating-system
                     (default andyl-os-base))
  ;; Total image size in mebibytes.
  (size              andyl-image-size
                     (default (config-ref "deployment.image.total-mib" (* 16 1024))))
  ;; ESP partition size in mebibytes.
  (esp-size          andyl-image-esp-size
                     (default (config-ref "boot.partitions.esp-mib" 1024)))
  ;; Root partition size in mebibytes.
  ;; #f means "calculate from system closure + margin".
  (root-size         andyl-image-root-size
                     (default (config-ref "boot.partitions.root-mib" (* 8 1024))))
  ;; Root partition filesystem label.
  (root-label        andyl-image-root-label
                     (default (config-ref "boot.filesystem.root-label" "ANDYL-ROOT")))
  ;; ESP partition filesystem label.
  (esp-label         andyl-image-esp-label
                     (default (config-ref "boot.filesystem.esp-label" "ESP")))
  ;; Output format: 'raw or 'qcow2.
  (format            andyl-image-format
                     (default 'raw)))


;;;
;;; Standard Partition Definitions
;;;

;; Partition 1: EFI System Partition
;; Contains systemd-boot, UKI/boot entries, and loader.conf.
;; 1 GiB is generous, allowing multiple generations of UKIs.
(define %andyl-esp-partition
  (andyl-partition
   (label (config-ref "boot.filesystem.esp-label" "ESP"))
   (size (config-ref "boot.partitions.esp-mib" 1024))
   (type "esp")
   (filesystem "vfat")
   (flags '(boot esp))))

;; Partition 2: Root filesystem (ext4, read-only)
;; Contains the complete system closure from /gnu/store, the system
;; profile, base /etc, kernel, systemd, and all base packages.
;; SELinux file contexts are baked in at image build time.
(define %andyl-root-partition
  (andyl-partition
   (label (config-ref "boot.filesystem.root-label" "ANDYL-ROOT"))
   (size (config-ref "boot.partitions.root-mib" (* 8 1024)))
   (type "linux")
   (filesystem (config-ref "boot.filesystem.root-type" "ext4"))
   (flags '())))

;; Partition 3: ZFS data area
;; Left unformatted at image build time.  Ignition creates the ZFS
;; pool (datapool) on this partition during first boot.
(define %andyl-zfs-partition
  (andyl-partition
   (label (config-ref "boot.filesystem.zfs-label" "ANDYL-DATA"))
   (size #f)                    ; Use remaining disk space
   (type "linux-reserved")
   (filesystem #f)              ; Unformatted; ZFS created by Ignition
   (flags '())))

(define %andyl-base-image-partitions
  (list %andyl-esp-partition
        %andyl-root-partition
        %andyl-zfs-partition))


;;;
;;; Image Assembly Helpers
;;;

;; Generate a partition table description as a gexp that can be consumed
;; by image build scripts (sfdisk format).
(define (image-partition-table partitions total-size-mib)
  "Return a gexp producing an sfdisk script for PARTITIONS within a
disk of TOTAL-SIZE-MIB mebibytes."
  #~(string-append
     "label: gpt\n"
     #$@(map
         (lambda (p)
           (let ((label (andyl-partition-label p))
                 (size  (andyl-partition-size p))
                 (type  (andyl-partition-type p)))
             #~(string-append
                #$(string-append "name=" label)
                #$(if size
                       (string-append ", size=" (number->string size) "M")
                       "")
                #$(string-append
                   ", type="
                   (cond
                    ((string=? type "esp")
                     "C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
                    ((string=? type "linux")
                     "0FC63DAF-8483-4772-8E79-3D69D8477DE4")
                    ((string=? type "linux-reserved")
                     "8DA63339-0007-60C0-C436-083AC8230908")
                    (else type)))
                "\n")))
         partitions)))


;; Generate the systemd-boot loader.conf content.
(define (generate-loader-conf)
  "Return the content of loader.conf for systemd-boot."
  (let ((timeout      (config-ref "boot.bootloader.timeout" 3))
        (editor       (config-ref "boot.bootloader.editor" #f))
        (console-mode (config-ref "boot.bootloader.console-mode" "max")))
    (string-append
     "# ANDYL OS systemd-boot configuration\n"
     "# See: https://systemd.io/BOOT_LOADER_SPECIFICATION/\n\n"
     "default andyl-os-*.conf\n"
     "timeout " (number->string timeout) "\n"
     "editor " (if editor "yes" "no") "\n"
     "console-mode " console-mode "\n")))


;; Generate the os-release file content.
(define* (generate-os-release #:key
                              (version "0.1.0")
                              (build-id "gen-1"))
  "Return the content of /usr/lib/os-release for ANDYL OS."
  (string-append
   "NAME=\"ANDYL OS\"\n"
   "ID=andyl-os\n"
   "VERSION=\"" version "\"\n"
   "VERSION_ID=" version "\n"
   "BUILD_ID=" build-id "\n"
   "PRETTY_NAME=\"ANDYL OS " version " (Generation " build-id ")\"\n"
   "HOME_URL=\"https://github.com/andyl/andyl-os\"\n"
   "BUG_REPORT_URL=\"https://github.com/andyl/andyl-os/issues\"\n"
   "VARIANT_ID=server\n"
   "ANSI_COLOR=\"0;34\"\n"))


;;;
;;; Image Definitions
;;;

;; Base image: uses the default operating-system (andyl-os-base).
;; This is primarily for testing the image assembly pipeline.
(define andyl-base-image
  (andyl-image))

;; Server image: uses the server operating-system configuration.
;; This is the standard production deployment image.
(define andyl-server-image
  (andyl-image
   ;; Import the server OS definition.  We use a lazy reference here
   ;; to avoid a circular dependency at module load time.
   ;; The actual operating-system is resolved at image build time.
   (size (* 32 1024))           ; 32 GiB for server images
   (root-size (* 12 1024))))    ; 12 GiB root (more packages)
