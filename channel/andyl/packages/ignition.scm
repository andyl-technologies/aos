;;; ANDYL OS -- Ignition First-Boot Provisioning Package
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the CoreOS Ignition package for ANDYL OS:
;;;
;;;   andyl-ignition -- First-boot provisioning tool (runs in initrd)
;;;
;;; Ignition is CoreOS's first-boot provisioning system.  It runs once
;;; in the initrd (before pivot_root), applying all machine-specific
;;; configuration atomically -- all-or-nothing semantics ensure the
;;; system never boots into a partially-configured state.
;;;
;;; In ANDYL OS, Ignition performs the following on first boot:
;;;   1. Partitions remaining disk space for ZFS (ANDYL-ZFS partition)
;;;   2. Writes machine-specific files to /etc overlay upper layer
;;;   3. Writes runtime config to /var
;;;   4. Creates the admin user with SSH authorized keys
;;;   5. Enables systemd units (including andyl-os-zfs-setup.service)
;;;
;;; Ignition config delivery mechanisms:
;;;   - QEMU fw_cfg (development/testing)
;;;   - Cloud provider user-data (AWS, GCP, Azure)
;;;   - USB drive labeled "ignition" (air-gapped)
;;;   - HTTP endpoint keyed by MAC address (bare metal)
;;;
;;; See:
;;;   RFC-0006 (First-Boot Configuration with CoreOS Ignition)
;;;   Phase 6 (CoreOS Ignition Integration)
;;;   RFC-0001 section 9 (Boot Flow -- Ignition in initrd)
;;;
;;; Package dependency graph:
;;;
;;;   andyl-ignition
;;;     +-- Go toolchain (build-time only)
;;;     +-- andyl-glibc
;;;     +-- andyl-linux-headers

(define-module (andyl packages ignition)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system go)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl packages linux)
  #:use-module (andyl config))


;;; =========================================================================
;;; CoreOS Ignition -- first-boot provisioning tool
;;; =========================================================================
;;;
;;; Ignition is purpose-built for immutable operating systems.  Unlike
;;; cloud-init, which runs every boot and applies configuration in
;;; multiple stages, Ignition runs exactly once in the initrd and
;;; applies all configuration atomically.
;;;
;;; Key properties:
;;;   - Runs in the initrd before pivot_root (before real root is mounted)
;;;   - All-or-nothing: failure prevents boot (no partial configuration)
;;;   - First-boot only: never runs again on subsequent boots
;;;   - Declarative JSON config (compiled from Butane YAML)
;;;   - Supports disk partitioning, file creation, user setup, systemd units
;;;
;;; Ignition reads its configuration from platform-specific sources:
;;;   - file:    local file at /etc/ignition.json
;;;   - qemu:    QEMU fw_cfg (opt/com.coreos/config)
;;;   - ec2:     AWS IMDSv2 user-data endpoint
;;;   - gce:     GCP metadata server
;;;   - azure:   Azure custom-data
;;;   - packet:  Equinix Metal metadata
;;;
;;; The Ignition binary is a statically-linked Go program.  It includes
;;; dracut modules for initrd integration.
;;;
;;; Version 2.19.x is used for compatibility with Ignition spec v3.4.0
;;; and Butane spec v1.5.0.

(define-public andyl-ignition
  (package
    (name "andyl-ignition")
    (version (config-version "image-tools" "ignition"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/coreos/ignition/archive/refs/tags/v"
                    version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/coreos/ignition/archive/refs/tags/v2.19.0.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system go-build-system)
    (arguments
     (list
      ;; The main Ignition binary entry point
      #:import-path "github.com/coreos/ignition/v2"
      #:install-source? #f

      #:phases
      #~(modify-phases %standard-phases
          ;; Ignition's Go module path requires building from a
          ;; subdirectory.  Build the main ignition binary and the
          ;; ignition-validate tool.
          (replace 'build
            (lambda* (#:key import-path #:allow-other-keys)
              (for-each
               (lambda (cmd)
                 (invoke "go" "build" "-v"
                         "-o" (string-append "bin/" (basename cmd))
                         (string-append import-path "/internal/exec/stages/" cmd)))
               '("fetch" "disks" "mount" "files"))
              ;; Build the main ignition binary
              (invoke "go" "build" "-v"
                      "-o" "bin/ignition"
                      (string-append import-path "/internal/exec"))
              ;; Build ignition-validate for config validation
              (invoke "go" "build" "-v"
                      "-o" "bin/ignition-validate"
                      (string-append import-path "/validate"))))

          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let* ((out    (assoc-ref outputs "out"))
                     (bindir (string-append out "/bin"))
                     (libdir (string-append out "/lib"))
                     (dracutdir (string-append libdir
                                               "/dracut/modules.d/30ignition"))
                     (systemddir (string-append libdir "/systemd/system"))
                     (presetdir (string-append libdir
                                               "/systemd/system-preset")))

                ;; Install binaries
                (mkdir-p bindir)
                (for-each
                 (lambda (bin)
                   (let ((src (string-append "bin/" bin)))
                     (when (file-exists? src)
                       (install-file src bindir))))
                 '("ignition" "ignition-validate"
                   "fetch" "disks" "mount" "files"))

                ;; Install dracut module for initrd integration.
                ;; The dracut module ensures Ignition runs during initrd.
                (mkdir-p dracutdir)
                (call-with-output-file
                    (string-append dracutdir "/module-setup.sh")
                  (lambda (port)
                    (display "#!/bin/bash\n" port)
                    (display "# Ignition dracut module for ANDYL OS\n\n" port)
                    (display "check() { return 0; }\n\n" port)
                    (display "depends() { echo systemd; }\n\n" port)
                    (display "install() {\n" port)
                    (display "    inst_multiple ignition ignition-validate\n"
                             port)
                    (display "    inst_simple \"${moddir}/ignition-fetch.service\" \\\n" port)
                    (display "        \"${systemdsystemunitdir}/ignition-fetch.service\"\n" port)
                    (display "    inst_simple \"${moddir}/ignition-disks.service\" \\\n" port)
                    (display "        \"${systemdsystemunitdir}/ignition-disks.service\"\n" port)
                    (display "    inst_simple \"${moddir}/ignition-mount.service\" \\\n" port)
                    (display "        \"${systemdsystemunitdir}/ignition-mount.service\"\n" port)
                    (display "    inst_simple \"${moddir}/ignition-files.service\" \\\n" port)
                    (display "        \"${systemdsystemunitdir}/ignition-files.service\"\n" port)
                    (display "    inst_simple \"${moddir}/ignition-complete.service\" \\\n" port)
                    (display "        \"${systemdsystemunitdir}/ignition-complete.service\"\n" port)
                    (display "    $SYSTEMCTL -q --root \"$initdir\" enable ignition-fetch.service\n" port)
                    (display "    $SYSTEMCTL -q --root \"$initdir\" enable ignition-disks.service\n" port)
                    (display "    $SYSTEMCTL -q --root \"$initdir\" enable ignition-mount.service\n" port)
                    (display "    $SYSTEMCTL -q --root \"$initdir\" enable ignition-files.service\n" port)
                    (display "    $SYSTEMCTL -q --root \"$initdir\" enable ignition-complete.service\n" port)
                    (display "}\n" port)))
                (chmod (string-append dracutdir "/module-setup.sh") #o755)

                ;; Install Ignition systemd units for initrd execution.
                ;; These units orchestrate the Ignition stages in the
                ;; correct order within the initrd, before switch-root.

                ;; ignition-fetch.service: fetches config from platform
                (call-with-output-file
                    (string-append dracutdir "/ignition-fetch.service")
                  (lambda (port)
                    (display "\
[Unit]
Description=Ignition (fetch)
DefaultDependencies=no
ConditionFirstBoot=true
After=systemd-udevd.service
Before=ignition-disks.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/ignition --platform=file --stage=fetch
ExecStart=/bin/ignition --platform=qemu --stage=fetch
ExecStart=/bin/ignition --platform=ec2 --stage=fetch
" port)))

                ;; ignition-disks.service: partitioning and RAID
                (call-with-output-file
                    (string-append dracutdir "/ignition-disks.service")
                  (lambda (port)
                    (display "\
[Unit]
Description=Ignition (disks)
DefaultDependencies=no
ConditionFirstBoot=true
After=ignition-fetch.service
Before=ignition-mount.service
Requires=ignition-fetch.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/ignition --stage=disks
" port)))

                ;; ignition-mount.service: filesystem creation and mounting
                (call-with-output-file
                    (string-append dracutdir "/ignition-mount.service")
                  (lambda (port)
                    (display "\
[Unit]
Description=Ignition (mount)
DefaultDependencies=no
ConditionFirstBoot=true
After=ignition-disks.service
Before=ignition-files.service
Requires=ignition-disks.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/ignition --stage=mount
" port)))

                ;; ignition-files.service: file and user creation
                (call-with-output-file
                    (string-append dracutdir "/ignition-files.service")
                  (lambda (port)
                    (display "\
[Unit]
Description=Ignition (files)
DefaultDependencies=no
ConditionFirstBoot=true
After=ignition-mount.service
Before=ignition-complete.service
Requires=ignition-mount.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/ignition --stage=files
" port)))

                ;; ignition-complete.service: marks first-boot done
                (call-with-output-file
                    (string-append dracutdir "/ignition-complete.service")
                  (lambda (port)
                    (display "\
[Unit]
Description=Ignition (complete)
DefaultDependencies=no
ConditionFirstBoot=true
After=ignition-files.service
Before=initrd-switch-root.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
" port)))))))))

    (native-inputs
     (list andyl-gcc))

    (inputs
     (list andyl-glibc
           andyl-linux-headers))

    (home-page "https://coreos.github.io/ignition/")
    (synopsis "CoreOS Ignition first-boot provisioning for ANDYL OS")
    (description
     "Ignition is a first-boot provisioning tool designed for immutable
operating systems.  It runs once in the initrd before pivot_root,
applying all machine-specific configuration atomically (all-or-nothing).
Ignition creates disk partitions, writes configuration files, sets up
users with SSH keys, and enables systemd units.  Configuration is
authored in Butane YAML and transpiled to Ignition JSON.  Supports
multiple config delivery mechanisms: QEMU fw_cfg, cloud provider
user-data (AWS, GCP, Azure), USB drive, and HTTP endpoint.")
    (license license:asl2.0)))
