;;; ANDYL OS -- Custom SELinux Policy Module
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the custom ANDYL OS SELinux policy that layers
;;; on top of the upstream reference targeted policy.  It provides type
;;; enforcement (.te), file context (.fc), and interface (.if) files
;;; for ANDYL OS-specific services and filesystem paths.
;;;
;;; Policy modules included:
;;;   andyl_systemd     -- systemd services (journald, networkd, resolved)
;;;   andyl_zfs         -- ZFS tools (zpool, zfs, zed)
;;;   andyl_container   -- Container storage on ZFS datapool
;;;   andyl_networking  -- eBPF/Cilium CNI
;;;   andyl_guix_store  -- Guix store (/gnu/store) access
;;;
;;; ANDYL OS-specific SELinux types:
;;;   guix_store_t / usr_t    -- /gnu/store content
;;;   andyl_etc_overlay_t     -- /var/etc-overlay upper layer
;;;   andyl_zfs_t             -- ZFS tool processes
;;;   andyl_zfs_data_t        -- ZFS mutable data datasets
;;;   andyl_cilium_t          -- Cilium CNI processes
;;;
;;; See also:
;;;   Phase 3 section 3.12 (SELinux Policy Development and Userspace)
;;;   RFC-0003 section 3.7 (Security Modules -- SELinux kernel config)

(define-module (andyl packages selinux-policy)
  #:use-module (guix packages)
  #:use-module (guix build-system trivial)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:))


;;; =========================================================================
;;; andyl-selinux-policy -- ANDYL OS custom SELinux policy module
;;; =========================================================================
;;;
;;; This package installs the ANDYL OS-specific SELinux policy modules
;;; including type enforcement (.te), file context (.fc), and policy
;;; interface (.if) files.  These are loaded as supplementary modules
;;; on top of the upstream reference targeted policy
;;; (andyl-selinux-policy-targeted) and container-selinux
;;; (andyl-container-selinux).
;;;
;;; The policy is installed under /etc/selinux/targeted/ so that
;;; semodule can load the compiled modules at boot or image build time.
;;;
;;; Boot parameters: security=selinux selinux=1

(define-public andyl-selinux-policy
  (package
    (name "andyl-selinux-policy")
    (version "1.0.0")
    (source #f)
    (build-system trivial-build-system)
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((out      (assoc-ref %outputs "out"))
                 (policy   (string-append out "/etc/selinux/targeted"))
                 (ctx-dir  (string-append policy "/contexts/files"))
                 (mod-dir  (string-append policy "/modules/active/modules")))

            (mkdir-p ctx-dir)
            (mkdir-p mod-dir)

            ;; =============================================================
            ;; andyl_systemd -- systemd service policy module
            ;; =============================================================

            ;; --- Type Enforcement (.te) ---
            (call-with-output-file (string-append mod-dir "/andyl_systemd.te")
              (lambda (port)
                (display "\
# ANDYL OS systemd service policy module
# Provides ANDYL OS-specific transitions and permissions for
# systemd services operating on the immutable root + overlay /etc.
policy_module(andyl_systemd, 1.0.0)

########################################
# journald -- write to ZFS-backed /var/log/journal
########################################

require {
    type systemd_journald_t;
    type systemd_journal_t;
    class dir { create write add_name remove_name };
    class file { create write open append getattr setattr };
}

allow systemd_journald_t systemd_journal_t:dir { create write add_name remove_name };
allow systemd_journald_t systemd_journal_t:file { create write open append getattr setattr };

########################################
# networkd, resolved -- overlay /etc access
########################################

require {
    type systemd_networkd_t;
    type systemd_resolved_t;
    type systemd_timesyncd_t;
    type etc_t;
    class file { read open getattr };
    class dir { search getattr };
}

allow systemd_networkd_t etc_t:file { read open getattr };
allow systemd_networkd_t etc_t:dir { search getattr };
allow systemd_resolved_t etc_t:file { read open getattr };
allow systemd_resolved_t etc_t:dir { search getattr };
allow systemd_timesyncd_t etc_t:file { read open getattr };
allow systemd_timesyncd_t etc_t:dir { search getattr };
" port)))

            ;; --- File Contexts (.fc) ---
            (call-with-output-file (string-append mod-dir "/andyl_systemd.fc")
              (lambda (port)
                (display "\
# ANDYL OS systemd file contexts
# Journal logs on ZFS datapool
/var/log/journal(/.*)?    system_u:object_r:systemd_journal_t:s0
" port)))

            ;; --- Interface (.if) ---
            (call-with-output-file (string-append mod-dir "/andyl_systemd.if")
              (lambda (port)
                (display "\
## <summary>ANDYL OS systemd policy interfaces</summary>

## <desc>
## <p>
##   Interfaces for ANDYL OS systemd service policy.
##   Provides access patterns for services operating on
##   the immutable root with overlay /etc.
## </p>
## </desc>

########################################
## <summary>
##   Allow a domain to read overlay /etc files.
## </summary>
## <param name=\"domain\">
##   <summary>
##     Domain allowed access.
##   </summary>
## </param>
#
interface(`andyl_read_overlay_etc',`
    gen_require(`
        type etc_t;
    ')
    allow $1 etc_t:file { read open getattr };
    allow $1 etc_t:dir { search getattr };
')
" port)))


            ;; =============================================================
            ;; andyl_zfs -- ZFS tools policy module
            ;; =============================================================

            ;; --- Type Enforcement (.te) ---
            (call-with-output-file (string-append mod-dir "/andyl_zfs.te")
              (lambda (port)
                (display "\
# ANDYL OS ZFS policy module
# ZFS tools (zpool, zfs, zed) need access to block devices
# and the ability to mount/unmount ZFS datasets for the
# mutable data pool.
policy_module(andyl_zfs, 1.0.0)

########################################
# Type declarations
########################################

type andyl_zfs_t;
type andyl_zfs_exec_t;
type andyl_zfs_data_t;

domain_type(andyl_zfs_t)
domain_entry_file(andyl_zfs_t, andyl_zfs_exec_t)

########################################
# Block device access
########################################

require {
    type fixed_disk_device_t;
    type removable_device_t;
    class blk_file { read write open ioctl getattr };
    class chr_file { read write open ioctl getattr };
}

allow andyl_zfs_t fixed_disk_device_t:blk_file { read write open ioctl getattr };

########################################
# Filesystem mount operations
########################################

require {
    type var_t;
    type var_lib_t;
    type var_log_t;
    class filesystem { mount unmount remount getattr associate };
    class dir { mounton read write search getattr create add_name remove_name };
    class file { read write open create getattr setattr unlink };
}

allow andyl_zfs_t var_lib_t:dir { mounton read write search getattr create add_name remove_name };
allow andyl_zfs_t var_log_t:dir { mounton read write search getattr };
allow andyl_zfs_t var_t:dir { mounton read write search getattr };
allow andyl_zfs_t self:filesystem { mount unmount remount getattr associate };

########################################
# ZFS data type access
########################################

allow andyl_zfs_t andyl_zfs_data_t:dir { read write search getattr create add_name remove_name };
allow andyl_zfs_t andyl_zfs_data_t:file { read write open create getattr setattr unlink };

########################################
# Capabilities for pool operations
########################################

require {
    class capability { sys_admin sys_rawio dac_override };
    class process { setrlimit };
}

allow andyl_zfs_t self:capability { sys_admin sys_rawio dac_override };
allow andyl_zfs_t self:process { setrlimit };
" port)))

            ;; --- File Contexts (.fc) ---
            (call-with-output-file (string-append mod-dir "/andyl_zfs.fc")
              (lambda (port)
                (display "\
# ANDYL OS ZFS file contexts
# ZFS tool binaries
/usr/sbin/zpool    system_u:object_r:andyl_zfs_exec_t:s0
/usr/sbin/zfs      system_u:object_r:andyl_zfs_exec_t:s0
/usr/sbin/zed      system_u:object_r:andyl_zfs_exec_t:s0
/usr/sbin/zdb      system_u:object_r:andyl_zfs_exec_t:s0

# ZFS data directories
/var/lib/zfs(/.*)?    system_u:object_r:andyl_zfs_data_t:s0
" port)))

            ;; --- Interface (.if) ---
            (call-with-output-file (string-append mod-dir "/andyl_zfs.if")
              (lambda (port)
                (display "\
## <summary>ANDYL OS ZFS policy interfaces</summary>

########################################
## <summary>
##   Execute ZFS tools in the andyl_zfs_t domain.
## </summary>
## <param name=\"domain\">
##   <summary>
##     Domain allowed to transition.
##   </summary>
## </param>
#
interface(`andyl_zfs_domtrans',`
    gen_require(`
        type andyl_zfs_t;
        type andyl_zfs_exec_t;
    ')
    domtrans_pattern($1, andyl_zfs_exec_t, andyl_zfs_t)
')

########################################
## <summary>
##   Read and write ZFS data files.
## </summary>
## <param name=\"domain\">
##   <summary>
##     Domain allowed access.
##   </summary>
## </param>
#
interface(`andyl_zfs_manage_data',`
    gen_require(`
        type andyl_zfs_data_t;
    ')
    allow $1 andyl_zfs_data_t:dir { read write search getattr create add_name remove_name };
    allow $1 andyl_zfs_data_t:file { read write open create getattr setattr unlink };
')
" port)))


            ;; =============================================================
            ;; andyl_container -- container storage on ZFS policy module
            ;; =============================================================

            ;; --- Type Enforcement (.te) ---
            (call-with-output-file (string-append mod-dir "/andyl_container.te")
              (lambda (port)
                (display "\
# ANDYL OS container storage policy module
# Extends upstream container-selinux with ANDYL OS-specific rules
# for ZFS-backed container storage and Kubernetes integration.
policy_module(andyl_container, 1.0.0)

########################################
# Container storage on ZFS
########################################
# Container storage lives on ZFS datapool at /var/lib/containers.
# The container runtime needs to manage overlay layers on top of
# ZFS datasets.

require {
    type container_runtime_t;
    type container_t;
    type container_file_t;
    type container_var_lib_t;
    type container_log_t;
    type container_runtime_tmpfs_t;
    class dir { read write search getattr create add_name remove_name rmdir mounton };
    class file { read write open create getattr setattr unlink execute map entrypoint };
    class filesystem { mount unmount getattr associate };
    class capability { sys_admin net_admin chown fowner dac_override setuid setgid };
}

# Runtime manages overlay filesystem on ZFS
allow container_runtime_t self:filesystem { mount unmount getattr associate };
allow container_runtime_t container_var_lib_t:dir { mounton };

########################################
# Kubernetes integration
########################################
# Kubelet mounts volumes into container namespaces and needs
# to manage labels for Pod SecurityContext seLinuxOptions.

require {
    type container_var_lib_t;
    class dir { relabelfrom relabelto };
    class file { relabelfrom relabelto };
}

allow container_runtime_t container_var_lib_t:dir { relabelfrom relabelto };
allow container_runtime_t container_var_lib_t:file { relabelfrom relabelto };
allow container_runtime_t container_file_t:dir { relabelfrom relabelto };
allow container_runtime_t container_file_t:file { relabelfrom relabelto };
" port)))

            ;; --- File Contexts (.fc) ---
            (call-with-output-file (string-append mod-dir "/andyl_container.fc")
              (lambda (port)
                (display "\
# ANDYL OS container file contexts
# Container storage on ZFS datapool

# Container storage root (ZFS: datapool/containers)
/var/lib/containers(/.*)?                  system_u:object_r:container_var_lib_t:s0
/var/lib/containers/storage(/.*)?          system_u:object_r:container_file_t:s0
/var/lib/containers/storage/overlay(/.*)?  system_u:object_r:container_file_t:s0

# containerd state directory
/var/lib/containerd(/.*)?    system_u:object_r:container_var_lib_t:s0

# CRI-O state directory
/var/lib/crio(/.*)?          system_u:object_r:container_var_lib_t:s0

# Kubelet state directory
/var/lib/kubelet(/.*)?       system_u:object_r:container_var_lib_t:s0

# Container logs
/var/log/containers(/.*)?    system_u:object_r:container_log_t:s0
/var/log/pods(/.*)?          system_u:object_r:container_log_t:s0

# Container runtime sockets
/run/containerd(/.*)?        system_u:object_r:container_runtime_tmpfs_t:s0
/run/crio(/.*)?              system_u:object_r:container_runtime_tmpfs_t:s0
/run/podman(/.*)?            system_u:object_r:container_runtime_tmpfs_t:s0
" port)))

            ;; --- Interface (.if) ---
            (call-with-output-file (string-append mod-dir "/andyl_container.if")
              (lambda (port)
                (display "\
## <summary>ANDYL OS container storage policy interfaces</summary>

########################################
## <summary>
##   Manage container storage on ZFS.
## </summary>
## <param name=\"domain\">
##   <summary>
##     Domain allowed access.
##   </summary>
## </param>
#
interface(`andyl_container_manage_storage',`
    gen_require(`
        type container_var_lib_t;
        type container_file_t;
    ')
    allow $1 container_var_lib_t:dir { read write search getattr create add_name remove_name };
    allow $1 container_var_lib_t:file { read write open create getattr setattr unlink };
    allow $1 container_file_t:dir { read write search getattr create add_name remove_name };
    allow $1 container_file_t:file { read write open create getattr setattr unlink };
')
" port)))


            ;; =============================================================
            ;; andyl_networking -- eBPF/Cilium networking policy module
            ;; =============================================================

            ;; --- Type Enforcement (.te) ---
            (call-with-output-file (string-append mod-dir "/andyl_networking.te")
              (lambda (port)
                (display "\
# ANDYL OS networking policy module
# Cilium CNI uses eBPF programs for networking.
# This module permits the necessary BPF operations.
policy_module(andyl_networking, 1.0.0)

########################################
# Type declarations
########################################

type andyl_cilium_t;
type andyl_cilium_exec_t;

domain_type(andyl_cilium_t)
domain_entry_file(andyl_cilium_t, andyl_cilium_exec_t)

########################################
# BPF program operations
########################################

require {
    class bpf { map_create map_read map_write prog_load prog_run };
    class capability { net_admin sys_admin net_raw };
    class capability2 { bpf perfmon };
}

allow andyl_cilium_t self:bpf { map_create map_read map_write prog_load prog_run };
allow andyl_cilium_t self:capability { net_admin sys_admin net_raw };
allow andyl_cilium_t self:capability2 { bpf perfmon };

########################################
# Network access
########################################

require {
    class tcp_socket { create listen accept bind connect getopt setopt };
    class udp_socket { create bind connect getopt setopt };
    class rawip_socket { create getopt setopt };
    class netlink_route_socket { create bind getattr nlmsg_read nlmsg_write };
    class packet_socket { create bind getopt setopt };
}

allow andyl_cilium_t self:tcp_socket { create listen accept bind connect getopt setopt };
allow andyl_cilium_t self:udp_socket { create bind connect getopt setopt };
allow andyl_cilium_t self:rawip_socket { create getopt setopt };
allow andyl_cilium_t self:netlink_route_socket { create bind getattr nlmsg_read nlmsg_write };
allow andyl_cilium_t self:packet_socket { create bind getopt setopt };
" port)))

            ;; --- File Contexts (.fc) ---
            (call-with-output-file (string-append mod-dir "/andyl_networking.fc")
              (lambda (port)
                (display "\
# ANDYL OS networking file contexts
/usr/bin/cilium-agent    system_u:object_r:andyl_cilium_exec_t:s0
/usr/bin/cilium           system_u:object_r:andyl_cilium_exec_t:s0
/var/run/cilium(/.*)?    system_u:object_r:andyl_cilium_exec_t:s0
" port)))

            ;; --- Interface (.if) ---
            (call-with-output-file (string-append mod-dir "/andyl_networking.if")
              (lambda (port)
                (display "\
## <summary>ANDYL OS networking policy interfaces</summary>

########################################
## <summary>
##   Execute Cilium in the andyl_cilium_t domain.
## </summary>
## <param name=\"domain\">
##   <summary>
##     Domain allowed to transition.
##   </summary>
## </param>
#
interface(`andyl_cilium_domtrans',`
    gen_require(`
        type andyl_cilium_t;
        type andyl_cilium_exec_t;
    ')
    domtrans_pattern($1, andyl_cilium_exec_t, andyl_cilium_t)
')
" port)))


            ;; =============================================================
            ;; andyl_guix_store -- Guix store policy module
            ;; =============================================================

            ;; --- Type Enforcement (.te) ---
            (call-with-output-file (string-append mod-dir "/andyl_guix_store.te")
              (lambda (port)
                (display "\
# ANDYL OS Guix store policy module
# The Guix store at /gnu/store is part of the immutable ext4 root
# filesystem.  It is mounted read-only and contains all package
# outputs.  We label it as usr_t to allow standard read/execute
# access by all domains.
policy_module(andyl_guix_store, 1.0.0)

########################################
# Guix store access -- read and execute
########################################
# All domains need to read and execute from /gnu/store since
# it contains all system binaries and libraries.

require {
    type usr_t;
    type init_t;
    type unconfined_t;
    type kernel_t;
    type sysadm_t;
    class file { read execute execute_no_trans open getattr map };
    class dir { read search open getattr };
    class lnk_file { read getattr };
}

# systemd (init_t) must execute binaries from the Guix store
allow init_t usr_t:file { read execute execute_no_trans open getattr map };
allow init_t usr_t:dir { read search open getattr };
allow init_t usr_t:lnk_file { read getattr };

# Unconfined users can read/execute from the store
allow unconfined_t usr_t:file { read execute execute_no_trans open getattr map };
allow unconfined_t usr_t:dir { read search open getattr };
allow unconfined_t usr_t:lnk_file { read getattr };

# Kernel threads may access store content
allow kernel_t usr_t:file { read open getattr };
allow kernel_t usr_t:dir { read search open getattr };

# System administrators
allow sysadm_t usr_t:file { read execute execute_no_trans open getattr map };
allow sysadm_t usr_t:dir { read search open getattr };
allow sysadm_t usr_t:lnk_file { read getattr };
" port)))

            ;; --- File Contexts (.fc) ---
            (call-with-output-file (string-append mod-dir "/andyl_guix_store.fc")
              (lambda (port)
                (display "\
# ANDYL OS Guix store file contexts
# The entire Guix store is labeled as usr_t (read-only system content)
/gnu/store(/.*)?    system_u:object_r:usr_t:s0
" port)))

            ;; --- Interface (.if) ---
            (call-with-output-file (string-append mod-dir "/andyl_guix_store.if")
              (lambda (port)
                (display "\
## <summary>ANDYL OS Guix store policy interfaces</summary>

########################################
## <summary>
##   Read and execute files from the Guix store.
## </summary>
## <param name=\"domain\">
##   <summary>
##     Domain allowed access.
##   </summary>
## </param>
#
interface(`andyl_guix_store_read_exec',`
    gen_require(`
        type usr_t;
    ')
    allow $1 usr_t:file { read execute execute_no_trans open getattr map };
    allow $1 usr_t:dir { read search open getattr };
    allow $1 usr_t:lnk_file { read getattr };
')
" port)))


            ;; =============================================================
            ;; Merged file contexts for all ANDYL OS paths
            ;; =============================================================
            ;; This file is read by setfiles/restorecon at image build time
            ;; and on first boot to label the filesystem.

            (call-with-output-file
                (string-append ctx-dir "/file_contexts.andyl")
              (lambda (port)
                (display "\
# ANDYL OS file contexts
# Applied at image build time by setfiles and on first boot by restorecon.

########################################
# Guix store -- immutable package store
########################################
/gnu/store(/.*)?    system_u:object_r:usr_t:s0

########################################
# /etc overlay upper layer (mutable on ZFS)
########################################
/var/etc-overlay(/.*)?           system_u:object_r:etc_t:s0
/var/etc-overlay-work(/.*)?      system_u:object_r:etc_t:s0

########################################
# Container storage paths (ZFS datapool)
########################################
/var/lib/containers(/.*)?                  system_u:object_r:container_var_lib_t:s0
/var/lib/containers/storage(/.*)?          system_u:object_r:container_file_t:s0
/var/lib/containers/storage/overlay(/.*)?  system_u:object_r:container_file_t:s0
/var/lib/containerd(/.*)?                  system_u:object_r:container_var_lib_t:s0
/var/lib/crio(/.*)?                        system_u:object_r:container_var_lib_t:s0

########################################
# Kubelet data
########################################
/var/lib/kubelet(/.*)?    system_u:object_r:container_var_lib_t:s0

########################################
# Journal logs
########################################
/var/log/journal(/.*)?    system_u:object_r:systemd_journal_t:s0

########################################
# ZFS dataset mount points and tools
########################################
/var/lib/zfs(/.*)?    system_u:object_r:andyl_zfs_data_t:s0
/usr/sbin/zpool       system_u:object_r:andyl_zfs_exec_t:s0
/usr/sbin/zfs         system_u:object_r:andyl_zfs_exec_t:s0
/usr/sbin/zed         system_u:object_r:andyl_zfs_exec_t:s0
/usr/sbin/zdb         system_u:object_r:andyl_zfs_exec_t:s0

########################################
# Container logs
########################################
/var/log/containers(/.*)?    system_u:object_r:container_log_t:s0
/var/log/pods(/.*)?          system_u:object_r:container_log_t:s0

########################################
# Container runtime sockets
########################################
/run/containerd(/.*)?    system_u:object_r:container_runtime_tmpfs_t:s0
/run/crio(/.*)?          system_u:object_r:container_runtime_tmpfs_t:s0
/run/podman(/.*)?        system_u:object_r:container_runtime_tmpfs_t:s0

########################################
# Cilium CNI
########################################
/usr/bin/cilium-agent    system_u:object_r:andyl_cilium_exec_t:s0
/usr/bin/cilium          system_u:object_r:andyl_cilium_exec_t:s0
/var/run/cilium(/.*)?    system_u:object_r:andyl_cilium_exec_t:s0
" port)))

            #t))))
    (home-page "https://github.com/SELinuxProject/selinux")
    (synopsis "ANDYL OS custom SELinux policy modules")
    (description
     "Custom SELinux policy modules for ANDYL OS, layered on top of the
upstream reference targeted policy.  Provides type enforcement (.te),
file context (.fc), and interface (.if) files for ANDYL OS-specific
services and filesystem paths.  Includes modules for: systemd services
on immutable root with overlay /etc, ZFS mutable data pool operations,
container storage on ZFS, eBPF/Cilium networking, and the Guix store
at /gnu/store.  Defines ANDYL OS-specific SELinux types including
andyl_zfs_t, andyl_zfs_data_t, and andyl_cilium_t.")
    (license license:gpl2+)))
